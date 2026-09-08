"""
ONE canonical email parser.

Both the old M5 project and the friend's project each had their own
partial parser (email_parser.py, email_security_features.py,
gmail_pipeline.extract_body, gmail_reader.extract_email_body). This
module replaces all of them. Every provider (Gmail raw RFC822 bytes,
a raw .eml upload) funnels through parse_rfc822_bytes(); Microsoft
Graph's JSON message shape funnels through parse_graph_message().

Both entry points return the same NormalizedEmail object, so nothing
downstream needs to know where the email came from.
"""

from __future__ import annotations

import hashlib
from email import message_from_bytes, policy
from email.header import decode_header as _mime_decode_header
from email.message import Message

from backend.app.schemas.email_message import AttachmentMeta, NormalizedEmail
from backend.app.services.url_extractor import extract_urls


def decode_mime_header(value: str | None) -> str:
    if not value:
        return ""

    parts = []

    for fragment, encoding in _mime_decode_header(value):
        if isinstance(fragment, bytes):
            parts.append(fragment.decode(encoding or "utf-8", errors="replace"))
        else:
            parts.append(str(fragment))

    return "".join(parts)


def _extract_bodies(msg: Message) -> tuple[str, str]:
    """Return (plain_text_body, html_body). Never raises on a bad part."""

    plain = ""
    html = ""

    if msg.is_multipart():
        for part in msg.walk():
            content_type = part.get_content_type()
            disposition = str(part.get("Content-Disposition", ""))

            if "attachment" in disposition:
                continue

            try:
                if content_type == "text/plain" and not plain:
                    payload = part.get_payload(decode=True)
                    if payload:
                        plain = payload.decode(
                            part.get_content_charset() or "utf-8",
                            errors="replace",
                        )

                elif content_type == "text/html" and not html:
                    payload = part.get_payload(decode=True)
                    if payload:
                        html = payload.decode(
                            part.get_content_charset() or "utf-8",
                            errors="replace",
                        )
            except Exception:
                # A malformed MIME part must never crash the whole scan.
                continue
    else:
        try:
            payload = msg.get_payload(decode=True)
            if payload:
                text = payload.decode(
                    msg.get_content_charset() or "utf-8", errors="replace"
                )
                if msg.get_content_type() == "text/html":
                    html = text
                else:
                    plain = text
        except Exception:
            pass

    return plain, html


def _extract_attachments(msg: Message) -> list[AttachmentMeta]:
    attachments: list[AttachmentMeta] = []

    if not msg.is_multipart():
        return attachments

    for part in msg.walk():
        disposition = str(part.get("Content-Disposition", ""))
        filename = part.get_filename()

        is_attachment = "attachment" in disposition or (
            filename and "inline" not in disposition
        )

        if not is_attachment or not filename:
            continue

        try:
            payload = part.get_payload(decode=True) or b""
        except Exception:
            payload = b""

        filename = decode_mime_header(filename)
        extension = ""
        if "." in filename:
            extension = "." + filename.rsplit(".", 1)[-1].lower()

        attachments.append(
            AttachmentMeta(
                filename=filename,
                content_type=part.get_content_type(),
                extension=extension,
                size_bytes=len(payload),
                sha256=hashlib.sha256(payload).hexdigest() if payload else None,
                content_bytes=payload or None,
            )
        )

    return attachments


def parse_rfc822_bytes(
    raw_bytes: bytes,
    *,
    provider: str,
    account_id: str = "",
    message_id: str = "",
    thread_id: str | None = None,
) -> NormalizedEmail:
    """Parse a raw RFC822 message (Gmail 'raw' format or an uploaded .eml)."""

    msg = message_from_bytes(raw_bytes, policy=policy.default)

    all_headers: dict[str, str] = {}
    for key in msg.keys():
        # Keep the first occurrence for the flat map; repeated headers
        # (Received, Authentication-Results) are captured separately below.
        if key not in all_headers:
            all_headers[key] = decode_mime_header(msg.get(key, ""))

    plain_body, html_body = _extract_bodies(msg)
    urls = extract_urls(plain_body + "\n" + html_body)

    return NormalizedEmail(
        provider=provider,
        account_id=account_id,
        message_id=message_id,
        thread_id=thread_id,
        sender=decode_mime_header(msg.get("From", "")),
        recipient=decode_mime_header(msg.get("To", "")),
        cc=[decode_mime_header(x) for x in msg.get_all("Cc", [])],
        bcc=[decode_mime_header(x) for x in msg.get_all("Bcc", [])],
        subject=decode_mime_header(msg.get("Subject", "")),
        date=decode_mime_header(msg.get("Date", "")),
        reply_to=decode_mime_header(msg.get("Reply-To")) or None,
        return_path=decode_mime_header(msg.get("Return-Path")) or None,
        received_headers=list(msg.get_all("Received", [])),
        received_spf=list(msg.get_all("Received-SPF", [])),
        authentication_results=list(msg.get_all("Authentication-Results", [])),
        all_headers=all_headers,
        body=plain_body,
        html_body=html_body,
        urls=urls,
        attachments=_extract_attachments(msg),
    )


def parse_graph_message(
    graph_message: dict,
    *,
    account_id: str = "",
) -> NormalizedEmail:
    """
    Normalize a Microsoft Graph message resource
    (https://learn.microsoft.com/graph/api/resources/message) into the
    same NormalizedEmail shape Gmail produces.

    Graph does not expose raw Received/Authentication-Results headers
    through /me/messages by default; when internetMessageHeaders is
    requested (via $select or $expand) we pull SPF/DKIM/DMARC-relevant
    entries out of it. Otherwise those fields stay empty rather than
    being guessed at.
    """

    headers_list = graph_message.get("internetMessageHeaders") or []
    all_headers: dict[str, str] = {}
    received_headers: list[str] = []
    received_spf: list[str] = []
    authentication_results: list[str] = []

    for entry in headers_list:
        name = entry.get("name", "")
        value = entry.get("value", "")

        if name and name not in all_headers:
            all_headers[name] = value

        lname = name.lower()
        if lname == "received":
            received_headers.append(value)
        elif lname == "received-spf":
            received_spf.append(value)
        elif lname == "authentication-results":
            authentication_results.append(value)

    body_content = (graph_message.get("body") or {}).get("content", "")
    body_type = (graph_message.get("body") or {}).get("contentType", "text")

    plain_body = body_content if body_type == "text" else ""
    html_body = body_content if body_type == "html" else ""

    urls = extract_urls(plain_body + "\n" + html_body)

    sender = ((graph_message.get("from") or {}).get("emailAddress") or {}).get(
        "address", ""
    )
    to_recipients = graph_message.get("toRecipients") or []
    recipient = (
        (to_recipients[0].get("emailAddress") or {}).get("address", "")
        if to_recipients
        else ""
    )

    attachments: list[AttachmentMeta] = []
    for att in graph_message.get("attachments") or []:
        content_bytes_b64 = att.get("contentBytes")
        sha256 = None
        size_bytes = att.get("size", 0)
        raw_bytes = None

        if content_bytes_b64:
            import base64

            try:
                raw_bytes = base64.b64decode(content_bytes_b64)
                sha256 = hashlib.sha256(raw_bytes).hexdigest()
                size_bytes = len(raw_bytes)
            except Exception:
                pass

        filename = att.get("name", "")
        extension = ("." + filename.rsplit(".", 1)[-1].lower()) if "." in filename else ""

        attachments.append(
            AttachmentMeta(
                filename=filename,
                content_type=att.get("contentType", "application/octet-stream"),
                extension=extension,
                size_bytes=size_bytes,
                sha256=sha256,
                content_bytes=raw_bytes,
            )
        )

    return NormalizedEmail(
        provider="microsoft",
        account_id=account_id,
        message_id=graph_message.get("id", ""),
        thread_id=graph_message.get("conversationId"),
        sender=sender,
        recipient=recipient,
        subject=graph_message.get("subject", ""),
        date=graph_message.get("receivedDateTime", ""),
        reply_to=None,
        return_path=None,
        received_headers=received_headers,
        received_spf=received_spf,
        authentication_results=authentication_results,
        all_headers=all_headers,
        body=plain_body,
        html_body=html_body,
        urls=urls,
        attachments=attachments,
    )
