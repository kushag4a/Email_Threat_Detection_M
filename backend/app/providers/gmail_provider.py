from __future__ import annotations

import base64
import threading

from google.oauth2.credentials import Credentials
from googleapiclient.discovery import build

from backend.app.providers.base import MailProvider, MessageListItem, MessagePage, MessageSummary
from backend.app.schemas.email_message import NormalizedEmail
from backend.app.services.email_parser import parse_rfc822_bytes

GMAIL_SCOPES = ["https://www.googleapis.com/auth/gmail.readonly"]

# Gmail's format="metadata" fetch only pulls the headers/snippet we
# ask for - orders of magnitude cheaper than format="raw", which
# downloads the entire MIME message (body + attachments) just to
# render one row of an inbox table.
_METADATA_HEADERS = ["From", "To", "Subject", "Date"]


def _get_header(headers: list[dict], name: str) -> str:
    for h in headers:
        if h.get("name", "").lower() == name.lower():
            return h.get("value", "")
    return ""


class GmailProvider(MailProvider):
    """
    BUG FIX (Gmail concurrency corruption - see DIAGNOSTIC_EVIDENCE.md):
    a single instance of this class is deliberately reused across many
    concurrent worker threads - /api/emails' ThreadPoolExecutor (up to
    10 threads) and scan_service.run_scan's IO_POOL (up to
    MAX_CONCURRENT_ANALYSES=5 threads) both call methods on the *same*
    GmailProvider object at the same time by design, for throughput.

    That used to be unsafe: `self._service` was a single
    googleapiclient Resource built once in __init__, backed by a single
    httplib2.Http transport. httplib2.Http caches persistent per-host
    connections in a plain `self.connections` dict with no locking, and
    its own source explicitly documents `close()` as "Not thread-safe,
    requires external synchronization against concurrent requests" -
    the same shared, unsynchronized state is read and written by every
    `.request()` call, including the ones issued transparently inside
    `.execute()`. Reusing one Http instance across threads let two
    threads read/write the same underlying TLS socket at once. That
    matches, exactly, the live failures observed: "'NoneType' object
    has no attribute 'close'", "Remote end closed connection without
    response", "SSL: DECRYPTION_FAILED_OR_BAD_RECORD_MAC", and reads
    that stall until they time out - and the same shared-transport
    reuse also explains why plain (non-scan) inbox listing at
    page_size=5/10 was extremely slow: up to 10 threads were
    serializing/corrupting each other on one connection instead of
    genuinely running in parallel.

    Fix: give every thread its own Resource (and therefore its own
    private Http transport and connection cache) via `threading.local`,
    built lazily on first use by that thread from the same shared
    `Credentials` object. This keeps full concurrency (no locking, no
    serialization of Gmail I/O) while removing all shared mutable
    transport state between threads. The `Credentials` object itself
    (`self._credentials`) is still shared across threads by reference,
    same as before this fix - only the transport/connection layer is
    now per-thread. See CHANGES.md for the residual, lower-severity
    credential-refresh-race caveat this does not change.
    """

    name = "google"

    def __init__(self, credentials: Credentials):
        self._credentials = credentials
        self._local = threading.local()
        self._user_email: str | None = None

    def _service(self):
        """Return this thread's own Gmail API Resource, built on first use."""
        service = getattr(self._local, "service", None)
        if service is None:
            service = build(
                "gmail", "v1", credentials=self._credentials, cache_discovery=False
            )
            self._local.service = service
        return service

    def get_current_user(self) -> str:
        if self._user_email is None:
            profile = self._service().users().getProfile(userId="me").execute()
            self._user_email = profile.get("emailAddress", "")
        return self._user_email

    def list_messages(self, page_size: int, page_token: str | None = None) -> MessagePage:
        request_kwargs = {
            "userId": "me",
            "labelIds": ["INBOX"],
            "maxResults": page_size,
        }
        if page_token:
            request_kwargs["pageToken"] = page_token

        response = self._service().users().messages().list(**request_kwargs).execute()

        items = [
            MessageListItem(message_id=m["id"], thread_id=m.get("threadId"))
            for m in response.get("messages", [])
        ]

        return MessagePage(items=items, next_page_token=response.get("nextPageToken"))

    def get_message_summary(self, message_id: str) -> MessageSummary:
        message = (
            self._service().users()
            .messages()
            .get(
                userId="me",
                id=message_id,
                format="metadata",
                metadataHeaders=_METADATA_HEADERS,
            )
            .execute()
        )

        headers = message.get("payload", {}).get("headers", [])
        parts = message.get("payload", {}).get("parts", []) or []

        has_attachments = any(
            part.get("filename") for part in parts if part.get("filename")
        )

        return MessageSummary(
            message_id=message_id,
            thread_id=message.get("threadId"),
            sender=_get_header(headers, "From"),
            recipient=_get_header(headers, "To"),
            subject=_get_header(headers, "Subject") or "(no subject)",
            date=_get_header(headers, "Date"),
            snippet=message.get("snippet", ""),
            has_attachments=has_attachments,
            provider="google",
        )

    def get_message(self, message_id: str) -> NormalizedEmail:
        message = (
            self._service().users()
            .messages()
            .get(userId="me", id=message_id, format="raw")
            .execute()
        )

        raw_bytes = base64.urlsafe_b64decode(message["raw"])

        return parse_rfc822_bytes(
            raw_bytes,
            provider="google",
            account_id=self.get_current_user(),
            message_id=message_id,
            thread_id=message.get("threadId"),
        )
