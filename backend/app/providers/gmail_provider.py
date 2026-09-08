from __future__ import annotations

import base64

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
    name = "google"

    def __init__(self, credentials: Credentials):
        self._credentials = credentials
        self._service = build("gmail", "v1", credentials=credentials)
        self._user_email: str | None = None

    def get_current_user(self) -> str:
        if self._user_email is None:
            profile = self._service.users().getProfile(userId="me").execute()
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

        response = self._service.users().messages().list(**request_kwargs).execute()

        items = [
            MessageListItem(message_id=m["id"], thread_id=m.get("threadId"))
            for m in response.get("messages", [])
        ]

        return MessagePage(items=items, next_page_token=response.get("nextPageToken"))

    def get_message_summary(self, message_id: str) -> MessageSummary:
        message = (
            self._service.users()
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
            self._service.users()
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
