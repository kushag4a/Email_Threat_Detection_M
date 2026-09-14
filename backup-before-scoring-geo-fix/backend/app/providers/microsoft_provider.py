from __future__ import annotations

import requests

from backend.app.providers.base import MailProvider, MessageListItem, MessagePage, MessageSummary
from backend.app.schemas.email_message import NormalizedEmail
from backend.app.services.email_parser import parse_graph_message

GRAPH_BASE = "https://graph.microsoft.com/v1.0"

# Requesting internetMessageHeaders lets the canonical parser recover
# Received/Authentication-Results, matching what M1 needs. Delegated,
# least-privilege scope only - never application/tenant-wide permissions.
GRAPH_SCOPES = ["Mail.Read", "User.Read", "offline_access"]

MESSAGE_SELECT_FIELDS = (
    "id,conversationId,subject,from,toRecipients,receivedDateTime,body"
)


class MicrosoftGraphProvider(MailProvider):
    name = "microsoft"

    def __init__(self, access_token: str):
        self._access_token = access_token
        self._user_email: str | None = None

    def _headers(self, extra: dict | None = None) -> dict:
        headers = {"Authorization": f"Bearer {self._access_token}"}
        if extra:
            headers.update(extra)
        return headers

    def get_current_user(self) -> str:
        if self._user_email is None:
            response = requests.get(f"{GRAPH_BASE}/me", headers=self._headers(), timeout=10)
            response.raise_for_status()
            data = response.json()
            self._user_email = data.get("mail") or data.get("userPrincipalName", "")
        return self._user_email

    def list_messages(self, page_size: int, page_token: str | None = None) -> MessagePage:
        # page_token, when present, is the full @odata.nextLink URL Graph
        # gave us last time - we follow it verbatim rather than
        # reconstructing query params, per Graph's pagination contract.
        if page_token:
            url = page_token
            params = None
        else:
            url = f"{GRAPH_BASE}/me/mailFolders/inbox/messages"
            params = {"$top": page_size, "$select": "id,conversationId"}

        response = requests.get(url, headers=self._headers(), params=params, timeout=15)
        response.raise_for_status()
        data = response.json()

        items = [
            MessageListItem(message_id=m["id"], thread_id=m.get("conversationId"))
            for m in data.get("value", [])
        ]

        return MessagePage(items=items, next_page_token=data.get("@odata.nextLink"))

    def get_message_summary(self, message_id: str) -> MessageSummary:
        # $select keeps this to a single lightweight metadata fetch -
        # no body/headers/attachments, unlike get_message().
        url = f"{GRAPH_BASE}/messages/{message_id}"
        params = {
            "$select": "id,conversationId,subject,from,toRecipients,receivedDateTime,bodyPreview,hasAttachments"
        }

        response = requests.get(url, headers=self._headers(), params=params, timeout=10)
        response.raise_for_status()
        data = response.json()

        sender = ((data.get("from") or {}).get("emailAddress") or {}).get("address", "")
        to_recipients = data.get("toRecipients") or []
        recipient = (
            (to_recipients[0].get("emailAddress") or {}).get("address", "")
            if to_recipients
            else ""
        )

        return MessageSummary(
            message_id=message_id,
            thread_id=data.get("conversationId"),
            sender=sender,
            recipient=recipient,
            subject=data.get("subject") or "(no subject)",
            date=data.get("receivedDateTime", ""),
            snippet=data.get("bodyPreview", ""),
            has_attachments=bool(data.get("hasAttachments")),
            provider="microsoft",
        )

    def get_message(self, message_id: str) -> NormalizedEmail:
        url = f"{GRAPH_BASE}/messages/{message_id}"
        params = {
            "$select": MESSAGE_SELECT_FIELDS,
            "$expand": "attachments",
        }
        # internetMessageHeaders is only returned when explicitly selected.
        headers_url = f"{GRAPH_BASE}/messages/{message_id}?$select=internetMessageHeaders"

        response = requests.get(url, headers=self._headers(), params=params, timeout=15)
        response.raise_for_status()
        message = response.json()

        try:
            header_response = requests.get(headers_url, headers=self._headers(), timeout=15)
            header_response.raise_for_status()
            message["internetMessageHeaders"] = header_response.json().get(
                "internetMessageHeaders", []
            )
        except Exception:
            # Header fetch failing must not crash the whole scan; SPF/DKIM/DMARC
            # simply stay unknown for this message, same as any per-email failure.
            message["internetMessageHeaders"] = []

        return parse_graph_message(message, account_id=self.get_current_user())
