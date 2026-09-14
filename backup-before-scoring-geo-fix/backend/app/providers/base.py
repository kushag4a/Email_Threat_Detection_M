from __future__ import annotations

from abc import ABC, abstractmethod

from backend.app.schemas.email_message import NormalizedEmail


class MessageListItem:
    def __init__(self, message_id: str, thread_id: str | None = None):
        self.message_id = message_id
        self.thread_id = thread_id


class MessagePage:
    """One page of message metadata plus the provider-native cursor for the next page."""

    def __init__(self, items: list[MessageListItem], next_page_token: str | None):
        self.items = items
        self.next_page_token = next_page_token


class MessageSummary:
    """
    Cheap, list-view metadata for one message. Deliberately does NOT
    include body/attachments/headers - fetching those for every row
    just to render the inbox table is exactly the "expensive listing"
    anti-pattern this project explicitly avoids. Full content is only
    fetched by get_message(), which is called on-demand (scan/open).
    """

    def __init__(self, message_id, thread_id, sender, recipient, subject,
                 date, snippet, has_attachments, provider):
        self.message_id = message_id
        self.thread_id = thread_id
        self.sender = sender
        self.recipient = recipient
        self.subject = subject
        self.date = date
        self.snippet = snippet
        self.has_attachments = has_attachments
        self.provider = provider

    def to_dict(self) -> dict:
        return {
            "message_id": self.message_id,
            "thread_id": self.thread_id,
            "sender": self.sender,
            "recipient": self.recipient,
            "subject": self.subject,
            "date": self.date,
            "snippet": self.snippet,
            "has_attachments": self.has_attachments,
            "provider": self.provider,
        }


class MailProvider(ABC):
    """
    Common interface every mail provider implements. The analysis
    pipeline (M1-M4, risk engine, dashboard) only ever talks to this
    interface and to NormalizedEmail - it never branches on provider
    name.
    """

    name: str = "base"

    @abstractmethod
    def get_current_user(self) -> str:
        """Return the authenticated account's address/identifier."""

    @abstractmethod
    def list_messages(self, page_size: int, page_token: str | None = None) -> MessagePage:
        """List message metadata for one page, using provider-native pagination."""

    @abstractmethod
    def get_message(self, message_id: str) -> NormalizedEmail:
        """Fetch and normalize a single full message."""

    @abstractmethod
    def get_message_summary(self, message_id: str) -> MessageSummary:
        """
        Cheap metadata fetch for inbox listing - sender/subject/date/
        snippet/has_attachments only. Must be much cheaper than
        get_message(); it must NOT fetch/parse the full raw message.
        """

    def disconnect(self) -> None:
        """Optional hook for providers that need explicit cleanup."""
        return None
