"""
Canonical, provider-independent email representation.

Every mail provider (Gmail, Microsoft Graph, or a raw .eml upload) is
normalized into this one object before it ever reaches the analysis
pipeline. M1/M2/M3/M4/risk-engine code never sees a provider-specific
shape.
"""

from __future__ import annotations

from pydantic import BaseModel, Field


class AttachmentMeta(BaseModel):
    filename: str
    content_type: str = "application/octet-stream"
    extension: str = ""
    size_bytes: int = 0
    sha256: str | None = None
    # Transient only - held in memory for this request's pipeline
    # (magic-byte detection + YARA need the actual bytes) and never
    # written to logs, the result cache, or the JSON API response.
    # Stripped explicitly wherever an AttachmentMeta is serialized for
    # output (see analysis_service.py).
    content_bytes: bytes | None = None


class NormalizedEmail(BaseModel):
    provider: str  # "gmail" | "microsoft" | "upload"
    account_id: str = ""  # provider account/mailbox identifier (for user isolation)
    message_id: str
    thread_id: str | None = None

    sender: str = ""
    recipient: str = ""
    cc: list[str] = Field(default_factory=list)
    bcc: list[str] = Field(default_factory=list)

    subject: str = ""
    date: str = ""

    reply_to: str | None = None
    return_path: str | None = None

    received_headers: list[str] = Field(default_factory=list)
    received_spf: list[str] = Field(default_factory=list)
    authentication_results: list[str] = Field(default_factory=list)

    all_headers: dict[str, str] = Field(default_factory=dict)

    body: str = ""
    html_body: str = ""

    urls: list[str] = Field(default_factory=list)

    attachments: list[AttachmentMeta] = Field(default_factory=list)
