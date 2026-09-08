from __future__ import annotations

from pydantic import BaseModel, Field


class M1Input(BaseModel):
    sender: str
    reply_to: str | None = None
    return_path: str | None = None
    received_headers: list[str] = Field(default_factory=list)
    received_spf: list[str] = Field(default_factory=list)
    authentication_results: list[str] = Field(default_factory=list)
    body: str = ""
    urls: list[str] = Field(default_factory=list)
    attachments: list[dict] = Field(default_factory=list)


class M1Output(BaseModel):
    spf: str
    dkim: str
    dmarc: str
    origin_ip: str | None = None
