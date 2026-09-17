from __future__ import annotations

from pydantic import BaseModel, Field

from backend.app.schemas.m1 import M1Output
from backend.app.schemas.threat_intel import ThreatIntelligenceResult


class EmailSummary(BaseModel):
    sender: str = ""
    recipient: str = ""
    subject: str = ""
    date: str = ""
    reply_to: str | None = None
    return_path: str | None = None
    body_preview: str = ""


class Classification(BaseModel):
    label: str
    probability: float


class M2Result(BaseModel):
    safe_probability: float
    phishing_probability: float
    threat_categories: dict[str, float] = Field(default_factory=dict)
    rule_based_threats: dict[str, int] = Field(default_factory=dict)
    top_classification: Classification | None = None


class HeaderAnalysis(BaseModel):
    reply_to_mismatch: bool = False
    return_path_mismatch: bool = False


class GeoResult(BaseModel):
    ip: str
    country: str = "Unknown"
    region: str = "Unknown"
    city: str = "Unknown"
    organization: str = "Unknown"
    note: str = (
        "Represents probable source infrastructure, not a confirmed "
        "physical location or attacker identity."
    )


class AttachmentInfo(BaseModel):
    filename: str
    content_type: str = ""
    extension: str = ""
    size_bytes: int = 0
    sha256: str | None = None


class RiskResult(BaseModel):
    score: int
    level: str  # LOW | MEDIUM | HIGH | CRITICAL
    reasons: list[str] = Field(default_factory=list)
    contributing_modules: list[str] = Field(default_factory=list)


class AnalysisResult(BaseModel):
    message_id: str
    provider: str
    account_id: str = ""

    email: EmailSummary
    header_analysis: HeaderAnalysis = Field(default_factory=HeaderAnalysis)

    m1: M1Output | None = None
    m2: M2Result | None = None
    m3: ThreatIntelligenceResult | None = None
    m4: list[GeoResult] = Field(default_factory=list)

    urls: list[str] = Field(default_factory=list)
    attachments: list[AttachmentInfo] = Field(default_factory=list)

    risk: RiskResult

    evidence_sources: list[str] = Field(default_factory=list)

    status: str = "analyzed"  # analyzed | analysis_failed | skipped
    error: str | None = None

    analyzed_at: str = ""
