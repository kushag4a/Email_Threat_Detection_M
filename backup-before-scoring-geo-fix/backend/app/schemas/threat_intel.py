from __future__ import annotations

from pydantic import BaseModel, Field


class PhishTankResult(BaseModel):
    source: str = "phishtank"
    url: str
    listed: bool
    verified: bool | None = None
    online: bool | None = None
    target: str | None = None
    risk: str


class SpamhausResult(BaseModel):
    source: str = "spamhaus_drop"
    ip: str
    listed: bool
    network: str | None = None
    risk: str


class LocalHeuristicResult(BaseModel):
    source: str = "local_heuristics"
    indicator: str
    indicator_type: str  # "url" | "ip"
    flags: list[str] = Field(default_factory=list)
    local_score: int = 0


class ThreatIntelligenceResult(BaseModel):
    phishtank: list[PhishTankResult] = Field(default_factory=list)
    spamhaus: list[SpamhausResult] = Field(default_factory=list)
    local_heuristics: list[LocalHeuristicResult] = Field(default_factory=list)
