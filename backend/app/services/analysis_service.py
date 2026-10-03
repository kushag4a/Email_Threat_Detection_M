"""
M5 - the single analysis orchestrator.

Provider -> NormalizedEmail -> M1 + M2 + M3 + M4 -> Risk Engine ->
AnalysisResult

This is the ONE pipeline. Gmail and Microsoft messages both arrive
here as a NormalizedEmail and are treated identically from this point
on - nothing below branches on `email.provider` except to copy it
into the output for display.
"""

from __future__ import annotations

import datetime
import logging
import time

from backend.app.forensic.m1_header_analyzer import analyze_email as m1_analyze
from backend.app.schemas.email_message import NormalizedEmail
from backend.app.services.attachment_analysis import analyze_attachments
from backend.app.services.bec_detector import detect_bec
from backend.app.services.geolocation import get_ip_geolocation
from backend.app.services.m1_adapter import prepare_m1_input
from backend.app.services.ml_classifier import build_analysis_text, classify_email
from backend.app.services.risk_engine import calculate_risk
from backend.app.spam import SpamAssassinResult, get_spamassassin_config
from backend.app.spam import analyze_email as spamassassin_analyze_email
from backend.app.threat_intel.aggregator import analyze_threat_intelligence

logger = logging.getLogger("email_threat_platform.analysis")


class _StageTimer:
    """Collects per-stage wall-clock time so scan slowness can be diagnosed."""

    def __init__(self):
        self.timings: dict[str, float] = {}
        self._t0 = time.perf_counter()

    def mark(self, stage: str):
        now = time.perf_counter()
        self.timings[stage] = round(now - self._t0, 4)
        self._t0 = now

    def log(self, message_id: str):
        total = round(sum(self.timings.values()), 4)
        parts = " ".join(f"{k}={v}s" for k, v in self.timings.items())
        logger.info("email %s: %s total=%ss", message_id, parts, total)


def _header_analysis(email: NormalizedEmail) -> dict:
    # Compare actual addresses, not raw header strings - "Name <a@b.com>"
    # vs "a@b.com" is the same address, not a mismatch. Caught via
    # end-to-end testing against a SCOPE-newsletter-style legitimate
    # email (see MERGE_LOG.md).
    from email.utils import parseaddr

    sender = parseaddr(email.sender or "")[1].lower()
    reply_to = parseaddr(email.reply_to or "")[1].lower()
    return_path = parseaddr(email.return_path or "")[1].lower()

    return {
        "reply_to_mismatch": bool(reply_to and sender and reply_to != sender),
        "return_path_mismatch": bool(return_path and sender and return_path != sender),
    }


def _build_raw_email_for_spamassassin(email: NormalizedEmail) -> bytes:
    """Best-effort raw RFC822 content for the optional SpamAssassin stage.

    Prefers an already-available raw source on the `NormalizedEmail`
    (e.g. the .eml-upload path, which has the original bytes) via
    `getattr` so this has no hard dependency on that attribute existing.
    Falls back to reconstructing a minimal RFC822 message from the
    fields already parsed elsewhere in the pipeline, so provider-fetched
    (Gmail/Microsoft) messages still give the optional stage something
    to analyze. This reconstruction is only used for this optional,
    non-blocking evidence source - it is never used for M1/M2/M3/BEC,
    and never raises (falls back to an empty payload on any error, which
    the adapter itself already handles as an "empty input" result).
    """
    for attr in ("raw_source", "raw_bytes", "raw_mime", "raw_email"):
        raw = getattr(email, attr, None)
        if raw:
            return raw.encode("utf-8", errors="replace") if isinstance(raw, str) else raw

    try:
        from email.message import EmailMessage

        msg = EmailMessage()
        msg["From"] = email.sender or ""
        msg["To"] = email.recipient or ""
        msg["Subject"] = email.subject or ""
        if email.date:
            msg["Date"] = email.date
        if email.reply_to:
            msg["Reply-To"] = email.reply_to
        if email.return_path:
            msg["Return-Path"] = email.return_path
        msg.set_content(email.body or email.html_body or "")
        return msg.as_bytes()
    except Exception:  # noqa: BLE001 - reconstruction must never break the pipeline
        return b""


def _run_spamassassin_stage(email: NormalizedEmail) -> dict | None:
    """Optional SpamAssassin analysis stage - spam-oriented evidence only.

    Fully gated behind `SPAMASSASSIN_ENABLED` (default: disabled). When
    disabled, this returns `None` immediately without invoking
    SpamAssassin or, transitively, Docker at all - so a fresh checkout
    with no SpamAssassin executable/container available still starts
    and analyzes email normally.

    When enabled, the existing, already-tested adapter
    (`backend.app.spam.analyze_email`) is invoked and its structured
    `SpamAssassinResult` is returned as-is (as a dict) - including when
    `available=False` or `error` is populated, since the adapter itself
    already reports every expected failure mode (missing executable,
    Docker not running, timeout, non-zero exit, unparsable output)
    through the result rather than raising. The `try/except` here is
    defense-in-depth against an unforeseen bug in the integration glue
    itself (e.g. building the raw email) - a SpamAssassin failure must
    never fail the overall email analysis.

    This is spam-oriented evidence, never a phishing/malware/BEC/threat-
    intel verdict, and is not (yet) consumed by `calculate_risk()` - see
    risk_engine.py; wiring it into risk scoring is a separate, deliberate
    follow-up.
    """
    config = get_spamassassin_config()
    if not config.enabled:
        return None

    try:
        raw_email = _build_raw_email_for_spamassassin(email)
        result = spamassassin_analyze_email(raw_email, config=config)
    except Exception as exc:  # noqa: BLE001 - intentional catch-all boundary
        logger.exception("Unexpected error running the optional SpamAssassin stage")
        result = SpamAssassinResult(
            available=False,
            error=f"unexpected spamassassin integration error: {exc}",
        )

    return result.model_dump()


def analyze_normalized_email(email: NormalizedEmail) -> dict:
    """Run the full pipeline on one already-fetched, already-parsed email."""

    timer = _StageTimer()

    # ---------------- Attachments: FIRST, cheapest signal, genuinely conditional ----------------
    # Canonical attachment-first/conditional order (see MERGE_LOG.md):
    # attachment metadata/bytes are available immediately after
    # parsing, before any network call or model inference. When there
    # are no attachments, analyze_attachments() returns immediately
    # (scanned=False) without touching the YARA module or file-type
    # detector at all - see attachment_analysis.py.
    attachment_result = analyze_attachments(
        [a.model_dump() for a in email.attachments]
    )
    timer.mark("attachments")

    # ---------------- M1: header / auth forensics ----------------
    m1_input = prepare_m1_input(email)
    m1_result = m1_analyze(m1_input.model_dump())
    header_analysis = _header_analysis(email)
    timer.mark("m1")

    # ---------------- M2: AI / ML classification ----------------
    analysis_text = build_analysis_text(email)
    m2_result = classify_email(
        analysis_text, force_rule_based=attachment_result["has_high_severity"]
    )
    timer.mark("m2")

    # ---------------- M3: local threat intelligence ----------------
    ips = [m1_result["origin_ip"]] if m1_result.get("origin_ip") else []
    m3_result = analyze_threat_intelligence(ips=ips, urls=email.urls)
    timer.mark("m3")

    # ---------------- Deterministic BEC pattern detection ----------------
    # Independent of the ML models and of threat_classifier.py's cheap
    # single-word keyword scan (m2["rule_based_threats"]) - see
    # bec_detector.py. Uses the same analysis_text the ML models see
    # (headers + body/visible-text).
    bec_result = detect_bec(analysis_text)
    timer.mark("bec")

    # ---------------- Optional: SpamAssassin (spam-oriented evidence) ----------------
    # Fully gated behind SPAMASSASSIN_ENABLED (default: disabled) - see
    # _run_spamassassin_stage. Independent of, and never converted into,
    # a phishing/malware/BEC/threat-intel verdict. Fed into
    # calculate_risk() below as a small, optional, capped supporting
    # signal (see risk_engine.py's RISK_CONFIG["spamassassin"]) - a
    # disabled/unavailable/errored/None-score result contributes zero
    # risk and leaves the rest of the engine's behavior unchanged.
    spamassassin_result = _run_spamassassin_stage(email)
    timer.mark("spamassassin")

    # ---------------- M4: geolocation / infrastructure ----------------
    # Deferred for background enrichment so slow external lookups
    # cannot block the primary threat-analysis path.
    geo_results = []
    timer.mark("m4")

    # ---------------- Unified risk engine ----------------
    risk = calculate_risk(
        m1=m1_result,
        m2=m2_result,
        m3=m3_result,
        header_analysis=header_analysis,
        attachment_analysis=attachment_result,
        bec_analysis=bec_result,
        spamassassin=spamassassin_result,
    )
    timer.mark("risk")
    timer.log(email.message_id)

    evidence_sources = ["attachment_analysis", "m1_header_forensics", "m2_ml_models"]
    if m3_result.get("phishtank"):
        evidence_sources.append("phishtank_local_feed")
    if m3_result.get("spamhaus"):
        evidence_sources.append("spamhaus_drop_local_feed")
    if m3_result.get("local_heuristics"):
        evidence_sources.append("local_heuristics")
    if bec_result.get("categories"):
        evidence_sources.append("deterministic_bec_detector")
    if spamassassin_result and spamassassin_result.get("available"):
        evidence_sources.append("spamassassin")
    if geo_results:
        evidence_sources.append("ip_geolocation")
    if attachment_result["scanned"] and any(i["yara"]["scanned"] for i in attachment_result["items"]):
        evidence_sources.append("yara_local_rules")

    # attachment_result["items"] never contains content_bytes - it's
    # built fresh in attachment_analysis.py from a.model_dump(), which
    # DOES include content_bytes, but analyze_attachments() never
    # copies that field into its returned item dicts. This is the only
    # "attachments" the API/dashboard ever sees.
    attachments_output = attachment_result["items"]
    attachment_summary = {
        "scanned": attachment_result["scanned"],
        "reason": attachment_result["reason"],
        "has_high_severity": attachment_result["has_high_severity"],
        "high_severity_filenames": attachment_result["high_severity_filenames"],
    }

    # ---------------- API contract prep (frontend explainability) ----------------
    # calculate_risk() already returns everything the future frontend
    # needs to render "RISK SCORE / WHY / SCORE CALCULATION / ACTIVE
    # SCORING POLICY" (see risk_engine.py's `calculation` key: raw vs
    # final score, per-signal contributions with the multiplier
    # actually used, caps_applied, floors_applied, thresholds). This
    # is surfaced here as top-level `risk_calculation` and
    # `risk_config_version` fields so a frontend can render them
    # without reaching into `risk` internals, while `risk` itself
    # keeps its existing score/level/reasons/contributing_modules
    # shape for backward compatibility with any existing caller. No
    # frontend redesign is implemented here - see TASK 4 - this is
    # API-contract preparation only.
    risk_calculation = risk.get("calculation")
    risk_config_version = risk.get("config_version")
    threat_types = risk.get("threat_types", [])

    return {
        "message_id": email.message_id,
        "provider": email.provider,
        "account_id": email.account_id,
        "email": {
            "sender": email.sender,
            "recipient": email.recipient,
            "subject": email.subject,
            "date": email.date,
            "reply_to": email.reply_to,
            "return_path": email.return_path,
            "body_preview": (email.body or email.html_body or "")[:500],
        },
        "header_analysis": header_analysis,
        "m1": m1_result,
        "m2": m2_result,
        "m3": m3_result,
        "m4": geo_results,
        "spamassassin": spamassassin_result,
        "geo_status": "pending" if m1_result.get("origin_ip") else "not_applicable",
        "urls": email.urls,
        "attachments_present": bool(email.attachments),
        "attachments": attachments_output,
        "attachment_analysis": attachment_summary,
        "risk": risk,
        "risk_calculation": risk_calculation,
        "risk_config_version": risk_config_version,
        "threat_types": threat_types,
        "bec_analysis": bec_result,
        "evidence_sources": evidence_sources,
        "status": "analyzed",
        "error": None,
        "analyzed_at": datetime.datetime.utcnow().isoformat() + "Z",
    }


def analyze_email_safe(email: NormalizedEmail) -> dict:
    """
    Same as analyze_normalized_email, but guarantees a batch of 100
    scans never dies because one message is malformed. Failures are
    reported per-message with status=analysis_failed, matching the
    spec's per-email error handling requirement.
    """
    try:
        return analyze_normalized_email(email)
    except Exception as exc:  # noqa: BLE001 - intentional catch-all boundary
        return {
            "message_id": email.message_id,
            "provider": email.provider,
            "account_id": email.account_id,
            "email": {
                "sender": email.sender,
                "subject": email.subject,
                "date": email.date,
            },
            "risk": {"score": 0, "level": "UNKNOWN", "reasons": [], "contributing_modules": []},
            "risk_calculation": None,
            "risk_config_version": None,
            "threat_types": [],
            "status": "analysis_failed",
            "error": str(exc),
            "analyzed_at": datetime.datetime.utcnow().isoformat() + "Z",
        }


def analyze_eml_upload(file_content: bytes) -> dict:
    """Entry point for the standalone .eml upload path (no provider/OAuth needed)."""
    from backend.app.services.email_parser import parse_rfc822_bytes

    email = parse_rfc822_bytes(
        file_content, provider="upload", message_id="uploaded-file"
    )
    return analyze_email_safe(email)
