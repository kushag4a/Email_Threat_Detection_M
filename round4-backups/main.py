from __future__ import annotations

from dotenv import load_dotenv

load_dotenv()

import asyncio
import time
from concurrent.futures import ThreadPoolExecutor
from pathlib import Path

from fastapi import FastAPI, HTTPException, Request, UploadFile, File, Query
from fastapi.responses import RedirectResponse, FileResponse
from fastapi.staticfiles import StaticFiles
from pydantic import BaseModel

from backend.app.auth import google_oauth, microsoft_oauth
from backend.app.auth.session import (
    SESSION_STORE,
    clear_provider,
    get_or_create_session,
    get_session_data,
    get_session_id,
)
from backend.app.providers.gmail_provider import GmailProvider
from backend.app.providers.microsoft_provider import MicrosoftGraphProvider
from backend.app.services.analysis_service import analyze_eml_upload
from backend.app.services.scan_service import run_scan, validate_scan_message_ids
from backend.app.services.store import STORE
from backend.app.threat_intel import phishtank_local, spamhaus, local_engine

app = FastAPI(title="AI Email Threat Detection Platform", version="1.0.0")

ALLOWED_PAGE_SIZES = {5, 10, 20, 50, 100}


# ============================================================
# Health / root
# ============================================================

@app.get("/health")
async def health():
    return {"status": "ok"}


# ============================================================
# Google OAuth
# ============================================================

@app.get("/auth/google/login")
def google_login(request: Request):
    if not google_oauth.is_configured():
        raise HTTPException(
            status_code=503,
            detail=(
                "Google OAuth is not configured on this server. Set "
                "GOOGLE_CLIENT_ID, GOOGLE_CLIENT_SECRET and "
                "GOOGLE_REDIRECT_URI (see .env.example)."
            ),
        )

    # BUG FIX (see MERGE_LOG.md): the cookie is now set directly on the
    # response we actually return, instead of on a throwaway Response
    # object whose headers were copied afterward - that copy step was
    # a real source of the "must log in twice" symptom.
    redirect = RedirectResponse("about:blank")  # location set below, once session exists
    session_id = get_or_create_session(request, redirect)
    auth_url = google_oauth.build_authorization_url(session_id)
    redirect.headers["location"] = auth_url
    return redirect


@app.get("/auth/google/callback")
def google_callback(request: Request):
    state = request.query_params.get("state", "")

    try:
        session_id, credentials = google_oauth.exchange_code_for_credentials(
            state, str(request.url)
        )
    except ValueError as exc:
        raise HTTPException(status_code=400, detail=str(exc))

    provider = GmailProvider(credentials)
    email_address = provider.get_current_user()

    SESSION_STORE.setdefault(session_id, {})["google"] = {
        "credentials": credentials,
        "email": email_address,
    }

    return RedirectResponse("/")


@app.get("/auth/google/status")
async def google_status(request: Request):
    session = get_session_data(request)
    google_session = session.get("google")

    if not google_session:
        return {"connected": False}

    return {"connected": True, "email": google_session.get("email")}


@app.post("/auth/google/logout")
def google_logout(request: Request):
    clear_provider(request, "google")
    return {"connected": False}


# ============================================================
# Microsoft OAuth
# ============================================================

@app.get("/auth/microsoft/login")
def microsoft_login(request: Request):
    if not microsoft_oauth.is_configured():
        raise HTTPException(
            status_code=503,
            detail=(
                "Microsoft OAuth is not configured on this server. Set "
                "MICROSOFT_CLIENT_ID, MICROSOFT_CLIENT_SECRET, "
                "MICROSOFT_TENANT_ID and MICROSOFT_REDIRECT_URI "
                "(see .env.example)."
            ),
        )

    redirect = RedirectResponse("about:blank")
    session_id = get_or_create_session(request, redirect)
    auth_url = microsoft_oauth.build_authorization_url(session_id)
    redirect.headers["location"] = auth_url
    return redirect


@app.get("/auth/microsoft/callback")
def microsoft_callback(request: Request):
    state = request.query_params.get("state", "")
    code = request.query_params.get("code", "")

    try:
        session_id, token_result = microsoft_oauth.exchange_code_for_token(state, code)
    except ValueError as exc:
        raise HTTPException(status_code=400, detail=str(exc))

    provider = MicrosoftGraphProvider(token_result["access_token"])
    email_address = provider.get_current_user()

    SESSION_STORE.setdefault(session_id, {})["microsoft"] = {
        "access_token": token_result["access_token"],
        "refresh_token": token_result.get("refresh_token"),
        "email": email_address,
    }

    return RedirectResponse("/")


@app.get("/auth/microsoft/status")
async def microsoft_status(request: Request):
    session = get_session_data(request)
    ms_session = session.get("microsoft")

    if not ms_session:
        return {"connected": False}

    return {"connected": True, "email": ms_session.get("email")}


@app.post("/auth/microsoft/logout")
def microsoft_logout(request: Request):
    clear_provider(request, "microsoft")
    return {"connected": False}


# ============================================================
# Provider resolution helper
# ============================================================

def _get_provider(request: Request, provider_name: str):
    session = get_session_data(request)
    provider_session = session.get(provider_name)

    if not provider_session:
        raise HTTPException(
            status_code=401, detail=f"Not connected to {provider_name}. Log in first."
        )

    if provider_name == "google":
        return GmailProvider(provider_session["credentials"])

    if provider_name == "microsoft":
        return MicrosoftGraphProvider(provider_session["access_token"])

    raise HTTPException(status_code=400, detail=f"Unknown provider {provider_name}")


# ============================================================
# Mailbox (listing, native pagination)
# ============================================================

@app.get("/api/emails")
def list_emails(
    request: Request,
    provider: str = Query(..., pattern="^(google|microsoft)$"),
    page_size: int = Query(5),
    page_token: str | None = None,
):
    if page_size not in ALLOWED_PAGE_SIZES:
        raise HTTPException(
            status_code=400,
            detail=f"page_size must be one of {sorted(ALLOWED_PAGE_SIZES)}",
        )

    mail_provider = _get_provider(request, provider)
    page = mail_provider.list_messages(page_size=page_size, page_token=page_token)

    # P0 FIX (see MERGE_LOG.md): this used to return bare {message_id,
    # thread_id} pairs, which is why the inbox table showed blank
    # sender/subject/date for a real inbox. Fetch cheap per-message
    # metadata (NOT full raw messages - see get_message_summary) for
    # just this page, concurrently, so listing stays fast even at
    # page_size=100. This function itself runs in FastAPI's worker
    # threadpool (sync def route), so blocking calls here do not
    # freeze the event loop.
    summaries: list[dict] = [None] * len(page.items)  # type: ignore[list-item]

    def fetch_one(index: int, message_id: str):
        try:
            summaries[index] = mail_provider.get_message_summary(message_id).to_dict()
        except Exception as exc:
            summaries[index] = {
                "message_id": message_id,
                "thread_id": None,
                "sender": "(failed to load)",
                "recipient": "",
                "subject": "(failed to load)",
                "date": "",
                "snippet": "",
                "has_attachments": False,
                "provider": provider,
                "error": str(exc),
            }

    with ThreadPoolExecutor(max_workers=min(10, max(1, len(page.items)))) as pool:
        futures = [
            pool.submit(fetch_one, i, item.message_id)
            for i, item in enumerate(page.items)
        ]
        for f in futures:
            f.result()

    return {
        "provider": provider,
        "messages": summaries,
        "next_page_token": page.next_page_token,
        "page_size": page_size,
    }


# ============================================================
# Scanning (bounded concurrency, per-message failure isolation)
# ============================================================

class ScanRequest(BaseModel):
    # BUG FIX (page-scoped scan bug - see DIAGNOSTIC_EVIDENCE.md): the
    # old signature took only a `count` integer and re-derived "the
    # first N messages" via its own from-scratch pagination
    # (page_token always starting at None), ignoring whatever page the
    # user was actually viewing in the dashboard. The caller must now
    # send the *exact* message IDs it currently has displayed - the
    # same IDs /api/emails just returned for that page - so scanning
    # page 2 scans page 2, not page 1 again. See
    # scan_service.validate_scan_message_ids for the validation and
    # session-scoping rationale.
    message_ids: list[str]


@app.post("/api/scan")
async def start_scan(
    request: Request,
    body: ScanRequest,
    provider: str = Query(..., pattern="^(google|microsoft)$"),
):
    session_id = get_session_id(request)
    if session_id is None:
        raise HTTPException(status_code=401, detail="No active session.")

    try:
        message_ids = validate_scan_message_ids(body.message_ids)
    except ValueError as exc:
        raise HTTPException(status_code=400, detail=str(exc)) from exc

    # Constructing the provider (and, for Gmail, its per-thread
    # transport - see gmail_provider.py) is enough to prove `provider`
    # is a supported name and that this session actually has a
    # connected account; the mailbox-ownership check for each
    # individual ID happens naturally when run_scan() fetches it below
    # (see validate_scan_message_ids' docstring for why that is the
    # right place for it, not here).
    mail_provider = _get_provider(request, provider)

    scan_id = STORE.create_scan(session_id=session_id, requested=len(message_ids))

    asyncio.create_task(
        run_scan(
            scan_id=scan_id,
            session_id=session_id,
            provider=mail_provider,
            message_ids=message_ids,
        )
    )

    return {"scan_id": scan_id, "requested": len(message_ids)}


@app.get("/api/scan/{scan_id}")
async def get_scan(scan_id: str, request: Request):
    session_id = get_session_id(request)
    if session_id is None:
        raise HTTPException(status_code=401, detail="No active session.")

    scan = STORE.get_scan(scan_id, session_id=session_id)
    if not scan:
        raise HTTPException(status_code=404, detail="Scan not found.")

    total = scan["requested"]
    done = scan["analyzed"] + scan["failed"]
    skipped = max(total - done, 0) if scan["status"] == "complete" else 0

    return {
        "scan_id": scan_id,
        "status": scan["status"],
        "requested": total,
        "analyzed": scan["analyzed"],
        "failed": scan["failed"],
        "skipped": skipped,
        "progress": f"{done}/{total}",
        "results": scan["results"],
    }


# ============================================================
# Single-email analysis (also used by the "upload a .eml" fallback,
# which needs no OAuth and is handy for regression-testing against
# original1.eml / pinterest1.eml / the SCOPE newsletter)
# ============================================================

@app.post("/api/analyze")
async def analyze_upload(file: UploadFile = File(...)):
    MAX_UPLOAD_BYTES = 25 * 1024 * 1024
    content = await file.read()

    if len(content) > MAX_UPLOAD_BYTES:
        raise HTTPException(status_code=413, detail="File too large (25MB limit).")

    if not file.filename.lower().endswith((".eml", ".txt")):
        raise HTTPException(status_code=400, detail="Only .eml files are supported.")

    # BUG FIX (see MERGE_LOG.md): analyze_eml_upload runs full ML
    # inference synchronously; calling it directly inside this
    # `async def` route blocked the event loop for the duration of
    # every analysis, same class of bug as the /api/scan fix above.
    loop = asyncio.get_event_loop()
    return await loop.run_in_executor(None, analyze_eml_upload, content)


@app.post("/api/analyze/batch")
async def analyze_upload_batch(files: list[UploadFile] = File(...)):
    """Custom Email page: up to 10 .eml files analyzed in one batch."""
    MAX_FILES = 10
    MAX_UPLOAD_BYTES = 25 * 1024 * 1024

    if len(files) > MAX_FILES:
        raise HTTPException(status_code=400, detail=f"Maximum {MAX_FILES} files per batch.")

    loop = asyncio.get_event_loop()
    results = []

    for f in files:
        content = await f.read()

        if len(content) > MAX_UPLOAD_BYTES:
            results.append(
                {"message_id": f.filename, "status": "analysis_failed",
                 "error": "File too large (25MB limit).",
                 "risk": {"score": 0, "level": "UNKNOWN", "reasons": [], "contributing_modules": []}}
            )
            continue

        if not f.filename.lower().endswith((".eml", ".txt")):
            results.append(
                {"message_id": f.filename, "status": "analysis_failed",
                 "error": "Only .eml files are supported.",
                 "risk": {"score": 0, "level": "UNKNOWN", "reasons": [], "contributing_modules": []}}
            )
            continue

        try:
            result = await loop.run_in_executor(None, analyze_eml_upload, content)
            result["source_filename"] = f.filename
            results.append(result)
        except Exception as exc:
            results.append(
                {"message_id": f.filename, "status": "analysis_failed", "error": str(exc),
                 "risk": {"score": 0, "level": "UNKNOWN", "reasons": [], "contributing_modules": []}}
            )

    analyzed = sum(1 for r in results if r.get("status") == "analyzed")
    failed = sum(1 for r in results if r.get("status") == "analysis_failed")

    return {
        "requested": len(files),
        "analyzed": analyzed,
        "failed": failed,
        "skipped": 0,
        "results": results,
    }


@app.get("/api/analysis/{provider}/{account_id}/{message_id}")
def get_analysis(provider: str, account_id: str, message_id: str, request: Request):
    session_id = get_session_id(request)
    if session_id is None:
        raise HTTPException(status_code=401, detail="No active session.")

    result = STORE.get_result(
        session_id=session_id, provider=provider, account_id=account_id, message_id=message_id
    )
    if result is None:
        raise HTTPException(status_code=404, detail="Analysis not found. Run a scan first.")

    return result


# ============================================================
# Scans page: real history of past results, session-scoped
# ============================================================

HIGH_RISK_LEVELS = {"HIGH", "CRITICAL"}
MAX_HISTORY_ITEMS = 70  # "approximately last 70" per spec - never fabricated beyond what exists


@app.get("/api/scans/history")
def scans_history(request: Request):
    session_id = get_session_id(request)
    if session_id is None:
        raise HTTPException(status_code=401, detail="No active session.")

    all_results = STORE.list_results(session_id=session_id)
    high_risk = [
        r for r in all_results
        if (r.get("risk") or {}).get("level") in HIGH_RISK_LEVELS
    ]
    high_risk.sort(key=lambda r: r.get("analyzed_at", ""), reverse=True)
    high_risk = high_risk[:MAX_HISTORY_ITEMS]

    # Daily suspicious-email trend, grouped by the date portion of
    # analyzed_at (real data only - an email with no prior scans in
    # this session simply produces an empty/short trend, not a
    # manufactured 70-point history).
    trend: dict[str, dict] = {}
    for r in all_results:
        level = (r.get("risk") or {}).get("level")
        if level not in {"LOW", "MEDIUM", "HIGH", "CRITICAL"}:
            continue
        day = (r.get("analyzed_at") or "")[:10] or "unknown"
        bucket = trend.setdefault(day, {"date": day, "total": 0, "critical": 0, "senders": set()})
        if level in HIGH_RISK_LEVELS:
            bucket["total"] += 1
            if level == "CRITICAL":
                bucket["critical"] += 1
            sender = (r.get("email") or {}).get("sender", "")
            if sender:
                bucket["senders"].add(sender)

    trend_points = sorted(
        [
            {
                "date": v["date"],
                "total_suspicious": v["total"],
                "critical": v["critical"],
                "distinct_senders": len(v["senders"]),
            }
            for v in trend.values()
        ],
        key=lambda p: p["date"],
    )

    return {
        "count": len(high_risk),
        "requested_max": MAX_HISTORY_ITEMS,
        "items": [
            {
                "message_id": r.get("message_id"),
                "date": (r.get("email") or {}).get("date", ""),
                "sender": (r.get("email") or {}).get("sender", ""),
                "subject": (r.get("email") or {}).get("subject", ""),
                "risk": r.get("risk"),
            }
            for r in high_risk
        ],
        "trend": trend_points,
    }


def _extract_domain(sender: str) -> str:
    if "@" in sender:
        return sender.rsplit("@", 1)[-1].strip(">").lower()
    return sender.lower()


@app.get("/api/scans/bad-sources")
def scans_bad_sources(request: Request):
    """Recurring suspicious senders/domains, computed only from what was actually scanned."""
    session_id = get_session_id(request)
    if session_id is None:
        raise HTTPException(status_code=401, detail="No active session.")

    all_results = STORE.list_results(session_id=session_id)
    by_domain: dict[str, dict] = {}

    for r in all_results:
        level = (r.get("risk") or {}).get("level")
        if level not in HIGH_RISK_LEVELS:
            continue

        sender = (r.get("email") or {}).get("sender", "")
        domain = _extract_domain(sender) or "unknown"
        bucket = by_domain.setdefault(
            domain, {"domain": domain, "suspicious_count": 0, "critical_count": 0, "reasons": set()}
        )
        bucket["suspicious_count"] += 1
        if level == "CRITICAL":
            bucket["critical_count"] += 1
        for reason in (r.get("risk") or {}).get("reasons", []):
            bucket["reasons"].add(reason)

    ranked = sorted(by_domain.values(), key=lambda b: b["suspicious_count"], reverse=True)

    return {
        "sources": [
            {
                "domain": b["domain"],
                "suspicious_count": b["suspicious_count"],
                "critical_count": b["critical_count"],
                "reasons": sorted(b["reasons"])[:5],
                "note": "Repeated suspicious activity from this source" if b["suspicious_count"] > 1 else "",
            }
            for b in ranked
        ]
    }


# ============================================================
# Threat Intelligence page
# ============================================================

@app.get("/api/threat-intel/summary")
def threat_intel_summary(request: Request):
    session_id = get_session_id(request)
    if session_id is None:
        raise HTTPException(status_code=401, detail="No active session.")

    all_results = STORE.list_results(session_id=session_id)

    phishtank_matches = 0
    spamhaus_matches = 0
    local_flags = 0
    urls_checked = 0
    ips_checked = 0

    for r in all_results:
        m3 = r.get("m3") or {}
        phishtank_matches += sum(1 for x in m3.get("phishtank", []) if x.get("listed"))
        spamhaus_matches += sum(1 for x in m3.get("spamhaus", []) if x.get("listed"))
        local_flags += sum(1 for x in m3.get("local_heuristics", []) if x.get("flags"))
        urls_checked += len(m3.get("phishtank", []))
        ips_checked += len(m3.get("spamhaus", []))

    data_dir = Path(__file__).parent / "threat_intel" / "data"
    phishtank_file = data_dir / "phishtank.json"
    spamhaus_file = data_dir / "spamhaus_drop.txt"

    def _last_updated(path: Path) -> str | None:
        if not path.exists():
            return None
        return time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime(path.stat().st_mtime))

    return {
        "sources": [
            {
                "name": "PhishTank (local feed)",
                "matches": phishtank_matches,
                "indicators_checked": urls_checked,
                "last_feed_update": _last_updated(phishtank_file),
                "status": "active" if phishtank_file.exists() else "feed missing",
            },
            {
                "name": "Spamhaus DROP (local feed)",
                "matches": spamhaus_matches,
                "indicators_checked": ips_checked,
                "last_feed_update": _last_updated(spamhaus_file),
                "status": "active" if spamhaus_file.exists() else "feed missing",
            },
            {
                "name": "Local heuristics",
                "matches": local_flags,
                "indicators_checked": urls_checked + ips_checked,
                "last_feed_update": None,
                "status": "active",
            },
        ]
    }


# ============================================================
# Reports page
# ============================================================

@app.get("/api/reports/summary")
def reports_summary(request: Request):
    session_id = get_session_id(request)
    if session_id is None:
        raise HTTPException(status_code=401, detail="No active session.")

    all_results = STORE.list_results(session_id=session_id)

    counts = {"LOW": 0, "MEDIUM": 0, "HIGH": 0, "CRITICAL": 0, "UNKNOWN": 0}
    domains: dict[str, int] = {}
    senders: dict[str, int] = {}
    categories: dict[str, int] = {}
    attachment_types: dict[str, int] = {}
    auth_failures: dict[str, int] = {}

    for r in all_results:
        level = (r.get("risk") or {}).get("level", "UNKNOWN")
        counts[level] = counts.get(level, 0) + 1

        sender = (r.get("email") or {}).get("sender", "")
        if sender:
            senders[sender] = senders.get(sender, 0) + 1
            domain = _extract_domain(sender)
            domains[domain] = domains.get(domain, 0) + 1

        m2 = r.get("m2") or {}
        top = m2.get("top_classification") or {}
        if top.get("label"):
            categories[top["label"]] = categories.get(top["label"], 0) + 1

        for a in r.get("attachments", []):
            ext = a.get("extension", "unknown") or "unknown"
            attachment_types[ext] = attachment_types.get(ext, 0) + 1

        m1 = r.get("m1") or {}
        for mechanism in ("spf", "dkim", "dmarc"):
            if m1.get(mechanism) == "fail":
                auth_failures[mechanism.upper()] = auth_failures.get(mechanism.upper(), 0) + 1

    def _top(d: dict, n=5):
        return sorted(d.items(), key=lambda kv: kv[1], reverse=True)[:n]

    return {
        "total_analyzed": len(all_results),
        "risk_breakdown": counts,
        "top_domains": [{"domain": k, "count": v} for k, v in _top(domains)],
        "top_senders": [{"sender": k, "count": v} for k, v in _top(senders)],
        "top_categories": [{"category": k, "count": v} for k, v in _top(categories)],
        "top_attachment_types": [{"extension": k, "count": v} for k, v in _top(attachment_types)],
        "auth_failures": auth_failures,
    }


# ============================================================
# Cases page: group high-risk results by domain (a lightweight,
# real "campaign" view - not a full case-management system)
# ============================================================

@app.get("/api/cases")
def list_cases(request: Request):
    session_id = get_session_id(request)
    if session_id is None:
        raise HTTPException(status_code=401, detail="No active session.")

    all_results = STORE.list_results(session_id=session_id)
    by_domain: dict[str, list[dict]] = {}

    for r in all_results:
        level = (r.get("risk") or {}).get("level")
        if level not in HIGH_RISK_LEVELS:
            continue
        domain = _extract_domain((r.get("email") or {}).get("sender", "")) or "unknown"
        by_domain.setdefault(domain, []).append(r)

    cases = []
    for i, (domain, results) in enumerate(
        sorted(by_domain.items(), key=lambda kv: len(kv[1]), reverse=True), start=1
    ):
        dates = sorted(r.get("analyzed_at", "") for r in results if r.get("analyzed_at"))
        senders = {(r.get("email") or {}).get("sender", "") for r in results}
        ips = {ip for r in results for ip in [(r.get("m1") or {}).get("origin_ip")] if ip}
        categories = {
            (r.get("m2") or {}).get("top_classification", {}).get("label")
            for r in results
            if (r.get("m2") or {}).get("top_classification")
        }
        highest = "HIGH"
        if any((r.get("risk") or {}).get("level") == "CRITICAL" for r in results):
            highest = "CRITICAL"

        cases.append({
            "case_id": f"CASE-{i:04d}",
            "domain": domain,
            "first_seen": dates[0] if dates else None,
            "last_seen": dates[-1] if dates else None,
            "message_count": len(results),
            "distinct_senders": len(senders),
            "distinct_ips": len(ips),
            "threat_categories": sorted(c for c in categories if c),
            "highest_risk": highest,
        })

    return {"cases": cases}


# ============================================================
# Threat-Origin Geographic Analytics (RC6)
#
# Only includes messages at HIGH / CRITICAL risk with actual
# geolocation enrichment.  Geographic data describes sending-
# infrastructure location, NOT the attacker's physical location.
# ============================================================

@app.get("/api/threat-geo/summary")
async def threat_geo_summary(request: Request):
    session_id = get_session_id(request)
    if session_id is None:
        raise HTTPException(status_code=401, detail="No active session.")

    suspicious = STORE.list_suspicious_results(session_id=session_id)

    # Aggregate by country
    by_country: dict[str, dict] = {}
    unique_senders: set[str] = set()
    unique_ips: set[str] = set()
    risk_breakdown: dict[str, int] = {}

    for r in suspicious:
        geo_status = r.get("geo_status", "pending")
        geo_list = r.get("m4") or []
        risk_level = (r.get("risk") or {}).get("level", "UNKNOWN")
        sender = (r.get("email") or {}).get("sender", "")
        origin_ip = (r.get("m1") or {}).get("origin_ip")

        risk_breakdown[risk_level] = risk_breakdown.get(risk_level, 0) + 1
        if sender:
            unique_senders.add(sender)
        if origin_ip:
            unique_ips.add(origin_ip)

        if geo_status != "completed" or not geo_list:
            continue

        for geo in geo_list:
            country = geo.get("country", "Unknown")
            entry = by_country.setdefault(country, {
                "country": country,
                "count": 0,
                "high": 0,
                "critical": 0,
                "unique_ips": set(),
                "unique_senders": set(),
            })
            entry["count"] += 1
            if risk_level == "HIGH":
                entry["high"] += 1
            elif risk_level == "CRITICAL":
                entry["critical"] += 1
            if origin_ip:
                entry["unique_ips"].add(origin_ip)
            if sender:
                entry["unique_senders"].add(sender)

    locations = []
    for entry in sorted(by_country.values(), key=lambda x: x["count"], reverse=True):
        locations.append({
            "country": entry["country"],
            "suspicious_count": entry["count"],
            "high_count": entry["high"],
            "critical_count": entry["critical"],
            "unique_ips": len(entry["unique_ips"]),
            "unique_senders": len(entry["unique_senders"]),
            "note": "Represents email-sending infrastructure location, not sender physical location.",
        })

    return {
        "total_suspicious": len(suspicious),
        "enriched_count": sum(1 for r in suspicious if r.get("geo_status") == "completed"),
        "pending_count": sum(1 for r in suspicious if r.get("geo_status") == "pending"),
        "unique_senders": len(unique_senders),
        "unique_ips": len(unique_ips),
        "risk_breakdown": risk_breakdown,
        "locations": locations,
    }


@app.get("/api/threat-geo/trend")
async def threat_geo_trend(
    request: Request,
    period: str = Query("day", pattern="^(day|week|month)$"),
):
    import datetime as _dt

    session_id = get_session_id(request)
    if session_id is None:
        raise HTTPException(status_code=401, detail="No active session.")

    suspicious = STORE.list_suspicious_results(session_id=session_id)

    # Parse dates and bucket by period
    buckets: dict[str, dict] = {}
    for r in suspicious:
        date_str = (r.get("email") or {}).get("date", "")
        analyzed_at = r.get("analyzed_at", "")
        risk_level = (r.get("risk") or {}).get("level", "UNKNOWN")
        sender = (r.get("email") or {}).get("sender", "")
        origin_ip = (r.get("m1") or {}).get("origin_ip")

        # Try to parse a date for bucketing (prefer analyzed_at, fall back to email date)
        bucket_date = None
        for d in [analyzed_at, date_str]:
            if not d:
                continue
            try:
                if "T" in d:
                    bucket_date = _dt.datetime.fromisoformat(d.replace("Z", "+00:00")).date()
                else:
                    # Try common email date formats
                    for fmt in ["%a, %d %b %Y %H:%M:%S %z", "%d %b %Y %H:%M:%S %z"]:
                        try:
                            bucket_date = _dt.datetime.strptime(d[:31], fmt).date()
                            break
                        except ValueError:
                            continue
                if bucket_date:
                    break
            except (ValueError, TypeError):
                continue

        if bucket_date is None:
            bucket_date = _dt.date.today()

        if period == "day":
            key = bucket_date.isoformat()
        elif period == "week":
            start_of_week = bucket_date - _dt.timedelta(days=bucket_date.weekday())
            key = f"week-{start_of_week.isoformat()}"
        else:  # month
            key = f"{bucket_date.year}-{bucket_date.month:02d}"

        bucket = buckets.setdefault(key, {
            "period": key,
            "suspicious_count": 0,
            "high_count": 0,
            "critical_count": 0,
            "unique_senders": set(),
            "unique_ips": set(),
        })
        bucket["suspicious_count"] += 1
        if risk_level == "HIGH":
            bucket["high_count"] += 1
        elif risk_level == "CRITICAL":
            bucket["critical_count"] += 1
        if sender:
            bucket["unique_senders"].add(sender)
        if origin_ip:
            bucket["unique_ips"].add(origin_ip)

    trend = []
    for b in sorted(buckets.values(), key=lambda x: x["period"]):
        trend.append({
            "period": b["period"],
            "suspicious_count": b["suspicious_count"],
            "high_count": b["high_count"],
            "critical_count": b["critical_count"],
            "unique_senders": len(b["unique_senders"]),
            "unique_ips": len(b["unique_ips"]),
        })

    return {"period_type": period, "trend": trend}


# ============================================================
# Static dashboard (served by this same FastAPI process)
# ============================================================

STATIC_DIR = "static"

app.mount("/assets", StaticFiles(directory=STATIC_DIR), name="assets")


@app.get("/")
def dashboard_index():
    return FileResponse(f"{STATIC_DIR}/index.html")
