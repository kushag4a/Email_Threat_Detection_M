"""
Dashboard aggregations over REAL analysis results.

Two things live here, both pure functions over the list of result dicts
that ``ResultStore.list_results()`` already returns (no I/O, no FastAPI,
stdlib only - so they are trivially unit-testable):

1. ``build_risk_trend``  - mail volume bucketed by period, split into the
   four risk classifications the rest of the UI uses (Safe / Medium /
   High / Critical). This replaces the old dashboard chart, which was
   (incorrectly) fed from ``/api/threat-geo/trend`` - a *geolocation*
   endpoint that only ever sees HIGH/CRITICAL mail and therefore cannot
   say anything about how much mail was scanned or how much of it was
   safe.

2. ``build_threat_vectors`` - the "Top threat vectors" ranking, built from
   threat *categories* (``result["threat_types"]``: Authentication
   Spoofing, Credential Phishing, ...). Threat-intelligence *sources*
   (PhishTank, Spamhaus DROP, local heuristics) are a different thing -
   they are evidence providers, not categories - so they are returned in
   a separate ``sources`` list rather than mixed into the ranking.

Nothing here invents data. A period with no mail is simply zero; a
result whose date cannot be parsed is counted under ``undated`` and left
out of the buckets (the old geo-trend code silently re-dated such mail to
"today", which is exactly the kind of fabrication to avoid).

Security logic is untouched: this module only *reads* ``risk.level``,
``threat_types`` and the M3 evidence already produced by the pipeline.
"""

from __future__ import annotations

import datetime as _dt
from email.utils import parsedate_to_datetime
from typing import Iterable

# risk.level (engine vocabulary) -> chart/UI key
LEVEL_TO_KEY: dict[str, str] = {
    "LOW": "safe",
    "MEDIUM": "medium",
    "HIGH": "high",
    "CRITICAL": "critical",
}
SEVERITY_KEYS: tuple[str, ...] = ("safe", "medium", "high", "critical")

# period query value -> number of buckets in the window (ending "today")
PERIOD_WINDOWS: dict[str, int] = {"day": 14, "week": 12, "month": 12}

MAX_DETECTIONS_PER_VECTOR = 100


# ----------------------------------------------------------------------
# Result helpers
# ----------------------------------------------------------------------

def _level(result: dict) -> str | None:
    return (result.get("risk") or {}).get("level")


def is_classified(result: dict) -> bool:
    """True for a successfully analyzed result with a real risk level."""
    if result.get("status") == "analysis_failed":
        return False
    return _level(result) in LEVEL_TO_KEY


def _parse_dt(value: str | None) -> _dt.date | None:
    """Parse an RFC-2822 email Date or an ISO-8601 timestamp to a UTC date."""
    if not value or not isinstance(value, str):
        return None
    text = value.strip()
    parsed: _dt.datetime | None = None
    try:
        parsed = parsedate_to_datetime(text)
    except (TypeError, ValueError, IndexError):
        parsed = None
    if parsed is None:
        try:
            parsed = _dt.datetime.fromisoformat(text.replace("Z", "+00:00"))
        except ValueError:
            return None
    if parsed.tzinfo is not None:
        parsed = parsed.astimezone(_dt.timezone.utc)
    return parsed.date()


def result_date(result: dict) -> _dt.date | None:
    """
    The date a message belongs to on the chart: when it was RECEIVED
    (the email's own Date header); if that is missing/unparseable, when
    it was analyzed. ``None`` if neither can be parsed.
    """
    received = _parse_dt((result.get("email") or {}).get("date"))
    if received is not None:
        return received
    return _parse_dt(result.get("analyzed_at"))


# ----------------------------------------------------------------------
# Risk trend (Safe / Medium / High / Critical per period)
# ----------------------------------------------------------------------

def _week_start(d: _dt.date) -> _dt.date:
    return d - _dt.timedelta(days=d.weekday())


def _add_months(year: int, month: int, delta: int) -> tuple[int, int]:
    index = year * 12 + (month - 1) + delta
    return index // 12, index % 12 + 1


def _bucket_key(d: _dt.date, period: str) -> str:
    if period == "day":
        return d.isoformat()
    if period == "week":
        return _week_start(d).isoformat()
    return f"{d.year}-{d.month:02d}"


def _window_keys(today: _dt.date, period: str) -> list[str]:
    """Ordered (oldest -> newest) bucket keys for the window ending today."""
    n = PERIOD_WINDOWS[period]
    if period == "day":
        return [(today - _dt.timedelta(days=i)).isoformat() for i in range(n - 1, -1, -1)]
    if period == "week":
        start = _week_start(today)
        return [(start - _dt.timedelta(weeks=i)).isoformat() for i in range(n - 1, -1, -1)]
    keys = []
    for i in range(n - 1, -1, -1):
        y, m = _add_months(today.year, today.month, -i)
        keys.append(f"{y}-{m:02d}")
    return keys


def _bucket_label(key: str, period: str) -> str:
    if period == "day":
        d = _dt.date.fromisoformat(key)
        return d.strftime("%d %b")
    if period == "week":
        d = _dt.date.fromisoformat(key)
        return "Wk " + d.strftime("%d %b")
    y, m = key.split("-")
    return _dt.date(int(y), int(m), 1).strftime("%b %Y")


def _empty_counts() -> dict[str, int]:
    return {k: 0 for k in SEVERITY_KEYS}


def build_risk_trend(
    results: Iterable[dict],
    *,
    period: str = "day",
    today: _dt.date | None = None,
) -> dict:
    """
    Bucket real analyzed mail by period and risk classification.

    Returns::

        {
          "period_type": "day" | "week" | "month",
          "window": {"start": iso, "end": iso, "buckets": n},
          "buckets": [{"period", "label", "safe", "medium", "high",
                       "critical", "total"}, ...],     # zero-filled, oldest first
          "totals": {"safe", "medium", "high", "critical", "total"},  # inside window
          "analyzed_total": int,     # every classified result, any date
          "outside_window": int,     # classified but dated outside the window
          "undated": int,            # classified but no parseable date
        }
    """
    if period not in PERIOD_WINDOWS:
        raise ValueError(f"period must be one of {sorted(PERIOD_WINDOWS)}")

    today = today or _dt.datetime.now(_dt.timezone.utc).date()
    keys = _window_keys(today, period)
    buckets = {
        key: {"period": key, "label": _bucket_label(key, period), **_empty_counts(), "total": 0}
        for key in keys
    }

    analyzed_total = outside = undated = 0
    for result in results:
        if not is_classified(result):
            continue
        analyzed_total += 1
        d = result_date(result)
        if d is None:
            undated += 1
            continue
        bucket = buckets.get(_bucket_key(d, period))
        if bucket is None:
            outside += 1
            continue
        bucket[LEVEL_TO_KEY[_level(result)]] += 1
        bucket["total"] += 1

    ordered = [buckets[k] for k in keys]
    totals = _empty_counts()
    totals["total"] = 0
    for b in ordered:
        for k in SEVERITY_KEYS:
            totals[k] += b[k]
        totals["total"] += b["total"]

    if period == "day":
        window_start = keys[0]
    elif period == "week":
        window_start = keys[0]
    else:
        window_start = keys[0] + "-01"

    return {
        "period_type": period,
        "window": {"start": window_start, "end": today.isoformat(), "buckets": len(keys)},
        "buckets": ordered,
        "totals": totals,
        "analyzed_total": analyzed_total,
        "outside_window": outside,
        "undated": undated,
    }


# ----------------------------------------------------------------------
# Threat vectors (categories) + threat-intelligence sources
# ----------------------------------------------------------------------

def _detection(result: dict, evidence: list[str] | None = None) -> dict:
    email = result.get("email") or {}
    risk = result.get("risk") or {}
    out = {
        "message_id": result.get("message_id"),
        "provider": result.get("provider"),
        "account_id": result.get("account_id"),
        "sender": email.get("sender", ""),
        "subject": email.get("subject", ""),
        "date": email.get("date", ""),
        "risk_level": risk.get("level"),
        "risk_score": risk.get("score"),
        "threat_types": list(result.get("threat_types") or []),
        "analyzed_at": result.get("analyzed_at"),
    }
    if evidence is not None:
        out["evidence"] = evidence
    return out


def _sort_detections(dets: list[dict]) -> list[dict]:
    return sorted(
        dets,
        key=lambda d: (-(d.get("risk_score") or 0), d.get("analyzed_at") or ""),
    )


def build_threat_vectors(results: Iterable[dict]) -> dict:
    """
    ``vectors``: threat CATEGORIES ranked by number of distinct emails.
    ``sources``: threat-INTELLIGENCE source summaries (PhishTank, Spamhaus
    DROP, local heuristics), each with the emails that matched - kept
    apart from the ranking on purpose.
    """
    classified = [r for r in results if is_classified(r)]

    by_type: dict[str, list[dict]] = {}
    for r in classified:
        for t in sorted({t for t in (r.get("threat_types") or []) if t}):
            by_type.setdefault(t, []).append(r)

    vectors = []
    for name, rs in by_type.items():
        severity = _empty_counts()
        for r in rs:
            severity[LEVEL_TO_KEY[_level(r)]] += 1
        dets = _sort_detections([_detection(r) for r in rs])
        vectors.append({
            "name": name,
            "count": len(rs),
            "severity": severity,
            "detections": dets[:MAX_DETECTIONS_PER_VECTOR],
            "truncated": len(dets) > MAX_DETECTIONS_PER_VECTOR,
        })
    vectors.sort(key=lambda v: (-v["count"], v["name"]))

    return {
        "total_analyzed": len(classified),
        "vectors": vectors,
        "sources": build_intel_sources(classified),
    }


def _host_of(url: str) -> str:
    try:
        from urllib.parse import urlparse
        return urlparse(url).hostname or ""
    except ValueError:
        return ""


def build_intel_sources(results: Iterable[dict]) -> list[dict]:
    """
    Per-source match counts (same counting rules as
    ``/api/threat-intel/summary``) plus the emails that matched.
    """
    specs = [
        ("phishtank", "PhishTank (local feed)"),
        ("spamhaus", "Spamhaus DROP (local feed)"),
        ("local_heuristics", "Local heuristics"),
    ]
    matches = {k: 0 for k, _ in specs}
    dets: dict[str, list[dict]] = {k: [] for k, _ in specs}

    for r in results:
        m3 = r.get("m3") or {}
        pt = [x for x in m3.get("phishtank", []) if x.get("listed")]
        sh = [x for x in m3.get("spamhaus", []) if x.get("listed")]
        lh = [x for x in m3.get("local_heuristics", []) if x.get("flags")]

        matches["phishtank"] += len(pt)
        matches["spamhaus"] += len(sh)
        matches["local_heuristics"] += len(lh)

        if pt:
            hosts = sorted({_host_of(x.get("url", "")) or "listed URL" for x in pt})
            dets["phishtank"].append(_detection(r, hosts[:5]))
        if sh:
            nets = sorted({x.get("network") or x.get("ip") or "listed IP" for x in sh})
            dets["spamhaus"].append(_detection(r, [str(n) for n in nets[:5]]))
        if lh:
            flags = sorted({f for x in lh for f in x.get("flags", [])})
            dets["local_heuristics"].append(_detection(r, flags[:6]))

    out = []
    for key, name in specs:
        ordered = _sort_detections(dets[key])
        out.append({
            "key": key,
            "name": name,
            "matches": matches[key],
            "message_count": len(ordered),
            "detections": ordered[:MAX_DETECTIONS_PER_VECTOR],
            "truncated": len(ordered) > MAX_DETECTIONS_PER_VECTOR,
        })
    return out
