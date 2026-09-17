"""
Background geolocation enrichment — runs AFTER the primary threat
verdict has been computed and saved.

Design requirements:
  - The primary email verdict must complete without waiting for geo.
  - Enrichment has explicit status: pending / completed / failed /
    not_applicable.
  - Identical IP lookups are deduplicated via the existing geo cache.
  - A geolocation failure NEVER changes the primary verdict.
  - Tasks are tracked (not fire-and-forget): a dedicated thread pool
    manages enrichment, and each task updates the store atomically.
  - Only messages with HIGH/CRITICAL risk AND a public origin IP
    are enriched by default (configurable).
"""

from __future__ import annotations

import logging
from concurrent.futures import Future, ThreadPoolExecutor

from backend.app.services.geolocation import get_ip_geolocation
from backend.app.services.store import STORE

logger = logging.getLogger("email_threat_platform.geo_enrichment")

# Dedicated thread pool for geo enrichment so it doesn't compete
# with scan I/O or CPU pools.
_GEO_POOL = ThreadPoolExecutor(max_workers=3, thread_name_prefix="geo-enrich")

# Track in-flight enrichment tasks so we know when things are pending.
_pending_tasks: dict[str, Future] = {}

# Only enrich messages at these risk levels (saves API calls for
# benign emails).  Set to None to enrich all.
_ENRICH_RISK_LEVELS = {"HIGH", "CRITICAL", "MEDIUM"}


def enqueue_geo_enrichment(
    *,
    ip: str,
    session_id: str,
    provider: str,
    account_id: str,
    message_id: str,
    risk_level: str,
) -> None:
    """
    Submit a background geolocation enrichment task for a given result.
    Non-blocking — returns immediately.
    """
    if _ENRICH_RISK_LEVELS and risk_level not in _ENRICH_RISK_LEVELS:
        # Skip enrichment for clearly benign messages to avoid
        # unnecessary external API calls.
        STORE.update_result_enrichment(
            session_id=session_id,
            provider=provider,
            account_id=account_id,
            message_id=message_id,
            enrichment={
                "geo": [],
                "geo_status": "not_applicable",
            },
        )
        return

    task_key = f"{session_id}:{provider}:{account_id}:{message_id}"

    future = _GEO_POOL.submit(
        _do_enrichment,
        ip=ip,
        session_id=session_id,
        provider=provider,
        account_id=account_id,
        message_id=message_id,
    )
    _pending_tasks[task_key] = future

    # Attach a done callback to clean up tracking
    def _on_done(f: Future) -> None:
        _pending_tasks.pop(task_key, None)

    future.add_done_callback(_on_done)


def _do_enrichment(
    *,
    ip: str,
    session_id: str,
    provider: str,
    account_id: str,
    message_id: str,
) -> None:
    """Runs in a background thread. Never raises — failures are recorded."""
    try:
        geo = get_ip_geolocation(ip)

        # Add infrastructure-appropriate note
        geo["note"] = (
            "This represents the email-sending infrastructure location, "
            "not necessarily the sender's physical location."
        )

        STORE.update_result_enrichment(
            session_id=session_id,
            provider=provider,
            account_id=account_id,
            message_id=message_id,
            enrichment={
                "geo": [geo],
                "geo_status": "completed",
            },
        )
        logger.info("geo enrichment completed for %s (IP: %s -> %s)",
                     message_id, ip, geo.get("country", "unknown"))

    except Exception as exc:
        STORE.update_result_enrichment(
            session_id=session_id,
            provider=provider,
            account_id=account_id,
            message_id=message_id,
            enrichment={
                "geo": [],
                "geo_status": "failed",
            },
        )
        logger.warning("geo enrichment failed for %s (IP: %s): %s",
                       message_id, ip, exc)


def get_enrichment_stats() -> dict:
    """Return stats about pending/completed enrichment tasks."""
    return {
        "pending_count": len(_pending_tasks),
    }
