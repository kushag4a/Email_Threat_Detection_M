"""
Runs a bounded-concurrency scan over N messages from a provider,
updating progress as it goes, and never lets one bad message abort
the batch.

CONCURRENCY ARCHITECTURE
========================
The scan separates I/O-bound work (provider.get_message — network
round trips to Gmail/Graph) from CPU-bound work (analyze_email_safe —
ML inference, email parsing, risk calculation).

I/O work runs in a dedicated ThreadPoolExecutor (IO_POOL) so that
network calls don't hold the GIL.

CPU work runs in a dedicated ProcessPoolExecutor (CPU_POOL) so that
heavy scikit-learn inference executes in child processes with their
own GIL — meaning the main FastAPI process's event loop and
request-handling threads remain fully responsive.

A bounded asyncio.Semaphore limits how many messages are in-flight
simultaneously, preventing unbounded resource consumption.

Why this prevents server freezing
---------------------------------
  - Event-loop starvation: impossible — no blocking work runs on the
    event loop; I/O and CPU work are in separate pools.
  - GIL starvation: impossible — CPU-heavy work is in child processes,
    each with its own GIL.  The main process GIL is free for incoming
    HTTP requests.
  - Executor starvation: impossible — I/O and CPU pools are separate
    and bounded.
  - Unbounded concurrency: impossible — semaphore + fixed pool sizes.
"""

from __future__ import annotations

import asyncio
import logging
import threading
import time
from concurrent.futures import ProcessPoolExecutor, ThreadPoolExecutor

from backend.app.providers.base import MailProvider
from backend.app.services.store import STORE

logger = logging.getLogger("email_threat_platform.scan")

# Bounded concurrency: at most N messages in-flight at any time.
MAX_CONCURRENT_ANALYSES = 5

# Dedicated thread pool for provider network I/O.  Separate from the
# default executor that AnyIO/Starlette uses for sync route handlers,
# so scan I/O never competes with /health or /auth/*/status handlers.
IO_POOL = ThreadPoolExecutor(max_workers=MAX_CONCURRENT_ANALYSES, thread_name_prefix="scan-io")

# Dedicated process pool for CPU-heavy analysis.  Child processes have
# their own GIL, so ML inference here cannot starve the main process.
# Workers are kept small to limit memory (each loads its own copy of
# the scikit-learn models, ~50-100MB).
#
# BUG FIX (RC - "nested executor explosion", see DIAGNOSTIC_EVIDENCE.md):
# this used to be a module-level `CPU_POOL = ProcessPoolExecutor(...)`
# constructed at import time. `_analyze_in_subprocess` below is the
# picklable callable submitted to that pool, and it lives in *this same
# module*. On every platform where ProcessPoolExecutor workers are
# spawned (always on Windows; also on Linux/macOS if the start method
# is "spawn"), a worker process unpickling that callable must import
# `backend.app.services.scan_service` by dotted path to resolve it -
# which re-runs this module's top-level code, including the
# `ProcessPoolExecutor(max_workers=3)` construction, *inside every
# worker process*. Reproduced directly (see DIAGNOSTIC_EVIDENCE.md):
# each worker created its own unused nested pool and its own
# multiprocessing queues/semaphores that were never shut down,
# producing "leaked semaphore" warnings and steadily growing resource
# usage under repeated scans. It also means the very first scan
# request pays for constructing N+1 process pools instead of 1.
#
# Fix: make pool creation lazy and guarded so it can only ever happen
# once, in the real main process. Worker processes never call
# get_cpu_pool() themselves - they only execute
# _analyze_in_subprocess - so the guard should never actually trip in
# normal operation; it exists to fail loudly instead of silently
# spawning nested pools if that assumption is ever violated.
_CPU_POOL: ProcessPoolExecutor | None = None
_CPU_POOL_LOCK = threading.Lock()

# IMPORTANT: Uvicorn --reload starts the actual application server in a
# spawned child process on Windows, so `current_process().name ==
# "MainProcess"` is NOT a valid way to identify the application process.
# Instead, mark only the actual ProcessPoolExecutor workers with an
# initializer. The application/reloader/server process is allowed to
# create the single CPU pool; its pool workers are explicitly marked so
# accidental nested pool creation still fails loudly.
_IS_CPU_WORKER = False


def _mark_cpu_worker() -> None:
    """ProcessPool initializer: mark this process as a CPU worker."""
    global _IS_CPU_WORKER
    _IS_CPU_WORKER = True


def get_cpu_pool() -> ProcessPoolExecutor:
    """Lazily create one CPU pool in the application process.

    This must work when the FastAPI server itself was spawned by
    Uvicorn's Windows reloader. CPUPool workers are identified by the
    explicit initializer above rather than by multiprocessing process
    name, because Uvicorn's server process is also a spawned process on
    Windows.
    """
    global _CPU_POOL
    if _CPU_POOL is not None:
        return _CPU_POOL

    if _IS_CPU_WORKER:
        raise RuntimeError(
            "Refusing to create a nested ProcessPoolExecutor inside a "
            "worker process. This should never happen - worker "
            "processes must only execute _analyze_in_subprocess."
        )

    with _CPU_POOL_LOCK:
        if _CPU_POOL is None:
            _CPU_POOL = ProcessPoolExecutor(
                max_workers=3,
                initializer=_mark_cpu_worker,
            )
    return _CPU_POOL


def _analyze_in_subprocess(email_dict: dict) -> dict:
    """
    Top-level function (picklable) that runs in a CPU_POOL child process.
    Imports are done inside the function so each child process loads its
    own copy of the ML models at first use.
    """
    from backend.app.schemas.email_message import NormalizedEmail
    from backend.app.services.analysis_service import analyze_email_safe

    email = NormalizedEmail(**email_dict)
    return analyze_email_safe(email)


# Largest single scan request accepted, in message IDs. Matches
# ALLOWED_PAGE_SIZES' max in main.py - kept as a plain constant here
# (not imported from main.py) to avoid a service module depending on
# the route module. main.py additionally re-validates against its own
# ALLOWED_PAGE_SIZES for the size the frontend claims to be sending.
MAX_SCAN_MESSAGE_IDS = 100


def validate_scan_message_ids(message_ids: list[str] | None) -> list[str]:
    """
    Validate and normalize a client-supplied list of message IDs for a
    scan request.

    BUG FIX (page-scoped scan bug - see DIAGNOSTIC_EVIDENCE.md):
    /api/scan used to accept only a `count` integer and independently
    re-derive "the first N messages in the mailbox" via its own
    from-scratch pagination loop (page_token starting at None every
    time), completely ignoring which page the user was actually
    viewing in the UI. Anyone on page 2+ who clicked Scan had page 1's
    messages analyzed instead, silently. The fix requires the caller
    (the frontend) to send the exact message IDs it is currently
    displaying; this function validates that input instead of the
    route re-deriving anything from the mailbox.

    Ownership/session-scoping is enforced by the natural authorization
    boundary the Gmail/Graph API already provides, not by tracking a
    server-side registry of "which IDs are legitimate for this
    session": every message_id here is subsequently fetched via
    `provider.get_message(message_id)`, which is called with the
    *authenticated session's own credentials* (see gmail_provider.py -
    every API call is scoped to `userId="me"`). An ID that does not
    belong to that mailbox simply cannot be fetched under that token -
    it fails at the provider/API level and is recorded as a normal
    per-message failure (`status: "analysis_failed"`), the same way any
    other fetch failure already is. This avoids introducing new
    server-side state to duplicate an authorization check the provider
    abstraction already performs for free.

    Raises ValueError with a caller-safe message on invalid input.
    """
    if not message_ids:
        raise ValueError("message_ids must be a non-empty list.")

    if not isinstance(message_ids, list) or not all(
        isinstance(m, str) and m.strip() for m in message_ids
    ):
        raise ValueError("message_ids must be a list of non-empty strings.")

    # De-duplicate while preserving order - defensive against a client
    # bug or a retried request analyzing the same message twice in one
    # scan.
    seen: set[str] = set()
    deduped: list[str] = []
    for mid in message_ids:
        if mid not in seen:
            seen.add(mid)
            deduped.append(mid)

    if len(deduped) > MAX_SCAN_MESSAGE_IDS:
        raise ValueError(
            f"Cannot scan more than {MAX_SCAN_MESSAGE_IDS} messages in a "
            f"single request (got {len(deduped)})."
        )

    return deduped


async def run_scan(
    *,
    scan_id: str,
    session_id: str,
    provider: MailProvider,
    message_ids: list[str],
) -> None:
    semaphore = asyncio.Semaphore(MAX_CONCURRENT_ANALYSES)
    loop = asyncio.get_event_loop()

    async def process_one(message_id: str) -> None:
        async with semaphore:
            overall_start = time.perf_counter()
            try:
                # I/O phase: fetch raw email from provider (network call)
                fetch_start = time.perf_counter()
                email = await loop.run_in_executor(
                    IO_POOL, provider.get_message, message_id
                )
                fetch_time = round(time.perf_counter() - fetch_start, 4)

                # CPU phase: full analysis in a child process
                cpu_start = time.perf_counter()
                result = await loop.run_in_executor(
                    get_cpu_pool(), _analyze_in_subprocess, email.model_dump()
                )
                cpu_time = round(time.perf_counter() - cpu_start, 4)

                total_time = round(time.perf_counter() - overall_start, 4)
                logger.info(
                    "email %s: fetch=%ss cpu=%ss total=%ss",
                    message_id, fetch_time, cpu_time, total_time,
                )

            except Exception as exc:
                # Provider-level failure (network, auth expiry, ...)
                result = {
                    "message_id": message_id,
                    "provider": provider.name,
                    "status": "analysis_failed",
                    "error": str(exc),
                    "risk": {
                        "score": 0, "level": "UNKNOWN",
                        "reasons": [], "contributing_modules": [],
                    },
                    "geo_status": "not_applicable",
                }
                logger.warning(
                    "email %s: analysis failed in %ss: %s",
                    message_id, round(time.perf_counter() - overall_start, 4), exc,
                )

            # Store result and atomically update scan progress
            STORE.append_scan_result(scan_id, result)
            STORE.save_result(
                session_id=session_id,
                provider=provider.name,
                account_id=result.get("account_id", ""),
                message_id=message_id,
                result=result,
            )

            if result.get("status") == "analysis_failed":
                STORE.increment_scan_progress(scan_id, failed=1)
            else:
                STORE.increment_scan_progress(scan_id, analyzed=1)

            # Fire background geolocation enrichment (tracked, not fire-and-forget)
            origin_ip = (result.get("m1") or {}).get("origin_ip")
            if origin_ip and result.get("status") != "analysis_failed":
                # Import here to avoid circular imports at module level
                from backend.app.services.geo_enrichment import enqueue_geo_enrichment
                enqueue_geo_enrichment(
                    ip=origin_ip,
                    session_id=session_id,
                    provider=provider.name,
                    account_id=result.get("account_id", ""),
                    message_id=message_id,
                    risk_level=(result.get("risk") or {}).get("level", "UNKNOWN"),
                )

    await asyncio.gather(*(process_one(mid) for mid in message_ids))

    STORE.update_scan(scan_id, status="complete")
    logger.info("scan %s: complete (%d messages)", scan_id, len(message_ids))
