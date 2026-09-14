"""
Retention/cleanup for locally cached mailbox data and analysis
history (project handoff Task 8).

Everything this module deletes is a cache or a history record -
never OAuth credentials or tokens. Those never enter SQLite in the
first place: `auth/session.py`'s SESSION_STORE (which holds Google
Credentials objects / Microsoft access+refresh tokens) is a separate,
still in-memory-only dict that this module never touches.

Default retention window is ~30 days, configurable via the
VALORPROTECTS_RETENTION_DAYS environment variable.
"""

from __future__ import annotations

import os
import time

from backend.app.services.db import get_database

DEFAULT_RETENTION_DAYS = 30


def retention_seconds() -> float:
    """Current retention window, in seconds, re-read from the
    environment on every call so it can be changed without a
    restart-time-only config load."""
    raw = os.environ.get("VALORPROTECTS_RETENTION_DAYS", str(DEFAULT_RETENTION_DAYS))
    try:
        days = float(raw)
    except ValueError:
        days = DEFAULT_RETENTION_DAYS
    return days * 86400.0


def run_retention_cleanup(db_path: str | None = None, *, now: float | None = None,
                           retention_seconds_override: float | None = None) -> dict[str, int]:
    """
    Delete cached/history rows older than the retention window.

    Never deletes:
      - a scan whose status is still "running" (an in-progress scan
        is never "stale" no matter how old started_at is)
      - scan_results rows for a scan that is still present (they are
        only removed together with their parent scan row, so a scan
        can never end up with some but not all of its results gone)

    Returns a dict of rows removed per table (for logging and tests).
    `db_path=None` operates on an anonymous, empty ":memory:" database
    (matches ResultStore/MailboxCache's convention) - real callers
    (main.py) pass the actual persistent file path.
    """
    db = get_database(db_path if db_path is not None else ":memory:")
    cutoff = (now if now is not None else time.time()) - (
        retention_seconds_override if retention_seconds_override is not None
        else retention_seconds()
    )

    removed: dict[str, int] = {}
    with db.lock:
        conn = db.conn

        cur = conn.execute("DELETE FROM page_cache WHERE fetched_at < ?", (cutoff,))
        removed["page_cache"] = cur.rowcount

        cur = conn.execute("DELETE FROM messages WHERE fetched_at < ?", (cutoff,))
        removed["messages"] = cur.rowcount

        cur = conn.execute("DELETE FROM analysis_results WHERE updated_at < ?", (cutoff,))
        removed["analysis_results"] = cur.rowcount

        stale_scan_ids = [
            r["scan_id"] for r in conn.execute(
                "SELECT scan_id FROM scans WHERE started_at < ? AND status != 'running'",
                (cutoff,),
            ).fetchall()
        ]
        removed["scans"] = 0
        removed["scan_results"] = 0
        for scan_id in stale_scan_ids:
            cur = conn.execute("DELETE FROM scan_results WHERE scan_id = ?", (scan_id,))
            removed["scan_results"] += cur.rowcount
            conn.execute("DELETE FROM scans WHERE scan_id = ?", (scan_id,))
            removed["scans"] += 1

        conn.commit()

    return removed
