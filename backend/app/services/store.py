"""
Result/scan persistence, backed by SQLite (see db.py).

SQLite is the persistent source of truth; this class is the only
thing that talks to it for results/scans, so every other module
keeps working with plain dicts exactly as before.

DEMO LIMITATION, updated: results and scan history used to live only
in process memory and were lost on restart. They are now persisted
to a local SQLite file (see db.py:default_db_path) and survive a
process restart. What does NOT survive a restart is the *browser
session* itself (see auth/session.py's SESSION_STORE, still
in-memory by design) - so a fresh /api/scans/history call after a
restart needs the same session_id that wrote the data, i.e. the same
still-valid session cookie from before the restart, to see it. This
mirrors the ownership model already enforced by every method below
and by the pre-existing tests in test_store.py; it is not changed by
this file.

Every cached item carries its owner. Nothing is ever looked up by
message_id alone - always (session_id, provider, account_id,
message_id), so User A can never read User B's cached results even
if message ids happened to collide across mailboxes.

Thread-safety: all mutations go through the underlying Database's
lock (see db.py), so concurrent scan tasks (which run in separate
threads/processes) never race on counter increments or result
appends. This is the same single-lock guarantee the old in-memory
implementation had - just now also flushed to disk.
"""

from __future__ import annotations

import json
import threading
import time
import uuid

from backend.app.services.db import Database, default_db_path, get_database
# Legacy provider names that should be treated as equivalent to the
# canonical name.  When GmailProvider.name changed from "gmail" to
# "google", any results stored during a previous session under
# "gmail" would become orphaned without this mapping.
_PROVIDER_ALIASES: dict[str, str] = {
    "gmail": "google",
}

HIGH_RISK_LEVELS = {"HIGH", "CRITICAL"}


def _canonical_provider(provider: str) -> str:
    """Resolve a provider name to its canonical form."""
    return _PROVIDER_ALIASES.get(provider, provider)


class ResultStore:
    def __init__(self, db_path: str | None = None):
        # Matches the old "fresh ResultStore() == fresh isolated
        # state" behavior tests rely on: an explicit path (or the
        # real default file, used by the module-level STORE below)
        # is shared/persistent; no path at all means an anonymous,
        # private ":memory:" database, same lifetime as the old
        # plain-dict instance.
        self._db: Database = get_database(db_path if db_path is not None else ":memory:")

    @property
    def _lock(self) -> threading.RLock:
        return self._db.lock

    @property
    def _conn(self):
        return self._db.conn

    # ----------------------------------------------------------------
    # Results
    # ----------------------------------------------------------------

    def save_result(self, *, session_id: str, provider: str, account_id: str,
                     message_id: str, result: dict) -> None:
        provider = _canonical_provider(provider)
        risk_level = (result.get("risk") or {}).get("level")
        analyzed_at = result.get("analyzed_at")
        now = time.time()
        with self._lock:
            self._conn.execute(
                """
                INSERT INTO analysis_results
                    (session_id, provider, account_id, message_id,
                     result_json, risk_level, analyzed_at, updated_at)
                VALUES (?, ?, ?, ?, ?, ?, ?, ?)
                ON CONFLICT(session_id, provider, account_id, message_id)
                DO UPDATE SET
                    result_json = excluded.result_json,
                    risk_level = excluded.risk_level,
                    analyzed_at = excluded.analyzed_at,
                    updated_at = excluded.updated_at
                """,
                (session_id, provider, account_id, message_id,
                 json.dumps(result), risk_level, analyzed_at, now),
            )
            self._conn.commit()

    def get_result(self, *, session_id: str, provider: str, account_id: str,
                    message_id: str) -> dict | None:
        provider = _canonical_provider(provider)
        with self._lock:
            row = self._conn.execute(
                """
                SELECT result_json FROM analysis_results
                WHERE session_id = ? AND provider = ? AND account_id = ?
                      AND message_id = ?
                """,
                (session_id, provider, account_id, message_id),
            ).fetchone()
        return json.loads(row["result_json"]) if row else None

    def list_results(self, *, session_id: str, provider: str | None = None) -> list[dict]:
        if provider is not None:
            provider = _canonical_provider(provider)
        with self._lock:
            if provider is None:
                rows = self._conn.execute(
                    """
                    SELECT result_json FROM analysis_results
                    WHERE session_id = ? ORDER BY rowid
                    """,
                    (session_id,),
                ).fetchall()
            else:
                rows = self._conn.execute(
                    """
                    SELECT result_json FROM analysis_results
                    WHERE session_id = ? AND provider = ? ORDER BY rowid
                    """,
                    (session_id, provider),
                ).fetchall()
        return [json.loads(r["result_json"]) for r in rows]

    def update_result_enrichment(self, *, session_id: str, provider: str,
                                  account_id: str, message_id: str,
                                  enrichment: dict) -> bool:
        """
        Merge enrichment data (e.g. geolocation) into an existing result
        WITHOUT changing the primary verdict (risk score/level/reasons).

        Returns True if the result was found and updated, False otherwise.
        """
        provider = _canonical_provider(provider)
        with self._lock:
            row = self._conn.execute(
                """
                SELECT result_json FROM analysis_results
                WHERE session_id = ? AND provider = ? AND account_id = ?
                      AND message_id = ?
                """,
                (session_id, provider, account_id, message_id),
            ).fetchone()
            if row is None:
                return False

            result = json.loads(row["result_json"])
            # Merge geolocation into m4 array
            if "geo" in enrichment:
                result["m4"] = enrichment["geo"]
                result["geo_status"] = enrichment.get("geo_status", "completed")
            # Never touch risk/score/level/reasons — those are final

            self._conn.execute(
                """
                UPDATE analysis_results SET result_json = ?, updated_at = ?
                WHERE session_id = ? AND provider = ? AND account_id = ?
                      AND message_id = ?
                """,
                (json.dumps(result), time.time(),
                 session_id, provider, account_id, message_id),
            )
            self._conn.commit()
            return True

    def list_suspicious_results(self, *, session_id: str) -> list[dict]:
        """Return only HIGH/CRITICAL results for threat-geo analytics."""
        placeholders = ",".join("?" for _ in HIGH_RISK_LEVELS)
        with self._lock:
            rows = self._conn.execute(
                f"""
                SELECT result_json FROM analysis_results
                WHERE session_id = ? AND risk_level IN ({placeholders})
                ORDER BY rowid
                """,
                (session_id, *HIGH_RISK_LEVELS),
            ).fetchall()
        return [json.loads(r["result_json"]) for r in rows]

    # ----------------------------------------------------------------
    # Scan progress
    # ----------------------------------------------------------------

    def create_scan(self, *, session_id: str, requested: int) -> str:
        scan_id = str(uuid.uuid4())
        now = time.time()
        with self._lock:
            self._conn.execute(
                """
                INSERT INTO scans
                    (scan_id, session_id, requested, analyzed, failed,
                     status, started_at, updated_at)
                VALUES (?, ?, ?, 0, 0, 'running', ?, ?)
                """,
                (scan_id, session_id, requested, now, now),
            )
            self._conn.commit()
        return scan_id

    def _row_to_scan(self, row) -> dict:
        with self._lock:
            result_rows = self._conn.execute(
                "SELECT result_json FROM scan_results WHERE scan_id = ? ORDER BY seq",
                (row["scan_id"],),
            ).fetchall()
        return {
            "scan_id": row["scan_id"],
            "owner_session_id": row["session_id"],
            "requested": row["requested"],
            "analyzed": row["analyzed"],
            "failed": row["failed"],
            "status": row["status"],
            "results": [json.loads(r["result_json"]) for r in result_rows],
            "started_at": row["started_at"],
        }

    def get_scan(self, scan_id: str, *, session_id: str) -> dict | None:
        with self._lock:
            row = self._conn.execute(
                "SELECT * FROM scans WHERE scan_id = ?", (scan_id,)
            ).fetchone()
        if row is None or row["session_id"] != session_id:
            return None
        return self._row_to_scan(row)

    def update_scan(self, scan_id: str, **fields) -> None:
        if not fields:
            return
        # Small, explicit safelist rather than building SQL column
        # names from arbitrary kwargs - the only field this project
        # ever updates post-creation is `status` (see scan_service.py
        # run_scan's final "complete" transition), but a safelist
        # keeps this defensible even if that changes.
        allowed = {"status", "requested"}
        set_clauses = []
        params: list = []
        for key, value in fields.items():
            if key not in allowed:
                continue
            set_clauses.append(f"{key} = ?")
            params.append(value)
        if not set_clauses:
            return
        set_clauses.append("updated_at = ?")
        params.append(time.time())
        params.append(scan_id)
        with self._lock:
            if self._conn.execute(
                "SELECT 1 FROM scans WHERE scan_id = ?", (scan_id,)
            ).fetchone() is None:
                return
            self._conn.execute(
                f"UPDATE scans SET {', '.join(set_clauses)} WHERE scan_id = ?",
                params,
            )
            self._conn.commit()

    def increment_scan_progress(self, scan_id: str, *, analyzed: int = 0,
                                 failed: int = 0) -> None:
        """
        Atomically increment analyzed/failed counters.  This replaces
        the old read-modify-write pattern that raced when multiple
        process_one tasks finished simultaneously.

        Invariant: analyzed + failed <= requested is maintained because
        each message increments exactly once. The single Database lock
        (held for the whole UPDATE) is what makes this atomic across
        threads, same guarantee as the old in-memory version.
        """
        if analyzed == 0 and failed == 0:
            return
        with self._lock:
            self._conn.execute(
                """
                UPDATE scans
                SET analyzed = analyzed + ?, failed = failed + ?, updated_at = ?
                WHERE scan_id = ?
                """,
                (analyzed, failed, time.time(), scan_id),
            )
            self._conn.commit()

    def append_scan_result(self, scan_id: str, result: dict) -> None:
        with self._lock:
            if self._conn.execute(
                "SELECT 1 FROM scans WHERE scan_id = ?", (scan_id,)
            ).fetchone() is None:
                return
            next_seq = self._conn.execute(
                "SELECT COALESCE(MAX(seq), -1) + 1 AS n FROM scan_results WHERE scan_id = ?",
                (scan_id,),
            ).fetchone()["n"]
            self._conn.execute(
                "INSERT INTO scan_results (scan_id, seq, result_json) VALUES (?, ?, ?)",
                (scan_id, next_seq, json.dumps(result)),
            )
            self._conn.commit()

    def get_running_scan_for_session(self, session_id: str) -> dict | None:
        """Return the most recent running scan for a session (for refresh recovery)."""
        with self._lock:
            row = self._conn.execute(
                """
                SELECT * FROM scans
                WHERE session_id = ? AND status = 'running'
                ORDER BY started_at DESC LIMIT 1
                """,
                (session_id,),
            ).fetchone()
        return self._row_to_scan(row) if row is not None else None


# The module-level singleton is the one instance that points at the
# real, persistent database file (db.py's default_db_path()) instead
# of an anonymous, throwaway ":memory:" database. Everything in the
# running server shares this one STORE, same as before this change -
# only its backing storage moved from a plain dict to SQLite.
STORE = ResultStore(db_path=str(default_db_path()))
