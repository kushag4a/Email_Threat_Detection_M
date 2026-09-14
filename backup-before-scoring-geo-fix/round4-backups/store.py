"""
In-memory result cache.

DEMO LIMITATION: process memory only; cleared on restart. Acceptable
for the hackathon per the spec. If persistence is added later, prefer
SQLite over introducing new infrastructure (see PROJECT_CONTEXT.md).

Every cached item carries its owner. Nothing is ever looked up by
message_id alone - always (session_id, provider, account_id,
message_id), so User A can never read User B's cached results even
if message ids happened to collide across mailboxes.

Thread-safety: all mutations go through a threading.Lock so that
concurrent scan tasks (which run in separate threads/processes) never
race on counter increments or result appends.
"""

from __future__ import annotations

import threading
import time
import uuid

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
    def __init__(self):
        self._lock = threading.Lock()
        # key: (session_id, provider, account_id, message_id) -> record
        self._results: dict[tuple, dict] = {}
        # scan_id -> progress dict (also owner-scoped via session_id inside)
        self._scans: dict[str, dict] = {}

    # ----------------------------------------------------------------
    # Results
    # ----------------------------------------------------------------

    def save_result(self, *, session_id: str, provider: str, account_id: str,
                     message_id: str, result: dict) -> None:
        provider = _canonical_provider(provider)
        key = (session_id, provider, account_id, message_id)
        with self._lock:
            self._results[key] = {
                "owner_session_id": session_id,
                "provider": provider,
                "account_id": account_id,
                "message_id": message_id,
                "timestamp": time.time(),
                "result": result,
            }

    def get_result(self, *, session_id: str, provider: str, account_id: str,
                    message_id: str) -> dict | None:
        provider = _canonical_provider(provider)
        key = (session_id, provider, account_id, message_id)
        with self._lock:
            record = self._results.get(key)
            return dict(record["result"]) if record else None

    def list_results(self, *, session_id: str, provider: str | None = None) -> list[dict]:
        if provider is not None:
            provider = _canonical_provider(provider)
        with self._lock:
            return [
                r["result"]
                for r in self._results.values()
                if r["owner_session_id"] == session_id
                and (provider is None or r["provider"] == provider)
            ]

    def update_result_enrichment(self, *, session_id: str, provider: str,
                                  account_id: str, message_id: str,
                                  enrichment: dict) -> bool:
        """
        Merge enrichment data (e.g. geolocation) into an existing result
        WITHOUT changing the primary verdict (risk score/level/reasons).

        Returns True if the result was found and updated, False otherwise.
        """
        provider = _canonical_provider(provider)
        key = (session_id, provider, account_id, message_id)
        with self._lock:
            record = self._results.get(key)
            if record is None:
                return False
            result = record["result"]
            # Merge geolocation into m4 array
            if "geo" in enrichment:
                result["m4"] = enrichment["geo"]
                result["geo_status"] = enrichment.get("geo_status", "completed")
            # Never touch risk/score/level/reasons — those are final
            return True

    def list_suspicious_results(self, *, session_id: str) -> list[dict]:
        """Return only HIGH/CRITICAL results for threat-geo analytics."""
        with self._lock:
            return [
                r["result"]
                for r in self._results.values()
                if r["owner_session_id"] == session_id
                and (r["result"].get("risk") or {}).get("level") in HIGH_RISK_LEVELS
            ]

    # ----------------------------------------------------------------
    # Scan progress
    # ----------------------------------------------------------------

    def create_scan(self, *, session_id: str, requested: int) -> str:
        scan_id = str(uuid.uuid4())
        with self._lock:
            self._scans[scan_id] = {
                "scan_id": scan_id,
                "owner_session_id": session_id,
                "requested": requested,
                "analyzed": 0,
                "failed": 0,
                "skipped": 0,
                "status": "running",
                "results": [],
                "started_at": time.time(),
            }
        return scan_id

    def get_scan(self, scan_id: str, *, session_id: str) -> dict | None:
        with self._lock:
            scan = self._scans.get(scan_id)
            if not scan or scan["owner_session_id"] != session_id:
                return None
            # Return a snapshot so callers don't hold the lock
            return dict(scan)

    def update_scan(self, scan_id: str, **fields) -> None:
        with self._lock:
            if scan_id in self._scans:
                self._scans[scan_id].update(fields)

    def increment_scan_progress(self, scan_id: str, *, analyzed: int = 0,
                                 failed: int = 0) -> None:
        """
        Atomically increment analyzed/failed counters.  This replaces
        the old read-modify-write pattern that raced when multiple
        process_one tasks finished simultaneously.

        Invariant: analyzed + failed <= requested is maintained because
        each message increments exactly once.
        """
        with self._lock:
            scan = self._scans.get(scan_id)
            if scan is None:
                return
            scan["analyzed"] += analyzed
            scan["failed"] += failed

    def append_scan_result(self, scan_id: str, result: dict) -> None:
        with self._lock:
            if scan_id in self._scans:
                self._scans[scan_id]["results"].append(result)

    def get_running_scan_for_session(self, session_id: str) -> dict | None:
        """Return the most recent running scan for a session (for refresh recovery)."""
        with self._lock:
            for scan in reversed(list(self._scans.values())):
                if scan["owner_session_id"] == session_id and scan["status"] == "running":
                    return dict(scan)
        return None


STORE = ResultStore()
