"""
Tests for ResultStore: thread safety, atomic increments, provider
alias compatibility, enrichment updates, and scan invariants.
"""
from __future__ import annotations

import threading
import time

import pytest

from backend.app.services.store import ResultStore, _canonical_provider
from backend.app.services.db import get_database


# ── Provider alias ──────────────────────────────────────────────────

class TestProviderAlias:
    def test_gmail_maps_to_google(self):
        assert _canonical_provider("gmail") == "google"

    def test_google_stays_google(self):
        assert _canonical_provider("google") == "google"

    def test_microsoft_stays_microsoft(self):
        assert _canonical_provider("microsoft") == "microsoft"

    def test_save_with_gmail_retrieve_with_google(self, fresh_store):
        """Legacy results saved under 'gmail' must be found via 'google'."""
        fresh_store.save_result(
            session_id="s1", provider="gmail", account_id="a@b.com",
            message_id="m1", result={"status": "analyzed", "risk": {"level": "LOW"}},
        )
        r = fresh_store.get_result(
            session_id="s1", provider="google", account_id="a@b.com",
            message_id="m1",
        )
        assert r is not None
        assert r["status"] == "analyzed"

    def test_save_with_google_retrieve_with_gmail(self, fresh_store):
        """Results saved under 'google' must also be found via 'gmail'."""
        fresh_store.save_result(
            session_id="s1", provider="google", account_id="a@b.com",
            message_id="m2", result={"status": "analyzed"},
        )
        r = fresh_store.get_result(
            session_id="s1", provider="gmail", account_id="a@b.com",
            message_id="m2",
        )
        assert r is not None


# ── Session isolation ───────────────────────────────────────────────

class TestSessionIsolation:
    def test_cross_session_invisible(self, fresh_store):
        fresh_store.save_result(
            session_id="alice", provider="google", account_id="a@b.com",
            message_id="m1", result={"secret": True},
        )
        bob_result = fresh_store.get_result(
            session_id="bob", provider="google", account_id="a@b.com",
            message_id="m1",
        )
        assert bob_result is None

    def test_list_results_session_scoped(self, fresh_store):
        for sid in ["alice", "bob"]:
            fresh_store.save_result(
                session_id=sid, provider="google", account_id="a@b.com",
                message_id=f"m-{sid}", result={"owner": sid},
            )
        alice_results = fresh_store.list_results(session_id="alice")
        assert len(alice_results) == 1
        assert alice_results[0]["owner"] == "alice"


# ── Scan progress: atomic increments ───────────────────────────────

class TestScanProgress:
    def test_basic_progress(self, fresh_store):
        scan_id = fresh_store.create_scan(session_id="s1", requested=5)
        fresh_store.increment_scan_progress(scan_id, analyzed=1)
        fresh_store.increment_scan_progress(scan_id, analyzed=1)
        fresh_store.increment_scan_progress(scan_id, failed=1)

        scan = fresh_store.get_scan(scan_id, session_id="s1")
        assert scan["analyzed"] == 2
        assert scan["failed"] == 1
        assert scan["analyzed"] + scan["failed"] <= scan["requested"]

    def test_concurrent_increments(self, fresh_store):
        """Stress test: 100 threads each incrementing analyzed by 1.
        Final count must be exactly 100."""
        scan_id = fresh_store.create_scan(session_id="s1", requested=100)
        barrier = threading.Barrier(100)

        def worker():
            barrier.wait()
            fresh_store.increment_scan_progress(scan_id, analyzed=1)

        threads = [threading.Thread(target=worker) for _ in range(100)]
        for t in threads:
            t.start()
        for t in threads:
            t.join()

        scan = fresh_store.get_scan(scan_id, session_id="s1")
        assert scan["analyzed"] == 100
        assert scan["failed"] == 0

    def test_invariant_analyzed_plus_failed_lte_requested(self, fresh_store):
        scan_id = fresh_store.create_scan(session_id="s1", requested=3)
        for _ in range(2):
            fresh_store.increment_scan_progress(scan_id, analyzed=1)
        fresh_store.increment_scan_progress(scan_id, failed=1)

        scan = fresh_store.get_scan(scan_id, session_id="s1")
        assert scan["analyzed"] + scan["failed"] <= scan["requested"]

    def test_scan_owner_isolation(self, fresh_store):
        scan_id = fresh_store.create_scan(session_id="alice", requested=5)
        assert fresh_store.get_scan(scan_id, session_id="bob") is None
        assert fresh_store.get_scan(scan_id, session_id="alice") is not None


# ── Enrichment update ──────────────────────────────────────────────

class TestEnrichment:
    def test_enrichment_updates_geo_not_verdict(self, fresh_store):
        fresh_store.save_result(
            session_id="s1", provider="google", account_id="a@b.com",
            message_id="m1", result={
                "status": "analyzed",
                "risk": {"score": 75, "level": "HIGH", "reasons": ["SPF failed"]},
                "m4": [],
                "geo_status": "pending",
            },
        )
        ok = fresh_store.update_result_enrichment(
            session_id="s1", provider="google", account_id="a@b.com",
            message_id="m1", enrichment={
                "geo": [{"ip": "1.2.3.4", "country": "US", "city": "NYC"}],
                "geo_status": "completed",
            },
        )
        assert ok is True

        result = fresh_store.get_result(
            session_id="s1", provider="google", account_id="a@b.com",
            message_id="m1",
        )
        assert result["geo_status"] == "completed"
        assert len(result["m4"]) == 1
        # Verdict MUST be unchanged
        assert result["risk"]["score"] == 75
        assert result["risk"]["level"] == "HIGH"

    def test_enrichment_failure_preserves_verdict(self, fresh_store):
        fresh_store.save_result(
            session_id="s1", provider="google", account_id="a@b.com",
            message_id="m1", result={
                "status": "analyzed",
                "risk": {"score": 20, "level": "LOW", "reasons": []},
                "m4": [],
                "geo_status": "pending",
            },
        )
        fresh_store.update_result_enrichment(
            session_id="s1", provider="google", account_id="a@b.com",
            message_id="m1", enrichment={"geo": [], "geo_status": "failed"},
        )
        result = fresh_store.get_result(
            session_id="s1", provider="google", account_id="a@b.com",
            message_id="m1",
        )
        assert result["risk"]["level"] == "LOW"  # unchanged
        assert result["geo_status"] == "failed"


# ── Suspicious results listing ─────────────────────────────────────

class TestSuspiciousListing:
    def test_only_high_critical_returned(self, fresh_store):
        for level in ["LOW", "MEDIUM", "HIGH", "CRITICAL"]:
            fresh_store.save_result(
                session_id="s1", provider="google", account_id="a@b.com",
                message_id=f"m-{level}", result={
                    "risk": {"level": level},
                },
            )
        suspicious = fresh_store.list_suspicious_results(session_id="s1")
        levels = {r["risk"]["level"] for r in suspicious}
        assert levels == {"HIGH", "CRITICAL"}
        assert len(suspicious) == 2


# ── SQLite persistence (project handoff: SQLite + local cache task) ──
#
# fresh_store (see conftest.py) is a ResultStore() with no explicit
# db_path, i.e. a private ":memory:" database - same "fresh instance
# = fresh isolated state" behavior the old plain-dict ResultStore had.
# These new tests instead use an explicit tmp_path file to prove data
# actually survives a store object being thrown away and recreated -
# the thing a real process restart does - without touching any of the
# existing tests/fixtures above.

class TestSQLitePersistence:
    def test_result_survives_store_recreation(self, tmp_path):
        db_path = str(tmp_path / "persist.sqlite3")
        store1 = ResultStore(db_path=db_path)
        store1.save_result(
            session_id="s1", provider="google", account_id="a@b.com",
            message_id="m1", result={"status": "analyzed", "risk": {"level": "HIGH"}},
        )

        store2 = ResultStore(db_path=db_path)  # simulates a process restart
        result = store2.get_result(
            session_id="s1", provider="google", account_id="a@b.com", message_id="m1"
        )
        assert result is not None
        assert result["risk"]["level"] == "HIGH"

    def test_scan_and_its_results_survive_store_recreation(self, tmp_path):
        db_path = str(tmp_path / "persist_scan.sqlite3")
        store1 = ResultStore(db_path=db_path)
        scan_id = store1.create_scan(session_id="s1", requested=1)
        store1.append_scan_result(scan_id, {"message_id": "m1", "status": "analyzed"})
        store1.increment_scan_progress(scan_id, analyzed=1)
        store1.update_scan(scan_id, status="complete")

        store2 = ResultStore(db_path=db_path)
        scan = store2.get_scan(scan_id, session_id="s1")
        assert scan is not None
        assert scan["status"] == "complete"
        assert scan["analyzed"] == 1
        assert len(scan["results"]) == 1
        assert scan["results"][0]["message_id"] == "m1"

    def test_memory_stores_are_never_shared_across_instances(self):
        """Two ResultStore() calls with no db_path must behave like
        two independent in-memory dicts always did - never leak into
        each other."""
        store1 = ResultStore()
        store2 = ResultStore()
        store1.save_result(
            session_id="s1", provider="google", account_id="a@b.com",
            message_id="m1", result={"status": "analyzed"},
        )
        assert store2.get_result(
            session_id="s1", provider="google", account_id="a@b.com", message_id="m1"
        ) is None


class TestAccountAndProviderIsolation:
    """Beyond session isolation (TestSessionIsolation above): two
    different mailboxes, or the same mailbox under two providers,
    must never see each other's cached results even under the same
    session_id."""

    def test_different_account_ids_isolated(self, fresh_store):
        fresh_store.save_result(
            session_id="s1", provider="google", account_id="alice@b.com",
            message_id="m1", result={"risk": {"level": "HIGH"}},
        )
        fresh_store.save_result(
            session_id="s1", provider="google", account_id="bob@b.com",
            message_id="m1", result={"risk": {"level": "LOW"}},
        )
        alice = fresh_store.get_result(
            session_id="s1", provider="google", account_id="alice@b.com", message_id="m1"
        )
        bob = fresh_store.get_result(
            session_id="s1", provider="google", account_id="bob@b.com", message_id="m1"
        )
        assert alice["risk"]["level"] == "HIGH"
        assert bob["risk"]["level"] == "LOW"

    def test_same_account_different_provider_isolated(self, fresh_store):
        fresh_store.save_result(
            session_id="s1", provider="google", account_id="a@b.com",
            message_id="m1", result={"risk": {"level": "HIGH"}},
        )
        fresh_store.save_result(
            session_id="s1", provider="microsoft", account_id="a@b.com",
            message_id="m1", result={"risk": {"level": "CRITICAL"}},
        )
        google_r = fresh_store.get_result(
            session_id="s1", provider="google", account_id="a@b.com", message_id="m1"
        )
        ms_r = fresh_store.get_result(
            session_id="s1", provider="microsoft", account_id="a@b.com", message_id="m1"
        )
        assert google_r["risk"]["level"] == "HIGH"
        assert ms_r["risk"]["level"] == "CRITICAL"


class TestScanUpdateSafelist:
    def test_update_scan_ignores_unknown_fields(self, fresh_store):
        """update_scan must not raise or silently accept arbitrary
        column names - only the small safelist it documents."""
        scan_id = fresh_store.create_scan(session_id="s1", requested=1)
        fresh_store.update_scan(scan_id, status="complete", not_a_real_column="ignored")
        scan = fresh_store.get_scan(scan_id, session_id="s1")
        assert scan["status"] == "complete"

    def test_update_scan_on_unknown_scan_id_is_a_noop(self, fresh_store):
        fresh_store.update_scan("does-not-exist", status="complete")  # must not raise


class TestGetRunningScanForSession:
    def test_returns_running_scan(self, fresh_store):
        scan_id = fresh_store.create_scan(session_id="s1", requested=3)
        running = fresh_store.get_running_scan_for_session("s1")
        assert running is not None
        assert running["scan_id"] == scan_id

    def test_none_when_only_completed_scans_exist(self, fresh_store):
        scan_id = fresh_store.create_scan(session_id="s1", requested=1)
        fresh_store.update_scan(scan_id, status="complete")
        assert fresh_store.get_running_scan_for_session("s1") is None

    def test_scoped_to_session(self, fresh_store):
        fresh_store.create_scan(session_id="alice", requested=1)
        assert fresh_store.get_running_scan_for_session("bob") is None
