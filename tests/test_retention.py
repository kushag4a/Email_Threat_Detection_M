"""
Tests for backend.app.services.retention: stale-row cleanup, active
(running) scan protection, and configurable retention window.
"""
from __future__ import annotations

import time

import pytest

from backend.app.services.db import get_database
from backend.app.services.mailbox_cache import MailboxCache
from backend.app.services.retention import retention_seconds, run_retention_cleanup
from backend.app.services.store import ResultStore

DAY = 86400.0


def _msg(mid: str) -> dict:
    return {
        "message_id": mid, "thread_id": None, "sender": "s", "recipient": "r",
        "subject": "S", "date": "D", "snippet": "sn", "has_attachments": False,
        "provider": "google",
    }


def _backdate_message(db, provider, account_id, message_id, when):
    with db.lock:
        db.conn.execute(
            """
            INSERT OR REPLACE INTO messages
                (provider, account_id, message_id, thread_id, sender, recipient,
                 subject, date, snippet, has_attachments, fetched_at)
            VALUES (?, ?, ?, NULL, 's', 'r', 'S', 'D', 'sn', 0, ?)
            """,
            (provider, account_id, message_id, when),
        )
        db.conn.commit()


def _backdate_page(db, provider, account_id, page_size, page_token, message_ids, when):
    import json
    with db.lock:
        db.conn.execute(
            """
            INSERT OR REPLACE INTO page_cache
                (provider, account_id, page_size, page_token, message_ids,
                 next_page_token, fetched_at)
            VALUES (?, ?, ?, ?, ?, NULL, ?)
            """,
            (provider, account_id, page_size, page_token or "", json.dumps(message_ids), when),
        )
        db.conn.commit()


def _backdate_analysis_result(db, session_id, provider, account_id, message_id, when):
    with db.lock:
        db.conn.execute(
            """
            INSERT OR REPLACE INTO analysis_results
                (session_id, provider, account_id, message_id, result_json,
                 risk_level, analyzed_at, updated_at)
            VALUES (?, ?, ?, ?, '{}', 'LOW', NULL, ?)
            """,
            (session_id, provider, account_id, message_id, when),
        )
        db.conn.commit()


def _insert_scan(db, scan_id, session_id, status, when):
    with db.lock:
        db.conn.execute(
            """
            INSERT INTO scans (scan_id, session_id, requested, analyzed, failed,
                                status, started_at, updated_at)
            VALUES (?, ?, 1, 1, 0, ?, ?, ?)
            """,
            (scan_id, session_id, status, when, when),
        )
        db.conn.execute(
            "INSERT INTO scan_results (scan_id, seq, result_json) VALUES (?, 0, '{}')",
            (scan_id,),
        )
        db.conn.commit()


@pytest.fixture
def rig(tmp_path):
    db_path = str(tmp_path / "retention.sqlite3")
    return {
        "db_path": db_path,
        "db": get_database(db_path),
        "cache": MailboxCache(db_path=db_path),
        "store": ResultStore(db_path=db_path),
    }


class TestRetentionCleanup:
    def test_stale_message_removed_fresh_kept(self, rig):
        now = time.time()
        old = now - 40 * DAY
        _backdate_message(rig["db"], "google", "a@b.com", "stale1", old)
        rig["cache"].save_messages(provider="google", account_id="a@b.com", messages=[_msg("fresh1")])

        run_retention_cleanup(db_path=rig["db_path"], now=now)

        assert rig["cache"].get_message(provider="google", account_id="a@b.com", message_id="stale1") is None
        assert rig["cache"].get_message(provider="google", account_id="a@b.com", message_id="fresh1") is not None

    def test_stale_page_cache_removed(self, rig):
        now = time.time()
        old = now - 40 * DAY
        _backdate_message(rig["db"], "google", "a@b.com", "stale1", old)
        _backdate_page(rig["db"], "google", "a@b.com", 5, "STALETOK", ["stale1"], old)

        removed = run_retention_cleanup(db_path=rig["db_path"], now=now)
        assert removed["page_cache"] >= 1

    def test_stale_analysis_result_removed_fresh_kept(self, rig):
        now = time.time()
        old = now - 40 * DAY
        _backdate_analysis_result(rig["db"], "s1", "google", "a@b.com", "stale1", old)
        rig["store"].save_result(
            session_id="s1", provider="google", account_id="a@b.com",
            message_id="fresh1", result={"status": "analyzed", "risk": {"level": "LOW"}},
        )

        run_retention_cleanup(db_path=rig["db_path"], now=now)

        assert rig["store"].get_result(session_id="s1", provider="google", account_id="a@b.com", message_id="stale1") is None
        assert rig["store"].get_result(session_id="s1", provider="google", account_id="a@b.com", message_id="fresh1") is not None

    def test_stale_completed_scan_removed(self, rig):
        now = time.time()
        old = now - 40 * DAY
        _insert_scan(rig["db"], "scan-stale", "s1", "complete", old)

        run_retention_cleanup(db_path=rig["db_path"], now=now)

        assert rig["store"].get_scan("scan-stale", session_id="s1") is None

    def test_stale_but_running_scan_is_never_removed(self, rig):
        """An in-progress scan is never 'stale', no matter how old
        started_at is - retention must not delete active data."""
        now = time.time()
        old = now - 400 * DAY
        _insert_scan(rig["db"], "scan-running", "s1", "running", old)

        run_retention_cleanup(db_path=rig["db_path"], now=now)

        scan = rig["store"].get_scan("scan-running", session_id="s1")
        assert scan is not None
        assert scan["status"] == "running"

    def test_scan_results_removed_with_their_scan_no_orphans(self, rig):
        now = time.time()
        old = now - 40 * DAY
        _insert_scan(rig["db"], "scan-stale", "s1", "complete", old)

        run_retention_cleanup(db_path=rig["db_path"], now=now)

        with rig["db"].lock:
            count = rig["db"].conn.execute(
                "SELECT COUNT(*) c FROM scan_results WHERE scan_id = ?", ("scan-stale",)
            ).fetchone()["c"]
        assert count == 0

    def test_fresh_data_survives_default_window(self, rig):
        rig["cache"].save_messages(provider="google", account_id="a@b.com", messages=[_msg("m1")])
        rig["store"].save_result(
            session_id="s1", provider="google", account_id="a@b.com",
            message_id="m1", result={"status": "analyzed", "risk": {"level": "LOW"}},
        )
        removed = run_retention_cleanup(db_path=rig["db_path"])
        assert all(v == 0 for v in removed.values())
        assert rig["cache"].get_message(provider="google", account_id="a@b.com", message_id="m1") is not None

    def test_configurable_retention_window(self, rig):
        now = time.time()
        five_days_old = now - 5 * DAY
        _backdate_message(rig["db"], "google", "a@b.com", "m5d", five_days_old)

        # A 3-day window should treat 5-day-old data as stale...
        removed_short = run_retention_cleanup(
            db_path=rig["db_path"], now=now, retention_seconds_override=3 * DAY
        )
        assert removed_short["messages"] == 1

    def test_env_var_controls_default_window(self, monkeypatch):
        monkeypatch.setenv("VALORPROTECTS_RETENTION_DAYS", "7")
        assert retention_seconds() == pytest.approx(7 * DAY)

    def test_invalid_env_var_falls_back_to_default(self, monkeypatch):
        monkeypatch.setenv("VALORPROTECTS_RETENTION_DAYS", "not-a-number")
        assert retention_seconds() == pytest.approx(30 * DAY)
