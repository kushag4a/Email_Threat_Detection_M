"""
Tests for backend.app.services.db: schema creation, connection
memoization, and ":memory:" isolation semantics.
"""
from __future__ import annotations

import sqlite3

import pytest

from backend.app.services.db import Database, default_db_path, get_database

EXPECTED_TABLES = {
    "accounts", "messages", "page_cache", "analysis_results",
    "scans", "scan_results",
}


class TestSchemaCreation:
    def test_creates_all_expected_tables(self):
        db = Database(":memory:")
        rows = db.conn.execute(
            "SELECT name FROM sqlite_master WHERE type='table'"
        ).fetchall()
        table_names = {r["name"] for r in rows}
        assert EXPECTED_TABLES.issubset(table_names)

    def test_schema_init_is_idempotent(self, tmp_path):
        """Creating a Database twice against the same file must not
        raise (schema uses CREATE TABLE IF NOT EXISTS)."""
        path = str(tmp_path / "idempotent.sqlite3")
        Database(path)
        db2 = Database(path)  # should not raise
        rows = db2.conn.execute(
            "SELECT name FROM sqlite_master WHERE type='table'"
        ).fetchall()
        assert EXPECTED_TABLES.issubset({r["name"] for r in rows})

    def test_row_factory_returns_row_objects(self):
        db = Database(":memory:")
        db.conn.execute(
            "INSERT INTO accounts (provider, account_id, last_seen_at) VALUES (?, ?, ?)",
            ("google", "a@b.com", 1.0),
        )
        db.conn.commit()
        row = db.conn.execute("SELECT * FROM accounts").fetchone()
        assert row["provider"] == "google"
        assert row["account_id"] == "a@b.com"


class TestDatabaseFileLocation:
    def test_creates_parent_directory(self, tmp_path):
        path = tmp_path / "nested" / "dir" / "db.sqlite3"
        assert not path.parent.exists()
        Database(str(path))
        assert path.parent.exists()
        assert path.exists()

    def test_default_db_path_not_under_venv_backend_or_static(self):
        path = default_db_path()
        parts = {p.lower() for p in path.parts}
        assert ".venv" not in parts
        assert "backend" not in parts
        assert "static" not in parts

    def test_default_db_path_respects_env_override(self, monkeypatch, tmp_path):
        override = tmp_path / "custom" / "wherever.sqlite3"
        monkeypatch.setenv("VALORPROTECTS_DB_PATH", str(override))
        assert default_db_path() == override


class TestGetDatabaseMemoization:
    def test_memory_databases_are_never_shared(self):
        db1 = get_database(":memory:")
        db2 = get_database(":memory:")
        db1.conn.execute(
            "INSERT INTO accounts (provider, account_id, last_seen_at) VALUES ('google','x',1)"
        )
        db1.conn.commit()
        assert db2.conn.execute("SELECT COUNT(*) c FROM accounts").fetchone()["c"] == 0

    def test_real_file_path_is_memoized(self, tmp_path):
        path = str(tmp_path / "shared.sqlite3")
        db1 = get_database(path)
        db2 = get_database(path)
        assert db1 is db2

    def test_different_file_paths_are_distinct(self, tmp_path):
        db1 = get_database(str(tmp_path / "a.sqlite3"))
        db2 = get_database(str(tmp_path / "b.sqlite3"))
        assert db1 is not db2
