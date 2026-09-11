"""
SQLite connection management and schema for ValorProtects' local
persistence layer.

Design
------
- One `sqlite3.Connection` per `Database` instance, shared across
  threads (`check_same_thread=False`) and always accessed through
  that instance's own `threading.RLock`. This project's actual
  concurrency profile (a handful of scan worker threads, a handful
  of /api/emails listing threads) makes one well-locked connection
  simpler than a connection pool and avoids SQLite's "database is
  locked" errors from multiple writers hitting the same file.
- Real (non-":memory:") paths are memoized process-wide by resolved
  path, so every module in the running server shares one Database
  (one on-disk file, one WAL) instead of opening the file repeatedly.
- ":memory:" is NEVER memoized - every caller gets its own private,
  empty database. ResultStore()/MailboxCache() rely on this for the
  same "fresh instance = fresh isolated state" behavior their
  in-memory-dict predecessors had, which existing tests assume.

SQLite is the persistent source of truth here; nothing above this
module needs to know it's SQLite - callers work with plain dicts.
"""

from __future__ import annotations

import os
import sqlite3
import threading
from pathlib import Path

SCHEMA_SQL = """
CREATE TABLE IF NOT EXISTS accounts (
    provider TEXT NOT NULL,
    account_id TEXT NOT NULL,
    last_seen_at REAL NOT NULL,
    PRIMARY KEY (provider, account_id)
);

-- Message metadata cache (inbox listing rows). NEVER holds full
-- RFC822 body/attachments - see mailbox_cache.py.
CREATE TABLE IF NOT EXISTS messages (
    provider TEXT NOT NULL,
    account_id TEXT NOT NULL,
    message_id TEXT NOT NULL,
    thread_id TEXT,
    sender TEXT,
    recipient TEXT,
    subject TEXT,
    date TEXT,
    snippet TEXT,
    has_attachments INTEGER NOT NULL DEFAULT 0,
    fetched_at REAL NOT NULL,
    PRIMARY KEY (provider, account_id, message_id)
);
CREATE INDEX IF NOT EXISTS idx_messages_fetched_at ON messages(fetched_at);

-- One row per (account, page_size, page_token) the user has actually
-- navigated to. page_token is the *input* cursor used to fetch this
-- page ('' sentinel = first page), NOT a permanent identity for the
-- messages on it - message identity is (provider, account_id,
-- message_id) in the `messages` table above.
CREATE TABLE IF NOT EXISTS page_cache (
    provider TEXT NOT NULL,
    account_id TEXT NOT NULL,
    page_size INTEGER NOT NULL,
    page_token TEXT NOT NULL,
    message_ids TEXT NOT NULL,      -- JSON array, in page order
    next_page_token TEXT,
    fetched_at REAL NOT NULL,
    PRIMARY KEY (provider, account_id, page_size, page_token)
);
CREATE INDEX IF NOT EXISTS idx_page_cache_fetched_at ON page_cache(fetched_at);

-- Per-(session, mailbox, message) analysis result. session_id stays
-- part of the identity to preserve this project's existing,
-- already-tested session-isolation guarantee (see test_store.py) -
-- SQLite makes the *data* durable across a restart, it does not by
-- itself change who is allowed to see it.
CREATE TABLE IF NOT EXISTS analysis_results (
    session_id TEXT NOT NULL,
    provider TEXT NOT NULL,
    account_id TEXT NOT NULL,
    message_id TEXT NOT NULL,
    result_json TEXT NOT NULL,
    risk_level TEXT,
    analyzed_at TEXT,
    updated_at REAL NOT NULL,
    PRIMARY KEY (session_id, provider, account_id, message_id)
);
CREATE INDEX IF NOT EXISTS idx_analysis_session ON analysis_results(session_id);
CREATE INDEX IF NOT EXISTS idx_analysis_risk ON analysis_results(session_id, risk_level);
CREATE INDEX IF NOT EXISTS idx_analysis_updated ON analysis_results(updated_at);

CREATE TABLE IF NOT EXISTS scans (
    scan_id TEXT PRIMARY KEY,
    session_id TEXT NOT NULL,
    requested INTEGER NOT NULL,
    analyzed INTEGER NOT NULL DEFAULT 0,
    failed INTEGER NOT NULL DEFAULT 0,
    status TEXT NOT NULL,
    started_at REAL NOT NULL,
    updated_at REAL NOT NULL
);
CREATE INDEX IF NOT EXISTS idx_scans_session ON scans(session_id);
CREATE INDEX IF NOT EXISTS idx_scans_started ON scans(started_at);

CREATE TABLE IF NOT EXISTS scan_results (
    scan_id TEXT NOT NULL,
    seq INTEGER NOT NULL,
    result_json TEXT NOT NULL,
    PRIMARY KEY (scan_id, seq)
);
"""


def default_db_path() -> Path:
    """
    Local data directory for the runtime SQLite database.

    Resolution order:
      1. VALORPROTECTS_DB_PATH env var, if set (full file path) -
         lets ops point this at a different disk/location.
      2. <project root>/data/valorprotects.sqlite3

    Project root is derived from this file's own location (backend/
    app/services/db.py -> services -> app -> backend -> root), NOT
    from the process's current working directory, so it doesn't
    matter what directory uvicorn was launched from. Deliberately
    outside .venv, backend package source, and static (see
    MERGE_LOG.md / project handoff task 14).
    """
    env_path = os.environ.get("VALORPROTECTS_DB_PATH")
    if env_path:
        return Path(env_path)

    project_root = Path(__file__).resolve().parents[3]
    return project_root / "data" / "valorprotects.sqlite3"


class Database:
    """One SQLite connection, one lock, one schema."""

    def __init__(self, path: str | None = None):
        self.path = path if path is not None else str(default_db_path())
        self.lock = threading.RLock()

        if self.path != ":memory:":
            Path(self.path).parent.mkdir(parents=True, exist_ok=True)

        self._conn = sqlite3.connect(self.path, check_same_thread=False)
        self._conn.row_factory = sqlite3.Row

        with self.lock:
            if self.path != ":memory:":
                # WAL isn't meaningful for an anonymous :memory: DB and
                # some sqlite builds warn/no-op on it - skip for those.
                self._conn.execute("PRAGMA journal_mode=WAL")
            self._conn.execute("PRAGMA foreign_keys=ON")
            self._conn.executescript(SCHEMA_SQL)
            self._conn.commit()

    @property
    def conn(self) -> sqlite3.Connection:
        return self._conn

    def close(self) -> None:
        with self.lock:
            self._conn.close()


_DB_CACHE: dict[str, Database] = {}
_CACHE_LOCK = threading.Lock()


def get_database(path: str | None = None) -> Database:
    """
    Return a Database for `path`.

    Real file paths are memoized process-wide so every caller shares
    one connection per file. ":memory:" is never memoized - always
    returns a brand-new, empty database (see module docstring).
    """
    resolved = path if path is not None else str(default_db_path())

    if resolved == ":memory:":
        return Database(":memory:")

    with _CACHE_LOCK:
        db = _DB_CACHE.get(resolved)
        if db is None:
            db = Database(resolved)
            _DB_CACHE[resolved] = db
        return db
