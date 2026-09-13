"""
Local cache for mailbox listing (page metadata + per-message summary
rows), backed by SQLite with a small bounded RAM layer on top.

    Gmail / Microsoft
          |
    SQLite (persistent source of truth - `messages` + `page_cache`
            tables in db.py)
          |
    bounded RAM LRU (pure acceleration - cleared on restart, never
                      the only copy of anything; a get_page() miss
                      here always falls through to SQLite before
                      being reported as a miss to the caller)
          |
    FastAPI /api/emails route

This module never talks to Gmail/Graph directly and never imports
MailProvider - it only knows about plain dicts shaped like
MessageSummary.to_dict() (backend/app/providers/base.py), so it can
be exercised in tests without pydantic/googleapiclient/msal being
installed.

Page identity: a Gmail/Graph page token is a *transport cursor*, not
a permanent record identity - the same page_token value is not
guaranteed to mean the same thing forever, and message identity is
always (provider, account_id, message_id) (see MERGE_LOG.md /
project handoff task 3). This cache follows that: `page_cache` rows
key on (provider, account_id, page_size, page_token) purely to
remember "what messages did navigating here produce," and every
message's actual metadata lives independently, keyed by
(provider, account_id, message_id), in `messages`. If a page's
underlying messages ever fell out of the cache (e.g. retention swept
them - see retention.py) while the page_cache row itself survived,
get_page() below treats that as a MISS rather than serving partial/
stale rows, so a caller can never see a page with holes in it.
"""

from __future__ import annotations

import json
import os
import threading
import time
from collections import OrderedDict

from backend.app.services.db import Database, default_db_path, get_database

_PROVIDER_ALIASES: dict[str, str] = {"gmail": "google"}


def _canonical_provider(provider: str) -> str:
    return _PROVIDER_ALIASES.get(provider, provider)


def _page_token_key(page_token: str | None) -> str:
    """SQLite primary keys treat every NULL as distinct from every
    other NULL, so page_token=None ('page 1') would never dedupe
    against itself. Use '' as the on-disk sentinel for "no token"."""
    return page_token or ""


class BoundedCache:
    """
    Small, thread-safe LRU cache with optional TTL.

    RAM only - this is an acceleration layer, never the only copy of
    anything. Safe to clear or drop at any time without losing data;
    callers must always be able to recompute a miss from SQLite (or,
    one layer further up, from the provider).
    """

    def __init__(self, max_size: int = 200, ttl_seconds: float | None = None):
        if max_size < 1:
            raise ValueError("max_size must be >= 1")
        self._max_size = max_size
        self._ttl = ttl_seconds
        self._lock = threading.Lock()
        self._data: OrderedDict[tuple, tuple[float, object]] = OrderedDict()

    def get(self, key):
        with self._lock:
            entry = self._data.get(key)
            if entry is None:
                return None
            stored_at, value = entry
            if self._ttl is not None and (time.time() - stored_at) > self._ttl:
                del self._data[key]
                return None
            self._data.move_to_end(key)
            return value

    def set(self, key, value) -> None:
        with self._lock:
            self._data[key] = (time.time(), value)
            self._data.move_to_end(key)
            while len(self._data) > self._max_size:
                self._data.popitem(last=False)  # evict least-recently-used

    def invalidate(self, key) -> None:
        with self._lock:
            self._data.pop(key, None)

    def clear(self) -> None:
        with self._lock:
            self._data.clear()

    def __len__(self) -> int:
        with self._lock:
            return len(self._data)


class MailboxCache:
    def __init__(self, db_path: str | None = None, *,
                 ram_max_pages: int = 200, ram_max_messages: int = 2000,
                 ram_ttl_seconds: float | None = None,
                 clock=time.time):
        # Same convention as ResultStore: no explicit path -> private
        # ":memory:" database (fresh/isolated, for tests); the module
        # singleton below passes the real persistent file.
        self._db: Database = get_database(db_path if db_path is not None else ":memory:")
        self._page_ram = BoundedCache(max_size=ram_max_pages, ttl_seconds=ram_ttl_seconds)
        self._message_ram = BoundedCache(max_size=ram_max_messages, ttl_seconds=ram_ttl_seconds)

        # BUG FIX (stale mailbox cache - see DIAGNOSTIC_EVIDENCE.md):
        # `clock` is injected (defaults to the real time.time) so tests
        # can control "now" deterministically instead of sleeping for
        # an hour - see get_page_age_seconds/is_page_fresh below, which
        # are the only things that read it.
        self._clock = clock

        # In-flight background-prefetch / foreground-refresh dedupe
        # (Task 9, extended for freshness - see wait_for_in_flight_refresh).
        # Purely an in-process set/dict, not persisted - if the process
        # restarts mid-refresh there's nothing to clean up, the next
        # request just fetches normally.
        self._prefetch_lock = threading.Lock()
        self._prefetching: set[tuple] = set()
        self._refresh_events: dict[tuple, threading.Event] = {}

        # BUG FIX (prefetch hammering Gmail quota - see
        # DIAGNOSTIC_EVIDENCE.md): try_start_prefetch/finish_prefetch
        # above only ever prevented two refreshes for the exact same
        # page running AT THE SAME TIME - the moment one finished
        # (success OR failure), the very next request for that same
        # page would immediately claim and retry it, with no cooldown
        # at all. Against a real Gmail 403 rateLimitExceeded ("Total
        # Query Cost" / "Units per minute per user"), this produced an
        # unbounded retry loop - proven live (see DIAGNOSTIC_EVIDENCE.md's
        # real Windows log excerpt: dozens of consecutive "background
        # prefetch failed" / 403 lines for the same page tokens).
        # `_failed_until` tracks, per key, the timestamp before which
        # that key must NOT be re-claimed; finish_prefetch(failed=True)
        # sets it, try_start_prefetch checks it. This now matters even
        # more with TTL-based freshness (below), since an aged-out page
        # will be retried on every subsequent request unless something
        # backs off after a failure.
        self._failed_until: dict[tuple, float] = {}
        self.default_failure_cooldown_seconds = 60.0

    @property
    def _lock(self):
        return self._db.lock

    @property
    def _conn(self):
        return self._db.conn

    # ------------------------------------------------------------
    # Message metadata (the stable identity: provider/account/id)
    # ------------------------------------------------------------

    def save_messages(self, *, provider: str, account_id: str, messages: list[dict]) -> None:
        """`messages`: dicts shaped like MessageSummary.to_dict()."""
        provider = _canonical_provider(provider)
        now = self._clock()
        with self._lock:
            for m in messages:
                self._conn.execute(
                    """
                    INSERT INTO messages
                        (provider, account_id, message_id, thread_id, sender,
                         recipient, subject, date, snippet, has_attachments, fetched_at)
                    VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
                    ON CONFLICT(provider, account_id, message_id) DO UPDATE SET
                        thread_id = excluded.thread_id,
                        sender = excluded.sender,
                        recipient = excluded.recipient,
                        subject = excluded.subject,
                        date = excluded.date,
                        snippet = excluded.snippet,
                        has_attachments = excluded.has_attachments,
                        fetched_at = excluded.fetched_at
                    """,
                    (provider, account_id, m["message_id"], m.get("thread_id"),
                     m.get("sender"), m.get("recipient"), m.get("subject"),
                     m.get("date"), m.get("snippet"),
                     1 if m.get("has_attachments") else 0, now),
                )
            self._conn.commit()
            self._conn.execute(
                """
                INSERT INTO accounts (provider, account_id, last_seen_at)
                VALUES (?, ?, ?)
                ON CONFLICT(provider, account_id) DO UPDATE SET last_seen_at = excluded.last_seen_at
                """,
                (provider, account_id, now),
            )
            self._conn.commit()
        for m in messages:
            self._message_ram.set((provider, account_id, m["message_id"]), dict(m))

    def get_message(self, *, provider: str, account_id: str, message_id: str) -> dict | None:
        provider = _canonical_provider(provider)
        cached = self._message_ram.get((provider, account_id, message_id))
        if cached is not None:
            return dict(cached)

        with self._lock:
            row = self._conn.execute(
                """
                SELECT * FROM messages
                WHERE provider = ? AND account_id = ? AND message_id = ?
                """,
                (provider, account_id, message_id),
            ).fetchone()
        if row is None:
            return None

        d = {
            "message_id": row["message_id"],
            "thread_id": row["thread_id"],
            "sender": row["sender"],
            "recipient": row["recipient"],
            "subject": row["subject"],
            "date": row["date"],
            "snippet": row["snippet"],
            "has_attachments": bool(row["has_attachments"]),
            "provider": provider,
        }
        self._message_ram.set((provider, account_id, message_id), dict(d))
        return d

    # ------------------------------------------------------------
    # Page cache (navigation-shaped; see module docstring)
    # ------------------------------------------------------------

    def get_page_fetched_at(self, *, provider: str, account_id: str, page_size: int,
                             page_token: str | None) -> float | None:
        """
        The wall-clock time (per this cache's injected clock) at which
        this exact page was actually written by save_page() - i.e. the
        moment the provider fetch that produced it completed. Reads
        straight from SQLite's page_cache.fetched_at column, which
        save_page() always sets to "now" at write time (see below) -
        never application startup, login, or analysis time. Returns
        None if there is no cached row at all.
        """
        provider = _canonical_provider(provider)
        token_key = _page_token_key(page_token)
        with self._lock:
            row = self._conn.execute(
                """
                SELECT fetched_at FROM page_cache
                WHERE provider = ? AND account_id = ? AND page_size = ? AND page_token = ?
                """,
                (provider, account_id, page_size, token_key),
            ).fetchone()
        return None if row is None else row["fetched_at"]

    def get_page_age_seconds(self, *, provider: str, account_id: str, page_size: int,
                              page_token: str | None) -> float | None:
        """Seconds since this exact page was fetched, or None if there
        is no cached row at all (a true miss, not merely stale)."""
        fetched_at = self.get_page_fetched_at(
            provider=provider, account_id=account_id,
            page_size=page_size, page_token=page_token,
        )
        return None if fetched_at is None else max(0.0, self._clock() - fetched_at)

    def is_page_fresh(self, *, provider: str, account_id: str, page_size: int,
                       page_token: str | None, max_age_seconds: float) -> bool:
        """
        True only if a cached row exists AND its age is within
        max_age_seconds. False for both "no cached row" and "cached
        row too old" - callers that need to tell those two apart
        (e.g. to decide whether a stale copy is available as a
        fallback if a refresh fails) should call get_page_age_seconds
        directly instead.
        """
        age = self.get_page_age_seconds(
            provider=provider, account_id=account_id,
            page_size=page_size, page_token=page_token,
        )
        return age is not None and age <= max_age_seconds

    def get_page(self, *, provider: str, account_id: str, page_size: int,
                 page_token: str | None) -> dict | None:
        """
        Returns {"messages": [...], "next_page_token": str|None} on a
        cache HIT, or None on a MISS - callers must treat None as
        "go fetch this page from the provider," same as before this
        cache existed.
        """
        provider = _canonical_provider(provider)
        token_key = _page_token_key(page_token)
        ram_key = (provider, account_id, page_size, token_key)

        cached = self._page_ram.get(ram_key)
        if cached is not None:
            return self._hydrate_page(provider, account_id, cached)

        with self._lock:
            row = self._conn.execute(
                """
                SELECT message_ids, next_page_token FROM page_cache
                WHERE provider = ? AND account_id = ? AND page_size = ? AND page_token = ?
                """,
                (provider, account_id, page_size, token_key),
            ).fetchone()
        if row is None:
            return None

        page = {
            "message_ids": json.loads(row["message_ids"]),
            "next_page_token": row["next_page_token"],
        }
        self._page_ram.set(ram_key, page)
        return self._hydrate_page(provider, account_id, page)

    def _hydrate_page(self, provider: str, account_id: str, page: dict) -> dict | None:
        """Expand a cached page's message_ids into full metadata rows.
        Any missing message row (e.g. swept by retention while the
        page_cache row itself hadn't expired yet) makes this a MISS,
        never a page with holes in it."""
        messages = []
        for mid in page["message_ids"]:
            m = self.get_message(provider=provider, account_id=account_id, message_id=mid)
            if m is None:
                return None
            messages.append(m)
        return {"messages": messages, "next_page_token": page["next_page_token"]}

    def save_page(self, *, provider: str, account_id: str, page_size: int,
                  page_token: str | None, messages: list[dict],
                  next_page_token: str | None) -> None:
        provider = _canonical_provider(provider)
        token_key = _page_token_key(page_token)

        self.save_messages(provider=provider, account_id=account_id, messages=messages)

        message_ids = [m["message_id"] for m in messages]
        now = self._clock()
        with self._lock:
            self._conn.execute(
                """
                INSERT INTO page_cache
                    (provider, account_id, page_size, page_token, message_ids,
                     next_page_token, fetched_at)
                VALUES (?, ?, ?, ?, ?, ?, ?)
                ON CONFLICT(provider, account_id, page_size, page_token) DO UPDATE SET
                    message_ids = excluded.message_ids,
                    next_page_token = excluded.next_page_token,
                    fetched_at = excluded.fetched_at
                """,
                (provider, account_id, page_size, token_key,
                 json.dumps(message_ids), next_page_token, now),
            )
            self._conn.commit()

        ram_key = (provider, account_id, page_size, token_key)
        self._page_ram.set(ram_key, {"message_ids": message_ids, "next_page_token": next_page_token})

    # ------------------------------------------------------------
    # Bounded background-prefetch dedupe (Task 9)
    # ------------------------------------------------------------

    def try_start_prefetch(self, *, provider: str, account_id: str, page_size: int,
                            page_token: str | None, max_age_seconds: float | None = None) -> bool:
        """
        Claim this page for a background prefetch or foreground
        refresh (single-flight winner).

        Returns True if the caller should go fetch it now (and must
        call finish_prefetch when done, success or failure). Returns
        False if:
          - a cached copy exists and is "usable" (see max_age_seconds
            below), OR
          - another refresh for the exact same page is already in
            flight, OR
          - this exact page failed recently and is still within its
            cooldown window (see finish_prefetch's `failed` parameter)
        - in all three cases the caller should not fetch itself.

        `max_age_seconds`: controls what "usable" means for the first
        bullet above.
          - None (the default - unchanged from before the freshness
            feature existed): ANY cached copy at all counts as usable,
            regardless of age. This is what every pre-existing caller
            and test relies on.
          - a number: only a cached copy whose age is within
            max_age_seconds counts as usable - an older ("stale")
            cached copy does NOT block claiming a refresh. This is
            what the foreground /api/emails path and the background
            prefetcher now pass (MAILBOX_CACHE_TTL_SECONDS), so a page
            that ages past the freshness window becomes eligible for
            exactly one refresh instead of being served forever.
        """
        provider = _canonical_provider(provider)
        key = (provider, account_id, page_size, _page_token_key(page_token))

        if max_age_seconds is None:
            have_usable_copy = self.get_page(
                provider=provider, account_id=account_id,
                page_size=page_size, page_token=page_token,
            ) is not None
        else:
            have_usable_copy = self.is_page_fresh(
                provider=provider, account_id=account_id, page_size=page_size,
                page_token=page_token, max_age_seconds=max_age_seconds,
            )
        if have_usable_copy:
            return False

        with self._prefetch_lock:
            if key in self._prefetching:
                return False
            failed_until = self._failed_until.get(key)
            if failed_until is not None:
                if self._clock() < failed_until:
                    return False
                # Cooldown has elapsed - forget it so this branch is
                # O(1) to check on the (common) non-cooling-down path.
                del self._failed_until[key]
            self._prefetching.add(key)
            self._refresh_events[key] = threading.Event()
            return True

    def finish_prefetch(self, *, provider: str, account_id: str, page_size: int,
                         page_token: str | None, failed: bool = False,
                         cooldown_seconds: float | None = None) -> None:
        """
        Release this page's in-flight claim and wake up any callers
        blocked in wait_for_in_flight_refresh for the same key.

        `failed=True` additionally starts a cooldown window (default
        `self.default_failure_cooldown_seconds`, matching Gmail's
        "Units per minute per user" quota window) during which
        try_start_prefetch will refuse to re-claim this exact page,
        even though it is no longer "in flight" - this is what stops
        the retry-storm described above. `failed=False` (the default,
        matching every call site before this fix existed) starts no
        cooldown, so a successful refresh's page remains immediately
        reclaimable if it were ever evicted/invalidated - existing
        callers/tests that don't pass `failed` see no behavior change.
        """
        provider = _canonical_provider(provider)
        key = (provider, account_id, page_size, _page_token_key(page_token))
        with self._prefetch_lock:
            self._prefetching.discard(key)
            event = self._refresh_events.pop(key, None)
            if failed:
                cooldown = (
                    self.default_failure_cooldown_seconds
                    if cooldown_seconds is None else cooldown_seconds
                )
                self._failed_until[key] = self._clock() + cooldown
        if event is not None:
            event.set()

    def wait_for_in_flight_refresh(self, *, provider: str, account_id: str, page_size: int,
                                    page_token: str | None, timeout: float = 30.0) -> bool:
        """
        BUG FIX (stale mailbox cache / keep single-flight - see
        DIAGNOSTIC_EVIDENCE.md): the foreground /api/emails path needs
        a caller that LOSES try_start_prefetch's race to actually wait
        for and then use the winner's result, unlike the background
        prefetch path (whose losers can just do nothing, since the
        request that triggered them already has its own data). Without
        this, N concurrent foreground requests for the same stale/
        missing page would each independently decide "I lost the race,
        I'll fetch it myself anyway" - exactly the quota-storm pattern
        this whole fix exists to prevent.

        Blocks until the in-flight refresh for this exact key
        completes (success or failure), or `timeout` elapses. Returns
        True if there was actually a refresh to wait for; False if
        none was in flight for this key (the caller should then decide
        for itself, e.g. by calling try_start_prefetch()). After this
        returns True, the caller should re-read the cache: it will
        reflect the winner's fresh page on success, or remain
        whatever it was before (possibly still stale, possibly still
        completely absent) on failure - this method never raises the
        winner's exception itself.
        """
        provider = _canonical_provider(provider)
        key = (provider, account_id, page_size, _page_token_key(page_token))
        with self._prefetch_lock:
            event = self._refresh_events.get(key)
        if event is None:
            return False
        event.wait(timeout=timeout)
        return True

    def is_in_failure_cooldown(self, *, provider: str, account_id: str, page_size: int,
                                page_token: str | None) -> bool:
        """Exposed for tests/observability - True if this exact page
        recently failed and try_start_prefetch will currently refuse it."""
        provider = _canonical_provider(provider)
        key = (provider, account_id, page_size, _page_token_key(page_token))
        with self._prefetch_lock:
            failed_until = self._failed_until.get(key)
            return failed_until is not None and self._clock() < failed_until

    def is_prefetching(self, *, provider: str, account_id: str, page_size: int,
                        page_token: str | None) -> bool:
        provider = _canonical_provider(provider)
        key = (provider, account_id, page_size, _page_token_key(page_token))
        with self._prefetch_lock:
            return key in self._prefetching


# BUG FIX (stale mailbox cache - see DIAGNOSTIC_EVIDENCE.md): how long
# a cached mailbox page may be served without revalidating against the
# provider. Configurable via VALORPROTECTS_MAILBOX_CACHE_TTL_SECONDS
# (default 3600 = 1 hour) rather than hard-coded, matching this
# project's existing env-var configuration style (see
# VALORPROTECTS_ORG_DOMAINS in risk_engine.py). Read once at import
# time - same convention as every other env-driven constant in this
# codebase (e.g. ALLOWED_PAGE_SIZES's neighbors in main.py).
MAILBOX_CACHE_TTL_SECONDS = float(
    os.environ.get("VALORPROTECTS_MAILBOX_CACHE_TTL_SECONDS", "3600")
)

# Module singleton pointed at the real, persistent database file -
# shares the same on-disk file (and therefore the same underlying
# Database/lock, via db.get_database's memoization) as STORE in
# store.py.
MAILBOX_CACHE = MailboxCache(db_path=str(default_db_path()))
