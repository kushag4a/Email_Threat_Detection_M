"""
Tests for backend.app.services.mailbox_cache: page/message metadata
caching, account/provider isolation, bounded RAM cache eviction, and
prefetch dedupe.

No real Gmail/Graph credentials or network access needed - this
module never imports MailProvider and works entirely on plain dicts
shaped like MessageSummary.to_dict().
"""
from __future__ import annotations

import threading
import time

import pytest

from backend.app.services.mailbox_cache import BoundedCache, MailboxCache


def _msg(message_id: str, subject: str = "Subject") -> dict:
    return {
        "message_id": message_id,
        "thread_id": f"thread-{message_id}",
        "sender": "sender@example.com",
        "recipient": "user@example.com",
        "subject": subject,
        "date": "Mon, 01 Jan 2026 00:00:00 +0000",
        "snippet": "snippet text",
        "has_attachments": False,
        "provider": "google",
    }


@pytest.fixture
def cache() -> MailboxCache:
    return MailboxCache()


class TestPageCacheHitMiss:
    def test_miss_when_never_fetched(self, cache):
        assert cache.get_page(
            provider="google", account_id="a@b.com", page_size=5, page_token=None
        ) is None

    def test_hit_after_save(self, cache):
        cache.save_page(
            provider="google", account_id="a@b.com", page_size=5, page_token=None,
            messages=[_msg("m1"), _msg("m2")], next_page_token="TOK2",
        )
        page = cache.get_page(provider="google", account_id="a@b.com", page_size=5, page_token=None)
        assert page is not None
        assert [m["message_id"] for m in page["messages"]] == ["m1", "m2"]
        assert page["next_page_token"] == "TOK2"


class TestPageIndependence:
    def test_page_1_and_page_2_are_independent(self, cache):
        cache.save_page(
            provider="google", account_id="a@b.com", page_size=5, page_token=None,
            messages=[_msg("p1-a")], next_page_token="TOK2",
        )
        cache.save_page(
            provider="google", account_id="a@b.com", page_size=5, page_token="TOK2",
            messages=[_msg("p2-a")], next_page_token=None,
        )
        page1 = cache.get_page(provider="google", account_id="a@b.com", page_size=5, page_token=None)
        page2 = cache.get_page(provider="google", account_id="a@b.com", page_size=5, page_token="TOK2")
        assert [m["message_id"] for m in page1["messages"]] == ["p1-a"]
        assert [m["message_id"] for m in page2["messages"]] == ["p2-a"]

    def test_returning_to_page_1_after_page_2_is_still_a_hit(self, cache):
        cache.save_page(
            provider="google", account_id="a@b.com", page_size=5, page_token=None,
            messages=[_msg("p1-a")], next_page_token="TOK2",
        )
        cache.save_page(
            provider="google", account_id="a@b.com", page_size=5, page_token="TOK2",
            messages=[_msg("p2-a")], next_page_token=None,
        )
        page1_again = cache.get_page(provider="google", account_id="a@b.com", page_size=5, page_token=None)
        assert page1_again is not None
        assert [m["message_id"] for m in page1_again["messages"]] == ["p1-a"]


class TestAccountAndProviderIsolation:
    def test_different_account_is_a_miss(self, cache):
        cache.save_page(
            provider="google", account_id="alice@b.com", page_size=5, page_token=None,
            messages=[_msg("m1")], next_page_token=None,
        )
        assert cache.get_page(
            provider="google", account_id="bob@b.com", page_size=5, page_token=None
        ) is None

    def test_different_provider_is_a_miss(self, cache):
        cache.save_page(
            provider="google", account_id="a@b.com", page_size=5, page_token=None,
            messages=[_msg("m1")], next_page_token=None,
        )
        assert cache.get_page(
            provider="microsoft", account_id="a@b.com", page_size=5, page_token=None
        ) is None

    def test_gmail_alias_resolves_to_google(self, cache):
        cache.save_page(
            provider="google", account_id="a@b.com", page_size=5, page_token=None,
            messages=[_msg("m1")], next_page_token=None,
        )
        assert cache.get_page(
            provider="gmail", account_id="a@b.com", page_size=5, page_token=None
        ) is not None


class TestPersistenceAcrossRecreation:
    def test_page_survives_cache_object_recreation(self, tmp_path):
        db_path = str(tmp_path / "mailbox.sqlite3")
        cache1 = MailboxCache(db_path=db_path)
        cache1.save_page(
            provider="google", account_id="a@b.com", page_size=10, page_token=None,
            messages=[_msg("m1")], next_page_token=None,
        )
        cache2 = MailboxCache(db_path=db_path)  # simulates a process restart
        page = cache2.get_page(provider="google", account_id="a@b.com", page_size=10, page_token=None)
        assert page is not None
        assert page["messages"][0]["message_id"] == "m1"

    def test_memory_instances_are_never_shared(self):
        c1 = MailboxCache()
        c2 = MailboxCache()
        c1.save_page(
            provider="google", account_id="a@b.com", page_size=5, page_token=None,
            messages=[_msg("m1")], next_page_token=None,
        )
        assert c2.get_page(provider="google", account_id="a@b.com", page_size=5, page_token=None) is None


class TestMessageLookup:
    def test_get_message_after_save(self, cache):
        cache.save_messages(provider="google", account_id="a@b.com", messages=[_msg("m1", "Hello")])
        m = cache.get_message(provider="google", account_id="a@b.com", message_id="m1")
        assert m is not None
        assert m["subject"] == "Hello"

    def test_get_message_miss(self, cache):
        assert cache.get_message(provider="google", account_id="a@b.com", message_id="nope") is None


class TestBoundedRamCache:
    def test_eviction_at_max_size(self):
        bc = BoundedCache(max_size=3)
        for i in range(5):
            bc.set(f"k{i}", i)
        assert len(bc) == 3
        assert bc.get("k0") is None
        assert bc.get("k1") is None
        assert bc.get("k4") == 4

    def test_thread_safe_under_concurrent_writes(self):
        bc = BoundedCache(max_size=50)
        def writer(n):
            for i in range(50):
                bc.set(f"t{n}-{i}", i)
        threads = [threading.Thread(target=writer, args=(n,)) for n in range(10)]
        for t in threads:
            t.start()
        for t in threads:
            t.join()
        assert len(bc) == 50  # bounded, never exceeds max_size

    def test_ttl_expiry(self):
        bc = BoundedCache(max_size=10, ttl_seconds=0.05)
        bc.set("a", 1)
        assert bc.get("a") == 1
        time.sleep(0.1)
        assert bc.get("a") is None

    def test_invalidate_and_clear(self):
        bc = BoundedCache(max_size=10)
        bc.set("a", 1)
        bc.invalidate("a")
        assert bc.get("a") is None
        bc.set("b", 2)
        bc.clear()
        assert len(bc) == 0


class TestBackgroundPrefetchDedupe:
    def test_claim_then_release_then_reclaim(self, cache):
        assert cache.try_start_prefetch(
            provider="google", account_id="a@b.com", page_size=5, page_token="NEXT"
        ) is True
        assert cache.try_start_prefetch(
            provider="google", account_id="a@b.com", page_size=5, page_token="NEXT"
        ) is False
        cache.finish_prefetch(provider="google", account_id="a@b.com", page_size=5, page_token="NEXT")
        assert cache.try_start_prefetch(
            provider="google", account_id="a@b.com", page_size=5, page_token="NEXT"
        ) is True

    def test_already_cached_page_is_never_claimed(self, cache):
        cache.save_page(
            provider="google", account_id="a@b.com", page_size=5, page_token="NEXT",
            messages=[_msg("m1")], next_page_token=None,
        )
        assert cache.try_start_prefetch(
            provider="google", account_id="a@b.com", page_size=5, page_token="NEXT"
        ) is False

    def test_concurrent_prefetch_claims_only_one_winner(self, cache):
        results = []
        lock = threading.Lock()

        def racer():
            ok = cache.try_start_prefetch(
                provider="google", account_id="a@b.com", page_size=5, page_token="RACE"
            )
            with lock:
                results.append(ok)

        threads = [threading.Thread(target=racer) for _ in range(20)]
        for t in threads:
            t.start()
        for t in threads:
            t.join()

        assert sum(results) == 1

    def test_prefetch_dedupe_is_per_page_not_global(self, cache):
        assert cache.try_start_prefetch(
            provider="google", account_id="a@b.com", page_size=5, page_token="PAGE_A"
        ) is True
        # A different page must not be blocked by an in-flight prefetch
        # of a different page.
        assert cache.try_start_prefetch(
            provider="google", account_id="a@b.com", page_size=5, page_token="PAGE_B"
        ) is True

    def test_failed_prefetch_never_caches_the_page(self, cache):
        """A prefetch that fails (mimicking a mocked provider raising
        a quota/network error) must leave the page as a cache MISS."""
        cache.try_start_prefetch(
            provider="google", account_id="a@b.com", page_size=5, page_token="FAILED_PAGE"
        )
        cache.finish_prefetch(
            provider="google", account_id="a@b.com", page_size=5, page_token="FAILED_PAGE",
            failed=True, cooldown_seconds=60,
        )
        assert cache.get_page(
            provider="google", account_id="a@b.com", page_size=5, page_token="FAILED_PAGE"
        ) is None

    def test_concurrent_duplicate_requests_result_in_single_provider_fetch(self, cache):
        """
        Integration-style regression test for the storm bug: 50
        concurrent callers all "requesting" the exact same
        (provider, account_id, page_size, page_token) must trigger
        exactly ONE underlying provider fetch - mocked here as
        `fake_provider_fetch`, standing in for
        mail_provider.list_messages()/_fetch_page_summaries() in
        main.py's real _prefetch_page/_get_fresh_page. Every caller
        that loses the race must do nothing and let the winner
        populate the cache; every caller (winner or not) must be able
        to read back the correct, deduplicated result afterward.
        """
        fetch_calls = []
        fetch_lock = threading.Lock()

        def fake_provider_fetch():
            with fetch_lock:
                fetch_calls.append(1)
            return [_msg("m1"), _msg("m2")]

        def worker():
            if cache.try_start_prefetch(
                provider="google", account_id="a@b.com", page_size=100, page_token="STORM_TOK"
            ):
                messages = fake_provider_fetch()
                cache.save_page(
                    provider="google", account_id="a@b.com", page_size=100,
                    page_token="STORM_TOK", messages=messages, next_page_token=None,
                )
                cache.finish_prefetch(
                    provider="google", account_id="a@b.com", page_size=100, page_token="STORM_TOK"
                )

        threads = [threading.Thread(target=worker) for _ in range(50)]
        for t in threads:
            t.start()
        for t in threads:
            t.join()

        assert len(fetch_calls) == 1, (
            f"expected exactly 1 underlying provider fetch across 50 "
            f"concurrent duplicate requests, got {len(fetch_calls)}"
        )
        page = cache.get_page(
            provider="google", account_id="a@b.com", page_size=100, page_token="STORM_TOK"
        )
        assert page is not None
        assert [m["message_id"] for m in page["messages"]] == ["m1", "m2"]

    def test_different_keys_are_independent_under_concurrency(self, cache):
        """Concurrent requests for DIFFERENT keys (different
        page_token here) must each get their own independent fetch -
        dedup must never bleed across keys."""
        fetch_calls_by_key: dict[str, int] = {"A": 0, "B": 0}
        lock = threading.Lock()

        def fake_fetch(key):
            with lock:
                fetch_calls_by_key[key] += 1
            return [_msg(f"m-{key}")]

        def worker(key):
            if cache.try_start_prefetch(
                provider="google", account_id="a@b.com", page_size=5, page_token=key
            ):
                messages = fake_fetch(key)
                cache.save_page(
                    provider="google", account_id="a@b.com", page_size=5,
                    page_token=key, messages=messages, next_page_token=None,
                )
                cache.finish_prefetch(
                    provider="google", account_id="a@b.com", page_size=5, page_token=key
                )

        threads = [threading.Thread(target=worker, args=(k,)) for k in ("A", "B") for _ in range(25)]
        for t in threads:
            t.start()
        for t in threads:
            t.join()

        assert fetch_calls_by_key == {"A": 1, "B": 1}


class TestPrefetchFailureCooldown:
    """
    Regression tests for the prefetch-hammering-Gmail-quota bug (see
    DIAGNOSTIC_EVIDENCE.md): finish_prefetch(failed=True) must start a
    cooldown so a page that just failed (e.g. Gmail 403
    rateLimitExceeded) cannot be immediately re-claimed by the very
    next request, the way it could before this fix.
    """

    def test_successful_finish_starts_no_cooldown(self, cache):
        """Backward compatibility: finish_prefetch's default
        (failed=False) must behave exactly as before this fix -
        immediately reclaimable."""
        cache.try_start_prefetch(
            provider="google", account_id="a@b.com", page_size=5, page_token="OK"
        )
        cache.finish_prefetch(provider="google", account_id="a@b.com", page_size=5, page_token="OK")
        assert cache.try_start_prefetch(
            provider="google", account_id="a@b.com", page_size=5, page_token="OK"
        ) is True

    def test_failed_finish_blocks_immediate_reclaim(self, cache):
        cache.try_start_prefetch(
            provider="google", account_id="a@b.com", page_size=5, page_token="QUOTA"
        )
        cache.finish_prefetch(
            provider="google", account_id="a@b.com", page_size=5, page_token="QUOTA",
            failed=True, cooldown_seconds=60,
        )
        assert cache.try_start_prefetch(
            provider="google", account_id="a@b.com", page_size=5, page_token="QUOTA"
        ) is False

    def test_is_in_failure_cooldown_reports_state(self, cache):
        cache.try_start_prefetch(
            provider="google", account_id="a@b.com", page_size=5, page_token="QUOTA"
        )
        assert cache.is_in_failure_cooldown(
            provider="google", account_id="a@b.com", page_size=5, page_token="QUOTA"
        ) is False
        cache.finish_prefetch(
            provider="google", account_id="a@b.com", page_size=5, page_token="QUOTA",
            failed=True, cooldown_seconds=60,
        )
        assert cache.is_in_failure_cooldown(
            provider="google", account_id="a@b.com", page_size=5, page_token="QUOTA"
        ) is True

    def test_cooldown_expires_after_its_window(self, cache):
        cache.try_start_prefetch(
            provider="google", account_id="a@b.com", page_size=5, page_token="QUOTA"
        )
        cache.finish_prefetch(
            provider="google", account_id="a@b.com", page_size=5, page_token="QUOTA",
            failed=True, cooldown_seconds=0.05,
        )
        assert cache.try_start_prefetch(
            provider="google", account_id="a@b.com", page_size=5, page_token="QUOTA"
        ) is False
        time.sleep(0.1)
        assert cache.try_start_prefetch(
            provider="google", account_id="a@b.com", page_size=5, page_token="QUOTA"
        ) is True

    def test_repeated_navigation_after_failure_only_attempts_once(self, cache):
        """Direct regression test for the live bug: many consecutive
        claim/fail cycles for the SAME page must only ever actually
        attempt the prefetch once per cooldown window, not once per
        call."""
        attempts = 0
        for _ in range(50):
            if cache.try_start_prefetch(
                provider="google", account_id="a@b.com", page_size=100, page_token="QUOTA_TOK"
            ):
                attempts += 1
                cache.finish_prefetch(
                    provider="google", account_id="a@b.com", page_size=100,
                    page_token="QUOTA_TOK", failed=True, cooldown_seconds=60,
                )
        assert attempts == 1

    def test_cooldown_is_per_page_not_global(self, cache):
        cache.try_start_prefetch(
            provider="google", account_id="a@b.com", page_size=5, page_token="BAD"
        )
        cache.finish_prefetch(
            provider="google", account_id="a@b.com", page_size=5, page_token="BAD",
            failed=True, cooldown_seconds=60,
        )
        assert cache.try_start_prefetch(
            provider="google", account_id="a@b.com", page_size=5, page_token="GOOD"
        ) is True


class TestPageSizeIsolation:
    """
    Regression tests for: "changing 5 -> 10 -> 100 cannot reuse or
    recursively invalidate unrelated cache entries." page_size is part
    of every cache key (see db.py's page_cache PRIMARY KEY).
    """

    def test_same_token_different_page_size_do_not_collide(self, cache):
        cache.save_page(
            provider="google", account_id="a@b.com", page_size=5, page_token=None,
            messages=[_msg("m5")], next_page_token=None,
        )
        assert cache.get_page(
            provider="google", account_id="a@b.com", page_size=100, page_token=None
        ) is None

    def test_saving_one_page_size_does_not_alter_another(self, cache):
        cache.save_page(
            provider="google", account_id="a@b.com", page_size=5, page_token=None,
            messages=[_msg("m5")], next_page_token=None,
        )
        cache.save_page(
            provider="google", account_id="a@b.com", page_size=100, page_token=None,
            messages=[_msg("m100")], next_page_token=None,
        )
        page5 = cache.get_page(provider="google", account_id="a@b.com", page_size=5, page_token=None)
        page100 = cache.get_page(provider="google", account_id="a@b.com", page_size=100, page_token=None)
        assert page5["messages"][0]["message_id"] == "m5"
        assert page100["messages"][0]["message_id"] == "m100"

    def test_prefetch_dedupe_is_per_page_size_too(self, cache):
        assert cache.try_start_prefetch(
            provider="google", account_id="a@b.com", page_size=5, page_token="TOK"
        ) is True
        assert cache.try_start_prefetch(
            provider="google", account_id="a@b.com", page_size=100, page_token="TOK"
        ) is True


class _FakeClock:
    """Deterministic, manually-advanced clock for freshness/TTL tests -
    no real sleeping needed to simulate an hour passing."""

    def __init__(self, start: float = 1_000_000.0):
        self.t = start

    def __call__(self) -> float:
        return self.t

    def advance(self, seconds: float) -> None:
        self.t += seconds


@pytest.fixture
def clock() -> _FakeClock:
    return _FakeClock()


@pytest.fixture
def fresh_cache(clock) -> MailboxCache:
    """A cache wired to the deterministic fake clock above, for
    freshness/TTL tests. Separate fixture name from `cache` (which
    uses the real wall clock) so both fixtures can coexist without
    ambiguity about which clock a given test is using."""
    return MailboxCache(clock=clock)


class TestMailboxCacheFreshness:
    """
    Regression tests for the stale-mailbox-cache bug: a live user
    compared Gmail (showing 12/11/10 Sept messages) against
    ValorProtects (still showing 10/9 Sept messages) - the mailbox
    page cache was serving arbitrarily old data with no revalidation
    at all. VALORPROTECTS_MAILBOX_CACHE_TTL_SECONDS (default 3600 = 1
    hour) now bounds how long a cached page may be served before the
    next request must revalidate it against the provider - via
    exactly one single-flight refresh, not one independent fetch per
    concurrent caller (see TestFreshnessSingleFlight below).

    All timing here is via the injected fake clock (`fresh_cache`
    fixture) - no real sleeping.
    """
    TTL = 3600.0

    def test_freshly_saved_page_is_fresh(self, fresh_cache):
        fresh_cache.save_page(
            provider="google", account_id="a@b.com", page_size=5, page_token=None,
            messages=[_msg("m1")], next_page_token=None,
        )
        assert fresh_cache.is_page_fresh(
            provider="google", account_id="a@b.com", page_size=5, page_token=None,
            max_age_seconds=self.TTL,
        ) is True

    def test_page_older_than_ttl_is_stale(self, fresh_cache, clock):
        fresh_cache.save_page(
            provider="google", account_id="a@b.com", page_size=5, page_token=None,
            messages=[_msg("m1")], next_page_token=None,
        )
        clock.advance(self.TTL + 1)
        assert fresh_cache.is_page_fresh(
            provider="google", account_id="a@b.com", page_size=5, page_token=None,
            max_age_seconds=self.TTL,
        ) is False

    def test_stale_page_data_is_still_retrievable_via_get_page(self, fresh_cache, clock):
        """get_page()'s existing contract is unchanged by the
        freshness feature - it still returns whatever is cached,
        stale or not. Freshness is a separate, explicit check
        (is_page_fresh/get_page_age_seconds), so a caller that wants
        the stale copy as a fallback (see main.py's _get_fresh_page)
        can still get it."""
        fresh_cache.save_page(
            provider="google", account_id="a@b.com", page_size=5, page_token=None,
            messages=[_msg("m1")], next_page_token=None,
        )
        clock.advance(self.TTL + 1)
        assert fresh_cache.get_page(
            provider="google", account_id="a@b.com", page_size=5, page_token=None
        ) is not None

    def test_missing_page_has_no_age_and_is_not_fresh(self, fresh_cache):
        assert fresh_cache.get_page_age_seconds(
            provider="google", account_id="a@b.com", page_size=5, page_token="NEVER_SAVED"
        ) is None
        assert fresh_cache.is_page_fresh(
            provider="google", account_id="a@b.com", page_size=5, page_token="NEVER_SAVED",
            max_age_seconds=self.TTL,
        ) is False

    def test_fresh_page_blocks_try_start_prefetch_with_max_age(self, fresh_cache):
        """Scenario 1 (fresh cache hit): a fresh page must NOT be
        claimable for refresh when max_age_seconds is passed - the
        provider must not be called."""
        fresh_cache.save_page(
            provider="google", account_id="a@b.com", page_size=5, page_token=None,
            messages=[_msg("m1")], next_page_token=None,
        )
        assert fresh_cache.try_start_prefetch(
            provider="google", account_id="a@b.com", page_size=5, page_token=None,
            max_age_seconds=self.TTL,
        ) is False

    def test_stale_page_is_claimable_for_refresh(self, fresh_cache, clock):
        """Scenario 2 (stale cache -> provider IS called): once a page
        ages past the TTL, try_start_prefetch(max_age_seconds=...)
        must allow exactly one caller to claim a refresh - this is the
        core fix, since the old try_start_prefetch (no max_age_seconds)
        would refuse forever just because SOME cached copy existed."""
        fresh_cache.save_page(
            provider="google", account_id="a@b.com", page_size=5, page_token=None,
            messages=[_msg("m1")], next_page_token=None,
        )
        clock.advance(self.TTL + 1)
        assert fresh_cache.try_start_prefetch(
            provider="google", account_id="a@b.com", page_size=5, page_token=None,
            max_age_seconds=self.TTL,
        ) is True

    def test_try_start_prefetch_without_max_age_is_unaffected_by_staleness(self, fresh_cache, clock):
        """Backward compatibility: existing callers that don't pass
        max_age_seconds (e.g. any pre-existing test/call site) must
        see EXACTLY the old behavior - "any cached copy blocks a
        claim," regardless of age."""
        fresh_cache.save_page(
            provider="google", account_id="a@b.com", page_size=5, page_token=None,
            messages=[_msg("m1")], next_page_token=None,
        )
        clock.advance(self.TTL * 10)  # very stale
        assert fresh_cache.try_start_prefetch(
            provider="google", account_id="a@b.com", page_size=5, page_token=None,
        ) is False

    def test_successful_stale_refresh_updates_timestamp_and_content(self, fresh_cache, clock):
        """Scenario 3 (successful stale refresh): saving a new page
        (simulating a successful provider refresh) must both replace
        the content and reset the freshness clock."""
        fresh_cache.save_page(
            provider="google", account_id="a@b.com", page_size=5, page_token=None,
            messages=[_msg("old-message")], next_page_token=None,
        )
        clock.advance(self.TTL + 1)
        assert fresh_cache.is_page_fresh(
            provider="google", account_id="a@b.com", page_size=5, page_token=None,
            max_age_seconds=self.TTL,
        ) is False

        fresh_cache.save_page(  # simulates the single-flight winner's successful refresh
            provider="google", account_id="a@b.com", page_size=5, page_token=None,
            messages=[_msg("new-message")], next_page_token=None,
        )
        assert fresh_cache.is_page_fresh(
            provider="google", account_id="a@b.com", page_size=5, page_token=None,
            max_age_seconds=self.TTL,
        ) is True
        page = fresh_cache.get_page(
            provider="google", account_id="a@b.com", page_size=5, page_token=None
        )
        assert page["messages"][0]["message_id"] == "new-message"

    def test_failed_stale_refresh_does_not_update_timestamp_or_content(self, fresh_cache, clock):
        """
        Scenario 4 (failed stale refresh): the failure path
        (finish_prefetch(failed=True), mirroring main.py's
        _get_fresh_page on a provider exception) must NEVER call
        save_page - so neither the freshness timestamp nor the
        content changes. The stale copy remains available (as a
        fallback - see main.py) but is still correctly reported as
        stale, not falsely "refreshed."
        """
        fresh_cache.save_page(
            provider="google", account_id="a@b.com", page_size=5, page_token=None,
            messages=[_msg("old-message")], next_page_token=None,
        )
        clock.advance(self.TTL + 1)

        claimed = fresh_cache.try_start_prefetch(
            provider="google", account_id="a@b.com", page_size=5, page_token=None,
            max_age_seconds=self.TTL,
        )
        assert claimed is True
        # Simulate a failed provider fetch - no save_page call.
        fresh_cache.finish_prefetch(
            provider="google", account_id="a@b.com", page_size=5, page_token=None,
            failed=True, cooldown_seconds=60,
        )

        # Timestamp must NOT have been bumped - still stale.
        assert fresh_cache.is_page_fresh(
            provider="google", account_id="a@b.com", page_size=5, page_token=None,
            max_age_seconds=self.TTL,
        ) is False
        # Content must be unchanged (the old stale copy, not lost).
        page = fresh_cache.get_page(
            provider="google", account_id="a@b.com", page_size=5, page_token=None
        )
        assert page["messages"][0]["message_id"] == "old-message"

    def test_first_page_none_token_becomes_stale_and_is_claimable(self, fresh_cache, clock):
        """Scenario 9: page_token=None (the first inbox page) is not
        special-cased away from staleness - it must become claimable
        for refresh exactly like any other page once its TTL elapses."""
        fresh_cache.save_page(
            provider="google", account_id="a@b.com", page_size=5, page_token=None,
            messages=[_msg("m1")], next_page_token="NEXT",
        )
        assert fresh_cache.try_start_prefetch(
            provider="google", account_id="a@b.com", page_size=5, page_token=None,
            max_age_seconds=self.TTL,
        ) is False  # still fresh
        clock.advance(self.TTL + 1)
        assert fresh_cache.try_start_prefetch(
            provider="google", account_id="a@b.com", page_size=5, page_token=None,
            max_age_seconds=self.TTL,
        ) is True  # now stale -> claimable

    def test_fresh_page_token_x_does_not_force_refresh(self, fresh_cache, clock):
        """Scenario 10, restated generically: a fresh page at ANY
        token (not just None) must not be claimable for refresh."""
        fresh_cache.save_page(
            provider="google", account_id="a@b.com", page_size=5, page_token="X",
            messages=[_msg("m1")], next_page_token=None,
        )
        clock.advance(self.TTL / 2)  # well within the TTL
        assert fresh_cache.try_start_prefetch(
            provider="google", account_id="a@b.com", page_size=5, page_token="X",
            max_age_seconds=self.TTL,
        ) is False

    def test_different_page_sizes_go_stale_independently(self, fresh_cache, clock):
        """Scenario 7: page_size=5 and page_size=10 must not collide
        or share a freshness clock."""
        fresh_cache.save_page(
            provider="google", account_id="a@b.com", page_size=5, page_token=None,
            messages=[_msg("m5")], next_page_token=None,
        )
        clock.advance(self.TTL / 2)
        fresh_cache.save_page(
            provider="google", account_id="a@b.com", page_size=10, page_token=None,
            messages=[_msg("m10")], next_page_token=None,
        )
        clock.advance(self.TTL / 2 + 1)  # page_size=5 now stale (age=TTL+1); page_size=10 still fresh (age=TTL/2+1)
        assert fresh_cache.is_page_fresh(
            provider="google", account_id="a@b.com", page_size=5, page_token=None,
            max_age_seconds=self.TTL,
        ) is False
        assert fresh_cache.is_page_fresh(
            provider="google", account_id="a@b.com", page_size=10, page_token=None,
            max_age_seconds=self.TTL,
        ) is True

    def test_different_accounts_go_stale_independently(self, fresh_cache, clock):
        """Scenario 8: no cross-account contamination of freshness."""
        fresh_cache.save_page(
            provider="google", account_id="account-a@example.com", page_size=5, page_token=None,
            messages=[_msg("m1")], next_page_token=None,
        )
        clock.advance(self.TTL / 2)
        fresh_cache.save_page(
            provider="google", account_id="account-b@example.com", page_size=5, page_token=None,
            messages=[_msg("m2")], next_page_token=None,
        )
        clock.advance(self.TTL / 2 + 1)
        assert fresh_cache.is_page_fresh(
            provider="google", account_id="account-a@example.com", page_size=5, page_token=None,
            max_age_seconds=self.TTL,
        ) is False
        assert fresh_cache.is_page_fresh(
            provider="google", account_id="account-b@example.com", page_size=5, page_token=None,
            max_age_seconds=self.TTL,
        ) is True

    def test_different_providers_go_stale_independently(self, fresh_cache, clock):
        """Scenario 8 (provider variant): no cross-provider
        contamination of freshness."""
        fresh_cache.save_page(
            provider="google", account_id="a@b.com", page_size=5, page_token=None,
            messages=[_msg("m1")], next_page_token=None,
        )
        clock.advance(self.TTL / 2)
        fresh_cache.save_page(
            provider="microsoft", account_id="a@b.com", page_size=5, page_token=None,
            messages=[_msg("m2")], next_page_token=None,
        )
        clock.advance(self.TTL / 2 + 1)
        assert fresh_cache.is_page_fresh(
            provider="google", account_id="a@b.com", page_size=5, page_token=None,
            max_age_seconds=self.TTL,
        ) is False
        assert fresh_cache.is_page_fresh(
            provider="microsoft", account_id="a@b.com", page_size=5, page_token=None,
            max_age_seconds=self.TTL,
        ) is True

    def test_configurable_ttl_constant_reads_env_default(self):
        """VALORPROTECTS_MAILBOX_CACHE_TTL_SECONDS must default to
        3600 (1 hour) when unset."""
        import importlib
        import backend.app.services.mailbox_cache as mc
        importlib.reload(mc)
        try:
            assert mc.MAILBOX_CACHE_TTL_SECONDS == 3600.0
        finally:
            import os
            os.environ.pop("VALORPROTECTS_MAILBOX_CACHE_TTL_SECONDS", None)
            importlib.reload(mc)


class TestFreshnessSingleFlight:
    """
    Scenario 5: 50 concurrent callers for the SAME stale key must
    still result in exactly 1 provider call (not 50) - the freshness
    feature must not reintroduce the quota-storm bug by making every
    caller independently decide "this is stale, I'll fetch it myself."
    Mirrors main.py's _get_fresh_page: the single-flight winner is the
    only one who ever calls the (here, fake) provider; everyone else
    must join via wait_for_in_flight_refresh and then read the
    winner's result from cache.
    """

    def test_fifty_concurrent_callers_on_stale_page_cause_one_fetch(self, fresh_cache, clock):
        fresh_cache.save_page(
            provider="google", account_id="a@b.com", page_size=100, page_token=None,
            messages=[_msg("old")], next_page_token=None,
        )
        clock.advance(3601)  # now stale

        fetch_calls = []
        fetch_lock = threading.Lock()

        def fake_provider_fetch():
            with fetch_lock:
                fetch_calls.append(1)
            time.sleep(0.02)  # simulate real network latency so losers actually have to wait
            return [_msg("refreshed")]

        def worker():
            if fresh_cache.try_start_prefetch(
                provider="google", account_id="a@b.com", page_size=100, page_token=None,
                max_age_seconds=3600,
            ):
                messages = fake_provider_fetch()
                fresh_cache.save_page(
                    provider="google", account_id="a@b.com", page_size=100,
                    page_token=None, messages=messages, next_page_token=None,
                )
                fresh_cache.finish_prefetch(
                    provider="google", account_id="a@b.com", page_size=100, page_token=None,
                )
            else:
                fresh_cache.wait_for_in_flight_refresh(
                    provider="google", account_id="a@b.com", page_size=100, page_token=None,
                )

        threads = [threading.Thread(target=worker) for _ in range(50)]
        for t in threads:
            t.start()
        for t in threads:
            t.join()

        assert len(fetch_calls) == 1
        page = fresh_cache.get_page(
            provider="google", account_id="a@b.com", page_size=100, page_token=None
        )
        assert page["messages"][0]["message_id"] == "refreshed"

    def test_different_stale_keys_refresh_independently_no_cross_contamination(self, fresh_cache, clock):
        """Scenario 6: two different stale keys refreshing at the same
        time must not block or interfere with each other, and must
        each get their own fetch."""
        for token in ("KEY_A", "KEY_B"):
            fresh_cache.save_page(
                provider="google", account_id="a@b.com", page_size=5, page_token=token,
                messages=[_msg(f"old-{token}")], next_page_token=None,
            )
        clock.advance(3601)

        fetch_calls_by_key: dict[str, int] = {"KEY_A": 0, "KEY_B": 0}
        lock = threading.Lock()

        def fake_fetch(key):
            with lock:
                fetch_calls_by_key[key] += 1
            return [_msg(f"refreshed-{key}")]

        def worker(key):
            if fresh_cache.try_start_prefetch(
                provider="google", account_id="a@b.com", page_size=5, page_token=key,
                max_age_seconds=3600,
            ):
                messages = fake_fetch(key)
                fresh_cache.save_page(
                    provider="google", account_id="a@b.com", page_size=5,
                    page_token=key, messages=messages, next_page_token=None,
                )
                fresh_cache.finish_prefetch(
                    provider="google", account_id="a@b.com", page_size=5, page_token=key,
                )
            else:
                fresh_cache.wait_for_in_flight_refresh(
                    provider="google", account_id="a@b.com", page_size=5, page_token=key,
                )

        threads = [threading.Thread(target=worker, args=(k,)) for k in ("KEY_A", "KEY_B") for _ in range(15)]
        for t in threads:
            t.start()
        for t in threads:
            t.join()

        assert fetch_calls_by_key == {"KEY_A": 1, "KEY_B": 1}
        for token in ("KEY_A", "KEY_B"):
            page = fresh_cache.get_page(
                provider="google", account_id="a@b.com", page_size=5, page_token=token
            )
            assert page["messages"][0]["message_id"] == f"refreshed-{token}"

    def test_losers_receive_refreshed_page_not_stale_one(self, fresh_cache, clock):
        """Concurrent callers that lose the single-flight race must
        see the WINNER's fresh result after waiting, not the old
        stale copy that was there when they started."""
        fresh_cache.save_page(
            provider="google", account_id="a@b.com", page_size=5, page_token=None,
            messages=[_msg("old")], next_page_token=None,
        )
        clock.advance(3601)

        winner_done = threading.Event()
        loser_saw: dict[str, str] = {}

        def winner():
            fresh_cache.try_start_prefetch(
                provider="google", account_id="a@b.com", page_size=5, page_token=None,
                max_age_seconds=3600,
            )
            time.sleep(0.05)
            fresh_cache.save_page(
                provider="google", account_id="a@b.com", page_size=5, page_token=None,
                messages=[_msg("new")], next_page_token=None,
            )
            fresh_cache.finish_prefetch(
                provider="google", account_id="a@b.com", page_size=5, page_token=None,
            )
            winner_done.set()

        def loser():
            # Give the winner a moment to claim first.
            time.sleep(0.01)
            claimed = fresh_cache.try_start_prefetch(
                provider="google", account_id="a@b.com", page_size=5, page_token=None,
                max_age_seconds=3600,
            )
            assert claimed is False
            fresh_cache.wait_for_in_flight_refresh(
                provider="google", account_id="a@b.com", page_size=5, page_token=None,
            )
            page = fresh_cache.get_page(
                provider="google", account_id="a@b.com", page_size=5, page_token=None
            )
            loser_saw["message_id"] = page["messages"][0]["message_id"]

        t1 = threading.Thread(target=winner)
        t2 = threading.Thread(target=loser)
        t1.start()
        t2.start()
        t1.join()
        t2.join()

        assert winner_done.is_set()
        assert loser_saw["message_id"] == "new"
