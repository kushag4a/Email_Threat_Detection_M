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
