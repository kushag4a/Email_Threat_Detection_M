"""
Regression tests for the Gmail transport concurrency fix.

Background (see DIAGNOSTIC_EVIDENCE.md / CHANGES.md): GmailProvider used
to build exactly one googleapiclient Resource (backed by exactly one
httplib2.Http transport) in __init__ and reuse it for every call. Both
/api/emails (a ThreadPoolExecutor of up to 10 threads) and
scan_service.run_scan (IO_POOL, up to MAX_CONCURRENT_ANALYSES=5 threads)
call methods on the *same* GmailProvider instance concurrently by design.
httplib2.Http is not thread-safe (its own source documents this), so
sharing one instance across threads let two threads read/write the same
underlying connection at once - this is what produced the live failures
("'NoneType' object has no attribute 'close'", "Remote end closed
connection without response", SSL record-MAC failures, stalled reads
that time out).

The fix makes GmailProvider build a separate Resource per calling thread
(via threading.local, lazily on first use), so concurrent threads never
touch the same transport/connection-cache object.

These tests monkeypatch googleapiclient.discovery.build so they run
without real network access or real Google credentials - they verify the
*isolation property* the fix relies on, not real Gmail API behavior.
Real Gmail API behavior requires a live, OAuth-connected account (see
DIAGNOSTIC_EVIDENCE.md; not verified in this environment).
"""
from __future__ import annotations

import threading

import pytest


class _FakeCredentials:
    """Stand-in for google.oauth2.credentials.Credentials - GmailProvider
    only ever stores this and passes it through to build(), so it does
    not need to be a real Credentials instance for these tests."""


@pytest.fixture
def patched_build(monkeypatch):
    """
    Replace googleapiclient.discovery.build with a fake that returns a
    fresh, distinct sentinel "Resource" object on every call, and records
    every call's kwargs so tests can assert on them.
    """
    import backend.app.providers.gmail_provider as gmail_provider_module

    calls = []

    class _FakeResource:
        """A distinct object per build() call - stands in for a real
        googleapiclient Resource (and its embedded Http transport)."""

    def _fake_build(*args, **kwargs):
        calls.append(kwargs)
        return _FakeResource()

    monkeypatch.setattr(gmail_provider_module, "build", _fake_build)
    return calls


class TestGmailProviderThreadLocalTransport:
    def test_service_is_built_lazily_not_in_init(self, patched_build):
        """__init__ must not call build() eagerly - only _service() does,
        the first time it's actually needed, on whichever thread needs it."""
        from backend.app.providers.gmail_provider import GmailProvider

        GmailProvider(_FakeCredentials())
        assert patched_build == [], "build() must not run in __init__"

    def test_service_cached_within_one_thread(self, patched_build):
        """Calling _service() twice on the same thread must return the
        SAME object (no rebuilding per call) and call build() exactly once."""
        from backend.app.providers.gmail_provider import GmailProvider

        provider = GmailProvider(_FakeCredentials())
        first = provider._service()
        second = provider._service()

        assert first is second
        assert len(patched_build) == 1

    def test_build_called_with_cache_discovery_false(self, patched_build):
        """Building a fresh Resource per thread must not also add
        concurrent discovery-cache file I/O on top of the fix."""
        from backend.app.providers.gmail_provider import GmailProvider

        provider = GmailProvider(_FakeCredentials())
        provider._service()

        assert patched_build[0].get("cache_discovery") is False

    def test_concurrent_threads_get_distinct_isolated_services(self, patched_build):
        """
        Core regression test for the bug: N concurrent threads calling
        _service() on the SAME GmailProvider instance must each receive
        their OWN Resource object - never each other's, and never a
        single shared one. This is the property that removes the shared,
        non-thread-safe httplib2 transport that caused the live failures.
        """
        from backend.app.providers.gmail_provider import GmailProvider

        provider = GmailProvider(_FakeCredentials())

        n_threads = 12
        barrier = threading.Barrier(n_threads)
        results: dict[int, object] = {}
        errors: list[BaseException] = []

        def worker(idx: int) -> None:
            try:
                # Barrier forces every thread to call _service() at
                # (as close as possible to) the same instant, maximizing
                # the chance of exposing any shared/racy state.
                barrier.wait(timeout=5)
                results[idx] = provider._service()
            except BaseException as exc:  # noqa: BLE001 - want to see any failure
                errors.append(exc)

        threads = [threading.Thread(target=worker, args=(i,)) for i in range(n_threads)]
        for t in threads:
            t.start()
        for t in threads:
            t.join(timeout=10)

        assert not errors, f"worker thread(s) raised: {errors}"
        assert len(results) == n_threads

        # Every thread must have gotten its OWN object - zero sharing.
        distinct_object_ids = {id(obj) for obj in results.values()}
        assert len(distinct_object_ids) == n_threads, (
            "expected one isolated Resource per thread, but some threads "
            "shared the same object - the concurrency bug would reproduce"
        )

        # And build() must have been called exactly once per thread -
        # not once total (the old, unsafe shared-instance behavior) and
        # not more than once per thread (no redundant rebuilding).
        assert len(patched_build) == n_threads

    def test_same_thread_reused_across_multiple_calls_still_single_build(self, patched_build):
        """
        Sanity check in the other direction: reusing the SAME thread for
        many sequential calls (e.g. get_current_user() then
        get_message()) must still only build once - the fix must not
        turn every call into a fresh, wasteful build().
        """
        from backend.app.providers.gmail_provider import GmailProvider

        provider = GmailProvider(_FakeCredentials())
        for _ in range(5):
            provider._service()

        assert len(patched_build) == 1
