"""
Regression tests for the page-scoped scan bug fix.

Background (see DIAGNOSTIC_EVIDENCE.md / CHANGES.md): /api/scan used to
accept only a `count` integer and re-derive "the first N messages in
the mailbox" via its own from-scratch pagination (page_token always
starting at None), completely ignoring which page of the inbox the
user was actually viewing. Selecting page 2 and clicking Scan silently
analyzed page 1's messages instead - the UI showed "Scanning" and a
completed progress bar, but for the wrong messages entirely.

The fix: /api/scan now requires the caller (the frontend) to send the
exact message IDs currently displayed for the page in view
(validate_scan_message_ids), and scan_service.run_scan operates only
on that explicit list - it no longer does any pagination of its own.

These tests exercise scan_service.validate_scan_message_ids and
scan_service.run_scan directly with a fake MailProvider - no real
Gmail/Graph credentials, network access, or FastAPI TestClient needed.
run_scan is driven with plain asyncio.run() rather than
pytest.mark.asyncio, since this project does not depend on
pytest-asyncio.
"""
from __future__ import annotations

import asyncio

import pytest

from backend.app.services import scan_service
from backend.app.services.store import STORE


class _FakeProvider:
    """
    Records exactly which message_ids get_message() is called with.
    Always fails fast with no real network/analysis - these tests are
    about *which IDs get fetched*, not analysis quality (that's
    covered by the existing pipeline-regression tests). A fast
    failure still exercises run_scan's real per-message failure
    handling and STORE bookkeeping, just without needing the real
    ProcessPoolExecutor/CPU analysis path to succeed.
    """

    name = "google"

    def __init__(self):
        self.fetched_message_ids: list[str] = []

    def get_message(self, message_id: str):
        self.fetched_message_ids.append(message_id)
        raise RuntimeError("fake provider - no real message data in this test")


PAGE_1_IDS = [f"page1-msg-{i}" for i in range(5)]
PAGE_2_IDS = [f"page2-msg-{i}" for i in range(5)]


class TestValidateScanMessageIds:
    def test_rejects_empty_list(self):
        with pytest.raises(ValueError):
            scan_service.validate_scan_message_ids([])

    def test_rejects_none(self):
        with pytest.raises(ValueError):
            scan_service.validate_scan_message_ids(None)

    def test_rejects_non_string_entries(self):
        with pytest.raises(ValueError):
            scan_service.validate_scan_message_ids(["a", 123, "b"])

    def test_rejects_blank_string_entries(self):
        with pytest.raises(ValueError):
            scan_service.validate_scan_message_ids(["a", "   ", "b"])

    def test_rejects_more_than_max(self):
        too_many = [f"id-{i}" for i in range(scan_service.MAX_SCAN_MESSAGE_IDS + 1)]
        with pytest.raises(ValueError):
            scan_service.validate_scan_message_ids(too_many)

    def test_accepts_exactly_max(self):
        exactly_max = [f"id-{i}" for i in range(scan_service.MAX_SCAN_MESSAGE_IDS)]
        result = scan_service.validate_scan_message_ids(exactly_max)
        assert len(result) == scan_service.MAX_SCAN_MESSAGE_IDS

    def test_deduplicates_while_preserving_order(self):
        """A client bug or retried request sending the same ID twice
        must not analyze it twice in one scan."""
        result = scan_service.validate_scan_message_ids(["a", "b", "a", "c", "b"])
        assert result == ["a", "b", "c"]


class TestPageScopedScanning:
    def test_scanning_page_1_only_fetches_page_1_ids(self):
        provider = _FakeProvider()
        scan_id = STORE.create_scan(session_id="sess-1", requested=len(PAGE_1_IDS))

        asyncio.run(
            scan_service.run_scan(
                scan_id=scan_id, session_id="sess-1", provider=provider,
                message_ids=PAGE_1_IDS,
            )
        )

        assert sorted(provider.fetched_message_ids) == sorted(PAGE_1_IDS)

    def test_scanning_page_2_only_fetches_page_2_ids(self):
        provider = _FakeProvider()
        scan_id = STORE.create_scan(session_id="sess-1", requested=len(PAGE_2_IDS))

        asyncio.run(
            scan_service.run_scan(
                scan_id=scan_id, session_id="sess-1", provider=provider,
                message_ids=PAGE_2_IDS,
            )
        )

        assert sorted(provider.fetched_message_ids) == sorted(PAGE_2_IDS)

    def test_scanning_page_2_never_touches_page_1_ids(self):
        """
        Core regression test for the live bug: scanning page 2 must
        never cause any page-1 message ID to be fetched. This is the
        exact scenario reported live - page 2 displayed, Scan clicked,
        page 1's messages were analyzed instead.
        """
        provider = _FakeProvider()
        scan_id = STORE.create_scan(session_id="sess-1", requested=len(PAGE_2_IDS))

        asyncio.run(
            scan_service.run_scan(
                scan_id=scan_id, session_id="sess-1", provider=provider,
                message_ids=PAGE_2_IDS,
            )
        )

        for page1_id in PAGE_1_IDS:
            assert page1_id not in provider.fetched_message_ids

    def test_repeated_scans_of_different_pages_stay_isolated(self):
        """Scanning page 1, then page 2, then page 1 again must fetch
        exactly the right IDs each time - no bleed-through between
        scans triggered back to back."""
        provider = _FakeProvider()

        for expected_ids in (PAGE_1_IDS, PAGE_2_IDS, PAGE_1_IDS):
            provider.fetched_message_ids.clear()
            scan_id = STORE.create_scan(session_id="sess-1", requested=len(expected_ids))
            asyncio.run(
                scan_service.run_scan(
                    scan_id=scan_id, session_id="sess-1", provider=provider,
                    message_ids=expected_ids,
                )
            )
            assert sorted(provider.fetched_message_ids) == sorted(expected_ids)

    def test_scan_results_are_associated_with_the_correct_scan_id(self):
        """
        Each scan's results list must contain exactly its own message
        IDs' results, never another scan's - the mechanism that
        prevents "page 1's old results displayed as page 2's results"
        (Task 3 in the stabilization brief).
        """
        provider = _FakeProvider()

        scan_id_1 = STORE.create_scan(session_id="sess-1", requested=len(PAGE_1_IDS))
        asyncio.run(
            scan_service.run_scan(
                scan_id=scan_id_1, session_id="sess-1", provider=provider,
                message_ids=PAGE_1_IDS,
            )
        )

        provider.fetched_message_ids.clear()
        scan_id_2 = STORE.create_scan(session_id="sess-1", requested=len(PAGE_2_IDS))
        asyncio.run(
            scan_service.run_scan(
                scan_id=scan_id_2, session_id="sess-1", provider=provider,
                message_ids=PAGE_2_IDS,
            )
        )

        scan_1 = STORE.get_scan(scan_id_1, session_id="sess-1")
        scan_2 = STORE.get_scan(scan_id_2, session_id="sess-1")

        scan_1_message_ids = {r["message_id"] for r in scan_1["results"]}
        scan_2_message_ids = {r["message_id"] for r in scan_2["results"]}

        assert scan_1_message_ids == set(PAGE_1_IDS)
        assert scan_2_message_ids == set(PAGE_2_IDS)
        assert scan_1_message_ids.isdisjoint(scan_2_message_ids)

    def test_scan_ownership_is_session_scoped(self):
        """
        A scan created for one session must not be retrievable by a
        different session_id. This is ResultStore's existing ownership
        check, re-asserted here as a regression guard specifically for
        the page-scoped-scan feature: message_ids are now
        client-supplied, so this boundary (a session can only ever see
        its own scans/results) matters more than it did when message
        IDs were always server-derived.
        """
        scan_id = STORE.create_scan(session_id="owner-session", requested=1)
        assert STORE.get_scan(scan_id, session_id="owner-session") is not None
        assert STORE.get_scan(scan_id, session_id="different-session") is None
