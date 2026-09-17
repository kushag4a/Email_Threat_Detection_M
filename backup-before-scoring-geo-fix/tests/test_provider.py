"""
Tests for provider identifier consistency.
"""
from __future__ import annotations

import pytest


class TestGmailProviderName:
    def test_canonical_name_is_google(self):
        from backend.app.providers.gmail_provider import GmailProvider
        assert GmailProvider.name == "google"

    def test_microsoft_name_is_microsoft(self):
        from backend.app.providers.microsoft_provider import MicrosoftGraphProvider
        assert MicrosoftGraphProvider.name == "microsoft"


class TestProviderRouteMapping:
    """The _get_provider helper in main.py must resolve 'google' and
    'microsoft' correctly."""

    def test_google_maps_to_gmail_provider(self):
        # We can't easily test _get_provider without a session,
        # but we can verify the import and class name.
        from backend.app.providers.gmail_provider import GmailProvider
        from backend.app.providers.microsoft_provider import MicrosoftGraphProvider
        # The route handler maps "google" -> GmailProvider, "microsoft" -> MicrosoftGraphProvider
        assert GmailProvider.name == "google"
        assert MicrosoftGraphProvider.name == "microsoft"


class TestStoreProviderCompatibility:
    """Results stored with either 'gmail' or 'google' must be
    retrievable with the other name."""

    def test_roundtrip_gmail_to_google(self, fresh_store):
        fresh_store.save_result(
            session_id="s1", provider="gmail", account_id="a@b.com",
            message_id="m1", result={"test": True},
        )
        # Must find via "google"
        assert fresh_store.get_result(
            session_id="s1", provider="google", account_id="a@b.com",
            message_id="m1",
        ) is not None

    def test_roundtrip_google_to_gmail(self, fresh_store):
        fresh_store.save_result(
            session_id="s1", provider="google", account_id="a@b.com",
            message_id="m2", result={"test": True},
        )
        # Must find via "gmail"
        assert fresh_store.get_result(
            session_id="s1", provider="gmail", account_id="a@b.com",
            message_id="m2",
        ) is not None

    def test_list_results_both_aliases(self, fresh_store):
        fresh_store.save_result(
            session_id="s1", provider="gmail", account_id="a@b.com",
            message_id="m1", result={"v": 1},
        )
        fresh_store.save_result(
            session_id="s1", provider="google", account_id="a@b.com",
            message_id="m2", result={"v": 2},
        )
        # Listing with either alias should find both
        results_google = fresh_store.list_results(session_id="s1", provider="google")
        results_gmail = fresh_store.list_results(session_id="s1", provider="gmail")
        # Both saved under canonical "google", so both queries return 2
        assert len(results_google) == 2
        assert len(results_gmail) == 2
