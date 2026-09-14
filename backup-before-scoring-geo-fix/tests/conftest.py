"""Shared test fixtures for ValorProtects tests."""
from __future__ import annotations

import pytest

from backend.app.schemas.email_message import NormalizedEmail, AttachmentMeta


@pytest.fixture
def sample_email() -> NormalizedEmail:
    """A minimal normalized email for pipeline tests."""
    return NormalizedEmail(
        message_id="test-msg-001",
        thread_id="thread-001",
        provider="google",
        account_id="user@example.com",
        sender="sender@example.com",
        recipient="user@example.com",
        subject="Weekly Team Standup Notes - September 2024",
        date="Mon, 01 Jan 2024 12:00:00 +0000",
        body="Hi team, here are the notes from today's standup meeting. We discussed the roadmap progress for Q4 and reviewed the sprint backlog items. Sarah will follow up on the database migration timeline and Mike will prepare the performance benchmarks for the next review. Let me know if I missed anything. Best regards, Alice",
        html_body="<p>Hi team, here are the notes from today's standup meeting. We discussed the roadmap progress for Q4 and reviewed the sprint backlog items.</p>",
        urls=["https://example.com"],
        reply_to="sender@example.com",
        return_path="sender@example.com",
        received_headers=["from mail.example.com"],
        received_spf=["pass"],
        authentication_results=["spf=pass; dkim=pass; dmarc=pass"],
        attachments=[],
    )


@pytest.fixture
def phishing_email() -> NormalizedEmail:
    """An email with multiple phishing indicators."""
    return NormalizedEmail(
        message_id="phish-msg-001",
        thread_id="thread-phish",
        provider="google",
        account_id="user@example.com",
        sender="security@paypa1.evil-domain.com",
        recipient="user@example.com",
        subject="Your account has been compromised - Verify Now",
        date="Mon, 01 Jan 2024 12:00:00 +0000",
        body="Your account has been compromised. Click here immediately to verify your identity: http://192.168.1.1/login.php?user=admin",
        html_body="<p>Click <a href='http://192.168.1.1/login.php'>here</a></p>",
        urls=["http://192.168.1.1/login.php?user=admin", "http://evil-domain.com/reset-password"],
        reply_to="different-reply@gmail.com",
        return_path="bounce@evil-domain.com",
        received_headers=["from unknown-relay.suspicious.net"],
        received_spf=["fail"],
        authentication_results=["spf=fail; dkim=fail; dmarc=fail"],
        attachments=[],
    )


@pytest.fixture
def newsletter_email() -> NormalizedEmail:
    """A legitimate marketing/newsletter email (e.g., from Pinterest).
    Must be scored LOW to avoid false positives."""
    return NormalizedEmail(
        message_id="newsletter-001",
        thread_id="thread-news",
        provider="google",
        account_id="user@example.com",
        sender="noreply@pinterest.com",
        recipient="user@example.com",
        subject="New ideas for you",
        date="Mon, 01 Jan 2024 12:00:00 +0000",
        body="Check out these new Pins based on your interests. We found some great ideas that you might like. Browse your feed for more personalized recommendations. You can manage your email preferences in your account settings at any time.",
        html_body="<p>Check out these new Pins based on your interests.</p>",
        urls=[
            "https://post.pinterest.com/f/a/verify-click/tracking123",
            "https://post.pinterest.com/f/a/account-settings/abc",
            "https://www.pinterest.com/pin/12345/",
            "https://post.pinterest.com/f/a/confirm-email/def",
            "https://help.pinterest.com/account/update-preferences",
        ],
        reply_to="noreply@pinterest.com",
        return_path="noreply@pinterest.com",
        received_headers=["from mail-out.pinterest.com"],
        received_spf=["pass"],
        authentication_results=["spf=pass; dkim=pass; dmarc=pass"],
        attachments=[],
    )


@pytest.fixture
def fresh_store():
    """A fresh ResultStore instance for isolated testing."""
    from backend.app.services.store import ResultStore
    return ResultStore()
