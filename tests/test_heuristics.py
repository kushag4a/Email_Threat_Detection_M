"""
Tests for local heuristic engine: false-positive resistance for
legitimate ESP/marketing emails, and detection of genuinely
suspicious URLs.
"""
from __future__ import annotations

import pytest

from backend.app.threat_intel.local_engine import analyze_url, _is_known_esp_host


# ── ESP host detection ─────────────────────────────────────────────

class TestESPHostDetection:
    def test_pinterest_tracking(self):
        assert _is_known_esp_host("post.pinterest.com")

    def test_sendgrid(self):
        assert _is_known_esp_host("em123.sendgrid.net")

    def test_mailchimp(self):
        assert _is_known_esp_host("click.mailchimp.com")

    def test_unknown_host_not_esp(self):
        assert not _is_known_esp_host("evil-phishing-site.com")

    def test_partial_match_not_fooled(self):
        """evil-pinterest.com should NOT match."""
        assert not _is_known_esp_host("evil-pinterest.com")


# ── False-positive resistance (legitimate emails) ─────────────────

class TestLegitimateURLs:
    """Tracking URLs from legitimate ESPs must NOT score high on
    keyword heuristics.  These URLs routinely contain words like
    'verify', 'account', 'confirm' in their paths."""

    def test_pinterest_tracking_url_low_score(self):
        r = analyze_url("https://post.pinterest.com/f/a/verify-click/tracking123")
        assert r["local_score"] < 15, f"Pinterest tracking URL scored {r['local_score']}"
        assert "suspicious_action_keywords" not in r["flags"]

    def test_pinterest_account_url_low_score(self):
        r = analyze_url("https://post.pinterest.com/f/a/account-settings/abc")
        assert r["local_score"] < 15
        assert "suspicious_action_keywords" not in r["flags"]

    def test_pinterest_confirm_url_low_score(self):
        r = analyze_url("https://post.pinterest.com/f/a/confirm-email/def")
        assert r["local_score"] < 15
        assert "suspicious_action_keywords" not in r["flags"]

    def test_google_account_url_low_score(self):
        r = analyze_url("https://accounts.google.com/signin/v2/verify")
        assert r["local_score"] < 15
        assert "suspicious_action_keywords" not in r["flags"]

    def test_mailchimp_tracking_low_score(self):
        r = analyze_url("https://click.mailchimp.com/track/confirm-subscription/123")
        assert r["local_score"] < 15


# ── Malicious URL detection preserved ─────────────────────────────

class TestMaliciousURLs:
    """Genuinely suspicious URLs must still be detected."""

    def test_ip_based_url_flagged(self):
        r = analyze_url("http://192.168.1.1/login.php")
        assert "ip_as_hostname" in r["flags"]
        assert r["local_score"] >= 15

    def test_punycode_domain_flagged(self):
        r = analyze_url("https://xn--pypal-4ve.com/login")
        assert "punycode_domain" in r["flags"]
        assert r["local_score"] >= 20

    def test_userinfo_in_url_flagged(self):
        r = analyze_url("https://admin@evil.com/login")
        assert "userinfo_in_url" in r["flags"]
        assert r["local_score"] >= 20

    def test_very_long_url_flagged(self):
        r = analyze_url("https://evil.com/" + "x" * 250)
        assert "very_long_url" in r["flags"]
        assert r["local_score"] >= 10

    def test_unknown_domain_with_keywords_flagged(self):
        """Non-ESP domains with suspicious keywords MUST still be flagged."""
        r = analyze_url("https://evil-domain.com/login/verify/password-reset")
        assert "suspicious_action_keywords" in r["flags"]
        assert r["local_score"] >= 5

    def test_unusual_port_flagged(self):
        r = analyze_url("https://evil.com:8443/admin")
        assert "unusual_port" in r["flags"]

    def test_missing_hostname_flagged(self):
        r = analyze_url("http:///path/to/something")
        assert "missing_hostname" in r["flags"]
        assert r["local_score"] >= 25


# ── Full pipeline regression tests ────────────────────────────────

class TestPipelineRegression:
    """End-to-end risk scoring regression tests."""

    def test_newsletter_scores_low(self, newsletter_email):
        """A legitimate marketing email MUST NOT be scored HIGH or above.
        The ML model may give moderate phishing probability to synthetic
        text, so we verify:
        1. Score stays below HIGH (60)
        2. No 'Local heuristics' reason (the RC5 fix target)
        3. No Return-Path mismatch
        """
        from backend.app.services.analysis_service import analyze_email_safe
        result = analyze_email_safe(newsletter_email)
        risk = result.get("risk", {})
        reasons = risk.get("reasons", [])
        assert risk.get("score", 0) < 60, (
            f"Newsletter scored {risk.get('score')} (should be <60): {reasons}"
        )
        assert not any("Local heuristics" in r for r in reasons), (
            f"Local heuristics should NOT contribute for newsletter: {reasons}"
        )
        assert not any("Return-Path" in r for r in reasons), (
            f"Return-Path mismatch should not trigger: {reasons}"
        )

    def test_phishing_scores_high_or_critical(self, phishing_email):
        """An email with multiple phishing indicators MUST score HIGH+."""
        from backend.app.services.analysis_service import analyze_email_safe
        result = analyze_email_safe(phishing_email)
        risk = result.get("risk", {})
        assert risk.get("level") in ("HIGH", "CRITICAL"), (
            f"Phishing email scored {risk.get('level')} ({risk.get('score')}) "
            f"with reasons: {risk.get('reasons')}"
        )

    def test_clean_email_scores_low(self, sample_email):
        """A clean email with passing auth MUST score LOW."""
        from backend.app.services.analysis_service import analyze_email_safe
        result = analyze_email_safe(sample_email)
        risk = result.get("risk", {})
        assert risk.get("level") == "LOW", (
            f"Clean email scored {risk.get('level')} ({risk.get('score')}) "
            f"with reasons: {risk.get('reasons')}"
        )

    def test_result_has_geo_status(self, sample_email):
        """Every analysis result must include a geo_status field."""
        from backend.app.services.analysis_service import analyze_email_safe
        result = analyze_email_safe(sample_email)
        assert "geo_status" in result
        assert result["geo_status"] == "pending"
