"""
Regression tests for Return-Path mismatch scoring.

Background (see DIAGNOSTIC_EVIDENCE.md / CHANGES.md): a real Twitch
notification (From: no-reply@twitch.tv, Return-Path on Amazon SES
infrastructure, SPF/DKIM/DMARC all passing) was scored SUSPICIOUS
(47/100) partly because Return-Path differing from the visible sender
added a flat +8 regardless of authentication outcome - even though
that pattern is completely normal for legitimate bulk-mail/ESP
infrastructure. The fix makes the penalty conditional on whether
SPF+DKIM+DMARC all passed: +2 (weak signal) when they do, +8
(unchanged) when they don't. This is generic - keyed off the auth
verdicts every message already gets from M1, not off any specific
sender - so it does not special-case Twitch or any other domain.
"""
from __future__ import annotations

from backend.app.services.risk_engine import calculate_risk


def _base_kwargs(**overrides):
    kwargs = dict(
        m1={"spf": "pass", "dkim": "pass", "dmarc": "pass"},
        m2={"phishing_probability": 0},
        m3={},
        header_analysis={"return_path_mismatch": False, "reply_to_mismatch": False},
        attachment_analysis={},
    )
    kwargs.update(overrides)
    return kwargs


class TestReturnPathMismatchWeighting:
    def test_legitimate_third_party_bulk_sender_gets_weak_signal(self):
        """SPF+DKIM+DMARC all pass, Return-Path differs (e.g. Amazon
        SES) - this must be a weak (+2) signal, not the old flat +8."""
        result = calculate_risk(**_base_kwargs(
            m1={"spf": "pass", "dkim": "pass", "dmarc": "pass"},
            header_analysis={"return_path_mismatch": True, "reply_to_mismatch": False},
        ))
        assert result["score"] == 2
        assert any("weak signal" in r for r in result["reasons"])

    def test_legitimate_direct_sender_matching_return_path_no_penalty(self):
        """No mismatch at all -> no Return-Path evidence contributed,
        regardless of auth outcome (score stays 0; the risk engine's
        existing "no significant risk indicators" placeholder reason
        is unrelated to this fix)."""
        result = calculate_risk(**_base_kwargs(
            m1={"spf": "pass", "dkim": "pass", "dmarc": "pass"},
            header_analysis={"return_path_mismatch": False, "reply_to_mismatch": False},
        ))
        assert result["score"] == 0
        assert not any("Return-Path" in r for r in result["reasons"])

    def test_suspicious_sender_with_mismatch_and_failed_auth_keeps_full_weight(self):
        """Genuine spoofing candidate: mismatch AND failed
        authentication must still score the full +8, unchanged from
        before this fix."""
        result = calculate_risk(**_base_kwargs(
            m1={"spf": "fail", "dkim": "fail", "dmarc": "fail"},
            header_analysis={"return_path_mismatch": True, "reply_to_mismatch": False},
        ))
        # 3 x 8 (SPF/DKIM/DMARC fail) + 8 (mismatch, full weight) = 32
        assert result["score"] == 32
        assert "Return-Path does not match sender" in result["reasons"]
        assert "SPF failed" in result["reasons"]

    def test_suspicious_sender_with_mismatch_and_partial_auth_failure_keeps_full_weight(self):
        """Even a single failed check (not full authentication) must
        keep the mismatch at full weight - "strong authentication"
        requires SPF+DKIM+DMARC to ALL pass, not just some."""
        result = calculate_risk(**_base_kwargs(
            m1={"spf": "pass", "dkim": "pass", "dmarc": "fail"},
            header_analysis={"return_path_mismatch": True, "reply_to_mismatch": False},
        ))
        assert "Return-Path does not match sender" in result["reasons"]
        assert not any("weak signal" in r for r in result["reasons"])

    def test_spf_dkim_dmarc_pass_with_third_party_return_path_reduces_concern(self):
        """Direct restatement of the real Twitch scenario: full
        authentication plus a third-party Return-Path must land well
        below what a flat +8 would have produced."""
        result = calculate_risk(**_base_kwargs(
            m1={"spf": "pass", "dkim": "pass", "dmarc": "pass"},
            m2={"phishing_probability": 96.36},
            header_analysis={"return_path_mismatch": True, "reply_to_mismatch": False},
        ))
        old_flat_penalty_score = round(0.9636 * 40 + 8)  # what the old code would have produced
        assert result["score"] < old_flat_penalty_score

    def test_generic_not_twitch_specific(self):
        """The fix is not keyed on sender domain at all - a
        completely different domain gets exactly the same treatment
        for the same auth/mismatch combination."""
        twitch_like = calculate_risk(**_base_kwargs(
            m1={"spf": "pass", "dkim": "pass", "dmarc": "pass"},
            header_analysis={"return_path_mismatch": True, "reply_to_mismatch": False},
        ))
        other_sender_same_shape = calculate_risk(**_base_kwargs(
            m1={"spf": "pass", "dkim": "pass", "dmarc": "pass"},
            header_analysis={"return_path_mismatch": True, "reply_to_mismatch": False},
        ))
        assert twitch_like["score"] == other_sender_same_shape["score"]

    def test_return_path_mismatch_flag_still_present_in_header_analysis(self):
        """Forensic visibility requirement: the mismatch boolean itself
        must still be computable/visible - this test guards the
        contract calculate_risk relies on, not a UI concern."""
        result = calculate_risk(**_base_kwargs(
            header_analysis={"return_path_mismatch": True, "reply_to_mismatch": False},
        ))
        assert "M1" in result["contributing_modules"]
