"""
Regression tests for the eight synthetic phishing .eml fixtures
(tests/fixtures/phishing_eml_suite/).

Each fixture is a SYNTHETIC test message (example-attacker.test /
example-company.test placeholder domains, no real payloads) designed
to exercise one specific detection technique. These assertions
intentionally focus on SECURITY BEHAVIOR - "this must not be scored
SAFE/LOW" and "the specific evidence type must be present" - rather
than pinning exact scores, since the underlying ML model's calibrated
probabilities can shift slightly across environments/versions without
the security posture actually regressing.
"""
from __future__ import annotations

from pathlib import Path

import pytest

from backend.app.services.analysis_service import analyze_eml_upload

FIXTURES_DIR = Path(__file__).parent / "fixtures" / "phishing_eml_suite"


def _analyze(filename: str) -> dict:
    content = (FIXTURES_DIR / filename).read_bytes()
    return analyze_eml_upload(content)


def _reasons(result: dict) -> list[str]:
    return result.get("risk", {}).get("reasons", [])


def _all_local_flags(result: dict) -> set[str]:
    flags: set[str] = set()
    for h in result.get("m3", {}).get("local_heuristics", []):
        flags.update(h.get("flags", []))
    return flags


def _rule_based_categories(result: dict) -> set[str]:
    rbt = result.get("m2", {}).get("rule_based_threats", {}) or {}
    return {category for category, value in rbt.items() if value > 0}


def _assert_not_safe_low(result: dict, label: str):
    level = result.get("risk", {}).get("level")
    score = result.get("risk", {}).get("score")
    assert level not in ("LOW", "SAFE"), (
        f"{label}: expected at least MEDIUM, got {level} (score={score}), "
        f"reasons={_reasons(result)}"
    )


class TestPhishingEmlSuite:
    def test_01_display_name_spoof(self):
        result = _analyze("01_display_name_spoof.eml")
        _assert_not_safe_low(result, "01_display_name_spoof")
        reasons = _reasons(result)
        assert any("Reply-To" in r for r in reasons), (
            f"expected a Reply-To/identity anomaly reason, got {reasons}"
        )

    def test_02_credential_harvest(self):
        result = _analyze("02_credential_harvest.eml")
        _assert_not_safe_low(result, "02_credential_harvest")
        reasons = _reasons(result)
        rule_categories = _rule_based_categories(result)
        assert (
            "credential_theft" in rule_categories
            or any("phishing" in r.lower() or "AI" in r for r in reasons)
        ), f"expected credential/phishing evidence, got reasons={reasons}, rule_categories={rule_categories}"

    def test_03_invoice_attachment(self):
        result = _analyze("03_invoice_attachment.eml")
        _assert_not_safe_low(result, "03_invoice_attachment")
        reasons = _reasons(result)
        assert any("Attachment" in r for r in reasons), (
            f"expected attachment evidence, got {reasons}"
        )

    def test_04_lookalike_domain(self):
        result = _analyze("04_lookalike_domain.eml")
        _assert_not_safe_low(result, "04_lookalike_domain")
        assert "brand_lookalike_domain" in _all_local_flags(result), (
            f"expected brand-lookalike evidence, flags={_all_local_flags(result)}, "
            f"reasons={_reasons(result)}"
        )

    def test_05_bec_reply_to_mismatch(self):
        result = _analyze("05_bec_reply_to_mismatch.eml")
        _assert_not_safe_low(result, "05_bec_reply_to_mismatch")
        reasons = _reasons(result)
        assert any("Reply-To" in r or "Return-Path" in r for r in reasons), (
            f"expected Reply-To/Return-Path header anomaly evidence, got {reasons}"
        )
        rule_categories = _rule_based_categories(result)
        assert "bec" in rule_categories or "financial_fraud" in rule_categories, (
            f"expected BEC/financial-fraud evidence, got {rule_categories}"
        )

    def test_06_uri_obfuscation(self):
        result = _analyze("06_uri_obfuscation.eml")
        _assert_not_safe_low(result, "06_uri_obfuscation")
        flags = _all_local_flags(result)
        assert "uri_userinfo_obfuscation" in flags or "userinfo_in_url" in flags, (
            f"expected URI/userinfo obfuscation evidence, flags={flags}"
        )

    def test_07_payroll_redirect(self):
        result = _analyze("07_payroll_redirect.eml")
        _assert_not_safe_low(result, "07_payroll_redirect")
        assert "redirector_with_nested_destination" in _all_local_flags(result), (
            f"expected nested-destination/redirect evidence, flags={_all_local_flags(result)}, "
            f"reasons={_reasons(result)}"
        )

    def test_08_unicode_lookalike(self):
        result = _analyze("08_unicode_lookalike.eml")
        _assert_not_safe_low(result, "08_unicode_lookalike")
        assert "brand_lookalike_domain" in _all_local_flags(result), (
            f"expected punycode/lookalike evidence, flags={_all_local_flags(result)}, "
            f"reasons={_reasons(result)}"
        )


class TestPhishingEmlSuiteSummary:
    """All eight synthetic malicious fixtures must clear MEDIUM."""

    @pytest.mark.parametrize(
        "filename",
        [
            "01_display_name_spoof.eml",
            "02_credential_harvest.eml",
            "03_invoice_attachment.eml",
            "04_lookalike_domain.eml",
            "05_bec_reply_to_mismatch.eml",
            "06_uri_obfuscation.eml",
            "07_payroll_redirect.eml",
            "08_unicode_lookalike.eml",
        ],
    )
    def test_severity_at_least_medium(self, filename):
        result = _analyze(filename)
        level = result.get("risk", {}).get("level")
        score = result.get("risk", {}).get("score")
        assert level in ("MEDIUM", "HIGH", "CRITICAL"), (
            f"{filename}: expected severity >= MEDIUM, got {level} (score={score})"
        )
