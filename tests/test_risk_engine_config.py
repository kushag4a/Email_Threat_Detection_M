"""
Tests for the centralized, configurable risk-scoring policy
(RISK_CONFIG) and the explainable calculation breakdown returned by
calculate_risk() - see TASK 2/2A/2B/2C/2D/2E in PROJECT_CONTEXT.
"""
from __future__ import annotations

import copy

from backend.app.services.risk_engine import RISK_CONFIG, calculate_risk
from backend.app.services.bec_detector import detect_bec


def _base_kwargs(**overrides):
    kwargs = dict(
        m1={"spf": "pass", "dkim": "pass", "dmarc": "pass"},
        m2={"phishing_probability": 0, "threat_categories": {}},
        m3={},
        header_analysis={},
        attachment_analysis={"items": []},
    )
    kwargs.update(overrides)
    return kwargs


# ---------------------------------------------------------------------------
# Default configuration reproduces current/documented behavior
# ---------------------------------------------------------------------------
class TestDefaultBehaviorUnchanged:
    def test_ml_probability_uses_documented_multiplier(self):
        result = calculate_risk(**_base_kwargs(
            m2={"phishing_probability": 75.0, "threat_categories": {}},
        ))
        # 0.75 * 40 = 30
        assert result["score"] == 30
        assert result["level"] == "MEDIUM"

    def test_high_ai_without_independent_evidence_is_not_critical(self):
        result = calculate_risk(**_base_kwargs(
            m2={"phishing_probability": 99.97, "threat_categories": {"spam": 90}},
        ))
        assert result["score"] >= 40
        assert result["level"] != "CRITICAL"

    def test_no_signals_scores_zero_low(self):
        result = calculate_risk(**_base_kwargs())
        assert result["score"] == 0
        assert result["level"] == "LOW"
        assert result["reasons"] == ["No significant risk indicators found"]


# ---------------------------------------------------------------------------
# TASK 2B: multiplier changes actually affect the score
# ---------------------------------------------------------------------------
class TestMultipliersAreReal:
    def test_changing_ml_multiplier_changes_score_and_breakdown(self):
        m2 = {"phishing_probability": 75.0, "threat_categories": {}}

        default_result = calculate_risk(**_base_kwargs(m2=m2))
        assert default_result["score"] == 30  # 0.75 * 40

        override_config = copy.deepcopy(RISK_CONFIG)
        override_config["weights"]["ml_phishing_probability_multiplier"] = 50
        override_result = calculate_risk(**_base_kwargs(m2=m2), config=override_config)
        assert override_result["score"] == round(0.75 * 50)  # 37.5 -> 38

        ml_item = next(
            i for i in override_result["calculation"]["items"]
            if i["signal"] == "ML phishing probability"
        )
        assert ml_item["multiplier"] == 50
        assert ml_item["input"] == 75.0
        assert abs(ml_item["contribution"] - 37.5) < 1e-6

    def test_partial_config_override_does_not_drop_other_sections(self):
        """Passing only {"weights": {...}} must not silently wipe out
        caps/floors/thresholds - the merge is additive per-section."""
        result = calculate_risk(**_base_kwargs(
            m1={"spf": "fail", "dkim": "pass", "dmarc": "pass"},
        ), config={"weights": {"spf_fail": 100}})
        # The override took effect...
        spf_item = next(i for i in result["calculation"]["items"] if i["signal"] == "SPF failed")
        assert spf_item["multiplier"] == 100
        assert spf_item["contribution"] == 100
        # ...and the untouched sections (caps/floors/thresholds) are
        # still fully present and unchanged, not dropped by the merge.
        assert result["calculation"]["thresholds"] == RISK_CONFIG["thresholds"]
        assert result["score"] == 100  # clamped, even though raw > 100

    def test_yara_floor_still_applies_after_unrelated_weights_override(self):
        """A partial override of "weights" must not disable the floor
        living in the untouched "floors" section."""
        result = calculate_risk(**_base_kwargs(
            m2={"phishing_probability": 1.0, "threat_categories": {}},
            attachment_analysis={
                "items": [
                    {
                        "filename": "bad.exe",
                        "flags": ["executable_or_script_extension"],
                        "yara": {"matches": [{"rule": "X", "severity": "high"}]},
                    }
                ]
            },
        ), config={"weights": {"spf_fail": 100}})  # unrelated override
        floor_value = RISK_CONFIG["floors"]["yara_high_medium_floor"]
        assert result["score"] >= floor_value
        assert result["calculation"]["floors_applied"]


# ---------------------------------------------------------------------------
# TASK 2C: caps are respected and reported
# ---------------------------------------------------------------------------
class TestCaps:
    def test_phishtank_capped_at_configured_max_before_override(self):
        """The additive PhishTank contribution itself is still capped
        at phishtank_max, exactly as before - but a confirmed PhishTank
        match is now also CRITICAL-grade evidence (see
        RISK_CONFIG["overrides"]["confirmed_malicious_url_threat_intel"]),
        so the FINAL score/level are no longer capped at this additive
        value alone. This is an intentional hardening (previously a
        confirmed malicious URL could be diluted down to a MEDIUM
        score by a low/benign ML probability - exactly the
        "neutralized by benign ML" failure mode the hardening task
        requires fixing)."""
        result = calculate_risk(**_base_kwargs(
            m3={"phishtank": [{"listed": True}] * 5},  # 5 * 20 = 100 raw
        ))
        cap = RISK_CONFIG["caps"]["phishtank_max"]
        cap_entries = [c for c in result["calculation"]["caps_applied"] if c["cap"] == "phishtank_max"]
        assert cap_entries
        assert cap_entries[0]["clamped_value"] == cap
        assert cap_entries[0]["raw_value"] == 100
        # The confirmed-malicious-URL override then raises score/level
        # beyond the additive cap - see TestHardOverrides below.
        assert result["score"] >= cap
        assert result["level"] == "CRITICAL"

    def test_attachment_contribution_capped(self):
        items = [
            {"filename": f"f{i}.exe", "flags": ["executable_or_script_extension"], "yara": {"matches": []}}
            for i in range(5)
        ]
        result = calculate_risk(**_base_kwargs(attachment_analysis={"items": items}))
        cap = RISK_CONFIG["caps"]["attachment_max"]
        assert result["score"] == cap
        cap_entries = [c for c in result["calculation"]["caps_applied"] if c["cap"] == "attachment_max"]
        assert cap_entries


# ---------------------------------------------------------------------------
# TASK 2D: floors are respected and reported
# ---------------------------------------------------------------------------
class TestFloors:
    def test_yara_floor_raises_low_score_to_high(self):
        result = calculate_risk(**_base_kwargs(
            m2={"phishing_probability": 1.0, "threat_categories": {}},
            attachment_analysis={
                "items": [
                    {
                        "filename": "invoice.pdf.exe",
                        "flags": ["executable_or_script_extension"],
                        "yara": {"matches": [{"rule": "Suspicious_Executable_Indicators", "severity": "medium"}]},
                    }
                ]
            },
        ))
        floor_value = RISK_CONFIG["floors"]["yara_high_medium_floor"]
        assert result["score"] >= floor_value
        assert result["level"] == "HIGH"
        assert result["calculation"]["floors_applied"]
        assert result["calculation"]["floors_applied"][0]["minimum"] == floor_value
        assert any("floor" in r.lower() for r in result["reasons"])

    def test_yara_floor_does_not_lower_an_already_higher_score(self):
        """The floor only raises a score that would otherwise land
        below it - it must never reduce a score that's already
        higher on its own evidence."""
        result = calculate_risk(**_base_kwargs(
            m2={"phishing_probability": 99.0, "threat_categories": {"phishing": 90}},
            m1={"spf": "fail", "dkim": "fail", "dmarc": "fail"},
            attachment_analysis={
                "items": [
                    {
                        "filename": "invoice.pdf.exe",
                        "flags": ["executable_or_script_extension"],
                        "yara": {"matches": [{"rule": "X", "severity": "high"}]},
                    }
                ]
            },
        ))
        floor_value = RISK_CONFIG["floors"]["yara_high_medium_floor"]
        assert result["score"] > floor_value
        # No floor entry recorded, since the score never needed raising.
        assert result["calculation"]["floors_applied"] == []

    def test_legitimate_pdf_attachment_alone_is_not_suspicious(self):
        """A plain PDF/DOCX/XLSX/image with matching magic bytes and
        no YARA hit must not raise the score merely for being
        attached (see attachment_analysis.py's documented
        false-positive requirement)."""
        result = calculate_risk(**_base_kwargs(
            attachment_analysis={
                "items": [
                    {
                        "filename": "report.pdf",
                        "flags": [],
                        "yara": {"matches": []},
                    }
                ]
            },
        ))
        assert result["score"] == 0
        assert result["level"] == "LOW"


# ---------------------------------------------------------------------------
# TASK 2E: thresholds produce the correct severity
# ---------------------------------------------------------------------------
class TestThresholds:
    def test_threshold_boundaries(self):
        thresholds = RISK_CONFIG["thresholds"]
        assert thresholds == {
            "low_max": 29,
            "medium_min": 30,
            "medium_max": 59,
            "high_min": 60,
            "high_max": 79,
            "critical_min": 80,
        }

    def test_critical_requires_independent_evidence(self):
        # High aggregate score built from AI + rule-based + a weak
        # Return-Path signal - none of which are "independent
        # high-confidence evidence" (no auth failure, no reply-to
        # mismatch, no threat-intel hit) - must be capped at HIGH,
        # never CRITICAL, even when the raw/aggregate number is 80+.
        result = calculate_risk(**_base_kwargs(
            m1={"spf": "pass", "dkim": "neutral", "dmarc": "pass"},
            m2={
                "phishing_probability": 100.0,
                "threat_categories": {"phishing": 100, "suspicious": 100, "spam": 100},
                "rule_based_threats": {"bec": 100},
            },
            header_analysis={"return_path_mismatch": True},
        ))
        assert result["score"] >= 80
        assert result["level"] == "HIGH"
        assert any("capped at HIGH" in r for r in result["reasons"])

    def test_critical_reached_with_independent_evidence(self):
        result = calculate_risk(**_base_kwargs(
            m2={"phishing_probability": 100.0, "threat_categories": {"phishing": 100}},
            m3={"phishtank": [{"listed": True}] * 3},
        ))
        assert result["level"] == "CRITICAL"


# ---------------------------------------------------------------------------
# TASK 2A: calculation breakdown matches the score; raw vs final score
# ---------------------------------------------------------------------------
class TestCalculationBreakdown:
    def test_breakdown_items_sum_to_raw_score(self):
        result = calculate_risk(**_base_kwargs(
            m1={"spf": "fail", "dkim": "pass", "dmarc": "pass"},
            m2={"phishing_probability": 60.0, "threat_categories": {"phishing": 75}},
            header_analysis={"reply_to_mismatch": True},
        ))
        items_sum = sum(i["contribution"] for i in result["calculation"]["items"])
        assert abs(items_sum - result["calculation"]["raw_score"]) < 1e-6

    def test_raw_score_vs_final_score_distinction(self):
        # Raw score can exceed 100 before clamping; final score is
        # always clamped into [0, 100].
        result = calculate_risk(**_base_kwargs(
            m2={"phishing_probability": 100.0, "threat_categories": {"phishing": 100, "suspicious": 100, "spam": 100}},
            m1={"spf": "fail", "dkim": "fail", "dmarc": "fail"},
            header_analysis={"reply_to_mismatch": True, "return_path_mismatch": True},
            m3={"phishtank": [{"listed": True}] * 3, "spamhaus": [{"listed": True}] * 3},
        ))
        assert result["calculation"]["raw_score"] > 100
        assert result["calculation"]["final_score"] == result["score"]
        assert result["score"] == 100

    def test_calculation_is_json_serializable(self):
        import json

        result = calculate_risk(**_base_kwargs(
            m2={"phishing_probability": 42.0, "threat_categories": {}},
        ))
        json.dumps(result)  # must not raise

    def test_thresholds_present_in_breakdown(self):
        result = calculate_risk(**_base_kwargs())
        assert result["calculation"]["thresholds"] == RISK_CONFIG["thresholds"]

    def test_config_version_present(self):
        result = calculate_risk(**_base_kwargs())
        assert "config_version" in result
        assert isinstance(result["config_version"], str)


# ---------------------------------------------------------------------------
# Existing phishing fixture suite must not regress - spot-check via
# calculate_risk() directly (full .eml pipeline covered by
# test_phishing_eml_suite.py).
# ---------------------------------------------------------------------------
class TestNoRegressionSpotChecks:
    def test_bec_reply_to_mismatch_plus_keyword_scan_reaches_medium_or_higher(self):
        result = calculate_risk(**_base_kwargs(
            m1={"spf": "pass", "dkim": "pass", "dmarc": "pass"},
            m2={
                "phishing_probability": 55.0,
                "threat_categories": {},
                "rule_based_threats": {"bec": 60},
            },
            header_analysis={"reply_to_mismatch": True},
        ))
        assert result["level"] in {"MEDIUM", "HIGH", "CRITICAL"}
        assert any("Reply-To" in r for r in result["reasons"])


# ---------------------------------------------------------------------------
# HARDENING: deterministic evidence cannot be neutralized by benign/
# high-confidence ML, and hard overrides are explicit + explainable.
# ---------------------------------------------------------------------------
class TestHardOverrides:
    def test_high_confidence_malicious_attachment_survives_benign_ml(self):
        """A YARA severity=high match must force CRITICAL even when the
        ML model scores the message as completely benign."""
        result = calculate_risk(**_base_kwargs(
            m2={"phishing_probability": 0.0, "threat_categories": {}},
            attachment_analysis={
                "items": [
                    {
                        "filename": "invoice.docm",
                        "flags": ["macro_enabled_document"],
                        "yara": {"matches": [{"rule": "Suspicious_Macro_AutoExec_Shell", "severity": "high"}]},
                    }
                ]
            },
        ))
        assert result["level"] == "CRITICAL"
        assert any(o["override"] == "yara_high_severity_malicious" for o in result["calculation"]["overrides_applied"])
        assert any("Deterministic evidence controlled the final severity" in r for r in result["reasons"])

    def test_medium_severity_yara_gets_high_floor_not_critical_override(self):
        """A medium-severity YARA match is HIGH-grade, not CRITICAL-grade
        - it must reach the documented floor but NOT trigger the
        severity=high-only override."""
        result = calculate_risk(**_base_kwargs(
            m2={"phishing_probability": 0.0, "threat_categories": {}},
            attachment_analysis={
                "items": [
                    {
                        "filename": "bad.exe",
                        "flags": ["executable_or_script_extension"],
                        "yara": {"matches": [{"rule": "Suspicious_Executable_Indicators", "severity": "medium"}]},
                    }
                ]
            },
        ))
        assert result["level"] == "HIGH"
        assert result["score"] >= RISK_CONFIG["floors"]["yara_high_medium_floor"]
        assert result["calculation"]["overrides_applied"] == []

    def test_confirmed_malicious_url_survives_benign_ml(self):
        """A confirmed PhishTank match must force CRITICAL even when
        ML/body scoring is completely benign."""
        result = calculate_risk(**_base_kwargs(
            m2={"phishing_probability": 0.0, "threat_categories": {}},
            m3={"phishtank": [{"listed": True, "url": "http://bad.example.test"}]},
        ))
        assert result["level"] == "CRITICAL"
        assert any(
            o["override"] == "confirmed_malicious_url_threat_intel"
            for o in result["calculation"]["overrides_applied"]
        )

    def test_verified_executable_content_gets_high_floor(self):
        """Magic-byte-confirmed executable content (not just a .exe
        extension) is HIGH-grade evidence on its own, even with no
        YARA match at all."""
        result = calculate_risk(**_base_kwargs(
            m2={"phishing_probability": 0.0, "threat_categories": {}},
            attachment_analysis={
                "items": [
                    {
                        "filename": "tool.exe",
                        "detected_type": "application/x-msdownload",
                        "flags": ["executable_or_script_extension"],
                        "yara": {"matches": []},
                    }
                ]
            },
        ))
        assert result["score"] >= RISK_CONFIG["floors"]["verified_executable_floor"]
        assert result["level"] in {"HIGH", "CRITICAL"}
        assert any(f["floor"] == "verified_executable_floor" for f in result["calculation"]["floors_applied"])

    def test_disguised_executable_forces_critical(self):
        """A file whose real (magic-byte-confirmed) content is an
        executable, disguised behind a non-executable-looking
        filename/extension, is a deliberate evasion pattern and must
        force CRITICAL."""
        result = calculate_risk(**_base_kwargs(
            m2={"phishing_probability": 0.0, "threat_categories": {}},
            attachment_analysis={
                "items": [
                    {
                        "filename": "invoice.pdf.exe",
                        "detected_type": "application/x-msdownload",
                        "flags": ["disguised_double_extension", "executable_or_script_extension"],
                        "yara": {"matches": []},
                    }
                ]
            },
        ))
        assert result["level"] == "CRITICAL"
        assert any(o["override"] == "disguised_malicious_executable" for o in result["calculation"]["overrides_applied"])

    def test_bare_exe_extension_without_content_verification_is_not_overridden(self):
        """A file merely NAMED .exe, with content that is NOT confirmed
        executable by magic bytes (e.g. the synthetic fixture payload
        used in tests/fixtures), must not fabricate a critical
        override - only the additive per-file attachment score
        applies. Matches attachment_analysis.py's documented
        false-positive requirement."""
        result = calculate_risk(**_base_kwargs(
            m2={"phishing_probability": 0.0, "threat_categories": {}},
            attachment_analysis={
                "items": [
                    {
                        "filename": "invoice.pdf.exe",
                        "detected_type": "text/plain",
                        "flags": ["disguised_double_extension", "executable_or_script_extension"],
                        "yara": {"matches": []},
                    }
                ]
            },
        ))
        assert result["calculation"]["overrides_applied"] == []
        assert not any(f["floor"] == "verified_executable_floor" for f in result["calculation"]["floors_applied"])

    def test_strong_lookalike_and_redirect_evidence_remain_visible_with_benign_ml(self):
        result = calculate_risk(**_base_kwargs(
            m2={"phishing_probability": 0.0, "threat_categories": {}},
            m3={
                "local_heuristics": [
                    {"flags": ["brand_lookalike_domain"], "local_score": 30},
                    {"flags": ["redirector_with_nested_destination"], "local_score": 20},
                ]
            },
        ))
        assert result["level"] in {"MEDIUM", "HIGH"}
        assert "Brand Impersonation" in result["threat_types"]
        assert "Malicious Redirect" in result["threat_types"]

    def test_overrides_never_lower_a_score(self):
        """Overrides only ever raise score/level - sanity check that a
        low-evidence message with no override triggers is untouched."""
        result = calculate_risk(**_base_kwargs())
        assert result["calculation"]["overrides_applied"] == []
        assert result["score"] == 0


# ---------------------------------------------------------------------------
# HARDENING: deterministic, combination-based BEC detection.
# ---------------------------------------------------------------------------
class TestBEC:
    def test_single_bec_category_does_not_reach_critical(self):
        """A single BEC phrase category (e.g. one mention of an invoice
        payment instruction) must not, by itself, push a legitimate
        email anywhere near CRITICAL."""
        bec = detect_bec("Please process the attached invoice for payment.")
        result = calculate_risk(**_base_kwargs(
            m2={"phishing_probability": 5.0, "threat_categories": {}},
            bec_analysis=bec,
        ))
        assert result["level"] != "CRITICAL"
        assert result["score"] < RISK_CONFIG["thresholds"]["high_min"]

    def test_bec_combination_raises_severity(self):
        """Executive impersonation + a payment-type request + secrecy
        and urgency together must raise severity meaningfully above a
        single category alone."""
        text = (
            "This is the CEO. I am currently in a meeting and need you "
            "to update the supplier bank account details immediately. "
            "Keep this confidential."
        )
        bec = detect_bec(text)
        assert bec["category_count"] >= 3
        result = calculate_risk(**_base_kwargs(
            m2={"phishing_probability": 5.0, "threat_categories": {}},
            bec_analysis=bec,
        ))
        assert result["level"] in {"MEDIUM", "HIGH"}
        assert result["score"] >= RISK_CONFIG["floors"]["bec_extreme_combo_floor"]
        assert any(f["floor"] == "bec_extreme_combo_floor" for f in result["calculation"]["floors_applied"])

    def test_extreme_bec_with_identity_mismatch_is_critical(self):
        text = (
            "This is the CEO. I am currently in a meeting and need you "
            "to update the supplier bank account details immediately. "
            "Keep this confidential."
        )
        bec = detect_bec(text)
        result = calculate_risk(**_base_kwargs(
            m2={"phishing_probability": 5.0, "threat_categories": {}},
            m1={"spf": "fail", "dkim": "fail", "dmarc": "fail"},
            bec_analysis=bec,
        ))
        assert result["level"] == "CRITICAL"
        assert any(
            o["override"] == "extreme_bec_with_identity_mismatch"
            for o in result["calculation"]["overrides_applied"]
        )

    def test_bec_categories_never_double_counted(self):
        text = (
            "Please update the supplier bank account details. "
            "Please update the supplier bank account details again. "
            "Update the supplier bank account details once more."
        )
        bec = detect_bec(text)
        assert bec["category_count"] == len(bec["categories"])
        # Repeating the same phrase many times must not multiply score.
        result_once = calculate_risk(**_base_kwargs(bec_analysis=detect_bec(
            "Please update the supplier bank account details."
        )))
        result_repeated = calculate_risk(**_base_kwargs(bec_analysis=bec))
        assert result_once["score"] == result_repeated["score"]

    def test_display_name_executive_impersonation_plus_urgent_transfer_request(self):
        """Regression for tests/fixtures/phishing_eml_suite/01_display_name_spoof.eml:
        a spoofed C-level display name ("CEO Office") combined with an
        urgent, one-off transfer request (as opposed to a request to
        CHANGE existing banking details) must be detected and raise
        severity - this is the classic "CEO fraud" wire-request
        pattern, distinct from the payment/bank-change patterns."""
        text = (
            "From: CEO Office <ceo.office@example-attacker.test>\n"
            "Subject: URGENT: confidential transfer request\n\n"
            "I am in a meeting and need a confidential vendor payment "
            "processed immediately. Reply with confirmation that the "
            "transfer has been initiated."
        )
        bec = detect_bec(text)
        assert "executive_impersonation" in bec["categories"]
        assert "wire_ach_change" in bec["categories"]
        result = calculate_risk(**_base_kwargs(bec_analysis=bec))
        assert result["level"] in {"MEDIUM", "HIGH", "CRITICAL"}

    def test_single_impersonation_phrase_alone_does_not_escalate(self):
        """A colleague legitimately saying "I am in a meeting" must not,
        on its own (no payment-type category alongside it), push
        severity up - only the COMBINATION is dangerous."""
        text = "Hey, I am in a meeting right now, can we talk after lunch about the vendor contract renewal?"
        bec = detect_bec(text)
        assert bec["categories"] == {"executive_impersonation": True}
        result = calculate_risk(**_base_kwargs(bec_analysis=bec))
        assert result["level"] == "LOW"

    def test_confidentiality_footer_alone_does_not_escalate(self):
        """A routine invoice/confidentiality-footer style email must
        not escalate from a single BEC-adjacent category."""
        text = (
            "Please see the attached signed NDA. This message is "
            "confidential and intended only for the recipient. Please "
            "process the attached invoice for our records."
        )
        bec = detect_bec(text)
        assert bec["category_count"] == 1
        result = calculate_risk(**_base_kwargs(bec_analysis=bec))
        assert result["level"] == "LOW"


# ---------------------------------------------------------------------------
# HARDENING: normalized threat_types come only from actual evidence.
# ---------------------------------------------------------------------------
class TestThreatTypes:
    def test_no_evidence_no_threat_types(self):
        result = calculate_risk(**_base_kwargs())
        assert result["threat_types"] == []

    def test_high_ml_probability_alone_does_not_create_threat_types(self):
        """Threat types must come from deterministic evidence, never
        from ML probability alone."""
        result = calculate_risk(**_base_kwargs(
            m2={"phishing_probability": 99.9, "threat_categories": {"phishing": 99, "suspicious": 99, "spam": 99}},
        ))
        assert result["threat_types"] == []

    def test_malware_attachment_threat_type_from_yara(self):
        result = calculate_risk(**_base_kwargs(
            attachment_analysis={
                "items": [
                    {
                        "filename": "bad.exe",
                        "flags": ["executable_or_script_extension"],
                        "yara": {"matches": [{"rule": "X", "severity": "medium"}]},
                    }
                ]
            },
        ))
        assert "Malware Attachment" in result["threat_types"]

    def test_authentication_spoofing_threat_type_from_auth_failure(self):
        result = calculate_risk(**_base_kwargs(m1={"spf": "fail", "dkim": "pass", "dmarc": "pass"}))
        assert "Authentication Spoofing" in result["threat_types"]

    def test_threat_intelligence_match_threat_type(self):
        result = calculate_risk(**_base_kwargs(m3={"phishtank": [{"listed": True}]}))
        assert "Threat Intelligence Match" in result["threat_types"]


# ---------------------------------------------------------------------------
# Final score always stays within [0, 100] even under maximal evidence.
# ---------------------------------------------------------------------------
class TestScoreBounds:
    def test_final_score_always_0_to_100_under_maximal_evidence(self):
        bec = detect_bec(
            "This is the CEO. I am currently in a meeting and need you "
            "to update the supplier bank account details immediately. "
            "Keep this confidential. Please wire the funds to the new account."
        )
        result = calculate_risk(**_base_kwargs(
            m1={"spf": "fail", "dkim": "fail", "dmarc": "fail"},
            m2={
                "phishing_probability": 100.0,
                "threat_categories": {"phishing": 100, "suspicious": 100, "spam": 100},
                "rule_based_threats": {"bec": 100, "credential_theft": 100, "financial_fraud": 100},
            },
            m3={
                "phishtank": [{"listed": True}] * 5,
                "spamhaus": [{"listed": True}] * 5,
                "local_heuristics": [
                    {"flags": ["brand_lookalike_domain"], "local_score": 30},
                    {"flags": ["uri_userinfo_obfuscation"], "local_score": 20},
                    {"flags": ["redirector_with_nested_destination"], "local_score": 20},
                ],
            },
            header_analysis={"reply_to_mismatch": True, "return_path_mismatch": True},
            attachment_analysis={
                "items": [
                    {
                        "filename": "invoice.pdf.exe",
                        "detected_type": "application/x-msdownload",
                        "flags": ["disguised_double_extension", "executable_or_script_extension"],
                        "yara": {"matches": [{"rule": "X", "severity": "high"}]},
                    }
                ]
            },
            bec_analysis=bec,
        ))
        assert 0 <= result["score"] <= 100
        assert result["level"] == "CRITICAL"
