"""
Tests for the centralized, configurable risk-scoring policy
(RISK_CONFIG) and the explainable calculation breakdown returned by
calculate_risk() - see TASK 2/2A/2B/2C/2D/2E in PROJECT_CONTEXT.
"""
from __future__ import annotations

import copy

from backend.app.services.risk_engine import RISK_CONFIG, calculate_risk


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
    def test_phishtank_capped_at_configured_max(self):
        result = calculate_risk(**_base_kwargs(
            m3={"phishtank": [{"listed": True}] * 5},  # 5 * 20 = 100 raw
        ))
        cap = RISK_CONFIG["caps"]["phishtank_max"]
        assert result["score"] == cap
        cap_entries = [c for c in result["calculation"]["caps_applied"] if c["cap"] == "phishtank_max"]
        assert cap_entries
        assert cap_entries[0]["clamped_value"] == cap
        assert cap_entries[0]["raw_value"] == 100

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
