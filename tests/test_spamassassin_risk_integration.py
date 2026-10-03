"""
Focused tests for wiring the isolated SpamAssassin adapter's evidence
(`backend.app.spam.SpamAssassinResult`) into the unified risk engine
(`backend/app/services/risk_engine.py`) as a SMALL, OPTIONAL,
CONFIGURABLE SUPPORTING SIGNAL - see RISK_CONFIG["spamassassin"] and
the "SpamAssassin" section of calculate_risk().

Scope / what these tests guard:
    A. Disabled (no result, or this engine's own spamassassin.enabled
       flag off) -> zero contribution.
    B. Unavailable (`available=False`) -> zero contribution.
    C. Low/below-threshold spam score -> zero contribution.
    D. Above-threshold score -> positive, formula-accurate contribution.
    E. Contribution is capped at the configured maximum.
    F. An extremely high SpamAssassin score cannot, by itself, reach
       CRITICAL (or even HIGH) - the cap keeps it a minor signal.
    G. SpamAssassin cannot override/weaken a YARA HIGH/CRITICAL result.
    H. SpamAssassin cannot override/weaken a confirmed threat-intel
       (PhishTank) CRITICAL result.
    I. SpamAssassin cannot override/weaken a serious BEC CRITICAL
       result.
    J. The explanation/evidence structure (`calculation`) always
       surfaces the SpamAssassin signal distinctly, with its score,
       threshold, and matched rules preserved.
    K. Baseline risk-engine behavior (no `spamassassin` argument at
       all, matching every pre-existing caller/test) is completely
       unaffected - see `TestBackwardCompatibility` below.

These tests exercise `calculate_risk()` directly and construct the
SpamAssassin evidence dict inline (matching
`SpamAssassinResult.model_dump()`'s shape) rather than importing
`backend.app.spam`, and construct any BEC evidence needed for the
override-priority tests (G/H/I) as a plain dict in the same shape
`bec_detector.detect_bec()` returns, rather than importing
`bec_detector` - so this file has no dependency on `pydantic`,
`backend.app.spam`, or `backend.app.services.bec_detector`, and runs
in complete isolation, exactly like the rest of the risk-engine test
suite is intended to.
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


def _sa(**overrides):
    """Build a SpamAssassin evidence dict matching
    `SpamAssassinResult.model_dump()`'s shape, with sane defaults for a
    successful, non-spam result."""
    result = dict(
        available=True,
        score=2.0,
        threshold=5.0,
        is_spam=False,
        matched_rules=[],
        raw_status=None,
        error=None,
        engine="spamassassin",
    )
    result.update(overrides)
    return result


SA_CFG = RISK_CONFIG["spamassassin"]


# ---------------------------------------------------------------------------
# A. Disabled -> zero contribution
# ---------------------------------------------------------------------------
class TestDisabled:
    def test_no_spamassassin_result_is_zero_contribution(self):
        result = calculate_risk(**_base_kwargs(spamassassin=None))
        assert result["score"] == 0
        assert result["calculation"]["spamassassin_contribution"] == 0
        assert "SpamAssassin" not in result["contributing_modules"]

    def test_engine_level_disabled_flag_zeroes_contribution_even_with_high_score(self):
        sa = _sa(score=50.0, threshold=5.0, is_spam=True)
        override_config = copy.deepcopy(RISK_CONFIG)
        override_config["spamassassin"]["enabled"] = False
        result = calculate_risk(**_base_kwargs(spamassassin=sa), config=override_config)
        assert result["score"] == 0
        assert result["calculation"]["spamassassin_contribution"] == 0
        assert "SpamAssassin" not in result["contributing_modules"]
        # Disabling the score contribution must not silently disable the
        # rest of the engine either.
        assert result["level"] == "LOW"


# ---------------------------------------------------------------------------
# B. Unavailable / errored / timeout -> zero contribution
# ---------------------------------------------------------------------------
class TestUnavailableOrErrored:
    def test_unavailable_is_zero_contribution(self):
        sa = _sa(available=False, score=None, threshold=None, is_spam=None, error="spamassassin executable 'spamassassin' was not found")
        result = calculate_risk(**_base_kwargs(spamassassin=sa))
        assert result["score"] == 0
        assert result["calculation"]["spamassassin_contribution"] == 0

    def test_execution_error_is_zero_contribution(self):
        sa = _sa(available=True, score=None, threshold=None, is_spam=None, error="spamassassin exited with code 1: boom")
        result = calculate_risk(**_base_kwargs(spamassassin=sa))
        assert result["score"] == 0
        assert result["calculation"]["spamassassin_contribution"] == 0

    def test_timeout_is_zero_contribution(self):
        sa = _sa(available=True, score=None, threshold=None, is_spam=None, error="spamassassin timed out after 15.0s")
        result = calculate_risk(**_base_kwargs(spamassassin=sa))
        assert result["score"] == 0
        assert result["calculation"]["spamassassin_contribution"] == 0

    def test_none_score_with_no_error_is_zero_contribution(self):
        """Defense in depth: even if `available=True`/`error=None` but
        `score` is somehow `None`, no contribution is made."""
        sa = _sa(available=True, error=None, score=None, threshold=None, is_spam=None)
        result = calculate_risk(**_base_kwargs(spamassassin=sa))
        assert result["score"] == 0
        assert result["calculation"]["spamassassin_contribution"] == 0


# ---------------------------------------------------------------------------
# C. Below-threshold score -> zero/minimal contribution
# ---------------------------------------------------------------------------
class TestBelowThreshold:
    def test_score_below_threshold_contributes_nothing(self):
        sa = _sa(score=1.0, threshold=5.0, is_spam=False)
        result = calculate_risk(**_base_kwargs(spamassassin=sa))
        assert result["calculation"]["spamassassin_contribution"] == 0
        assert result["score"] == 0

    def test_score_exactly_at_threshold_contributes_nothing(self):
        sa = _sa(score=5.0, threshold=5.0, is_spam=False)
        result = calculate_risk(**_base_kwargs(spamassassin=sa))
        assert result["calculation"]["spamassassin_contribution"] == 0


# ---------------------------------------------------------------------------
# D. Above-threshold score -> positive, formula-accurate contribution
# ---------------------------------------------------------------------------
class TestAboveThreshold:
    def test_above_threshold_contribution_matches_formula(self):
        sa = _sa(score=8.0, threshold=5.0, is_spam=True)  # 3 points above threshold
        result = calculate_risk(**_base_kwargs(spamassassin=sa))
        multiplier = SA_CFG["score_multiplier"]
        expected = min(3.0 * multiplier, SA_CFG["max_contribution"])
        assert abs(result["calculation"]["spamassassin_contribution"] - expected) < 1e-6
        assert result["score"] == round(expected)
        assert "SpamAssassin" in result["contributing_modules"]

    def test_missing_message_threshold_falls_back_to_configured_default(self):
        default_threshold = SA_CFG["default_score_threshold"]
        sa = _sa(score=default_threshold + 2.0, threshold=None, is_spam=True)
        result = calculate_risk(**_base_kwargs(spamassassin=sa))
        expected = min(2.0 * SA_CFG["score_multiplier"], SA_CFG["max_contribution"])
        assert abs(result["calculation"]["spamassassin_contribution"] - expected) < 1e-6

    def test_custom_multiplier_and_threshold_via_config_override(self):
        sa = _sa(score=20.0, threshold=10.0, is_spam=True)  # 10 points above threshold
        override_config = copy.deepcopy(RISK_CONFIG)
        override_config["spamassassin"]["score_multiplier"] = 0.5
        override_config["spamassassin"]["max_contribution"] = 100  # effectively uncapped for this test
        result = calculate_risk(**_base_kwargs(spamassassin=sa), config=override_config)
        assert abs(result["calculation"]["spamassassin_contribution"] - 5.0) < 1e-6

    def test_is_spam_true_adds_spam_threat_type_only(self):
        sa = _sa(score=15.0, threshold=5.0, is_spam=True)
        result = calculate_risk(**_base_kwargs(spamassassin=sa))
        assert result["threat_types"] == ["Spam"]

    def test_is_spam_false_never_adds_spam_threat_type(self):
        sa = _sa(score=15.0, threshold=5.0, is_spam=False)
        result = calculate_risk(**_base_kwargs(spamassassin=sa))
        assert "Spam" not in result["threat_types"]


# ---------------------------------------------------------------------------
# E. Contribution is capped
# ---------------------------------------------------------------------------
class TestMaximumContributionCapped:
    def test_very_high_score_is_capped_at_configured_maximum(self):
        sa = _sa(score=1000.0, threshold=5.0, is_spam=True)
        result = calculate_risk(**_base_kwargs(spamassassin=sa))
        cap = SA_CFG["max_contribution"]
        assert result["calculation"]["spamassassin_contribution"] == cap
        assert result["score"] == cap
        cap_entries = [
            c for c in result["calculation"]["caps_applied"] if c["cap"] == "spamassassin_max"
        ]
        assert cap_entries
        assert cap_entries[0]["clamped_value"] == cap

    def test_default_cap_is_five_points(self):
        """RECOMMENDED DEFAULT per the integration spec: max
        contribution = 5 risk points, unless the repository has a
        clear, separately-documented reason to exceed it."""
        assert SA_CFG["max_contribution"] == 5


# ---------------------------------------------------------------------------
# F. Extremely high SpamAssassin score cannot trigger CRITICAL (or even
#    HIGH) by itself.
# ---------------------------------------------------------------------------
class TestCannotSelfEscalate:
    def test_extreme_score_alone_stays_low(self):
        sa = _sa(score=1000.0, threshold=5.0, is_spam=True)
        result = calculate_risk(**_base_kwargs(spamassassin=sa))
        assert result["level"] == "LOW"
        assert result["score"] < RISK_CONFIG["thresholds"]["medium_min"]

    def test_extreme_score_combined_with_moderate_other_evidence_does_not_reach_critical(self):
        sa = _sa(score=1000.0, threshold=5.0, is_spam=True)
        result = calculate_risk(**_base_kwargs(
            spamassassin=sa,
            m2={"phishing_probability": 60.0, "threat_categories": {}},
        ))
        assert result["level"] != "CRITICAL"


# ---------------------------------------------------------------------------
# G. Cannot override deterministic YARA HIGH/CRITICAL evidence
# ---------------------------------------------------------------------------
class TestCannotOverrideYara:
    def test_yara_critical_override_unaffected_by_spamassassin(self):
        sa = _sa(score=1000.0, threshold=5.0, is_spam=True)
        without_sa = calculate_risk(**_base_kwargs(
            attachment_analysis={
                "items": [
                    {
                        "filename": "invoice.docm",
                        "flags": ["macro_enabled_document"],
                        "yara": {"matches": [{"rule": "X", "severity": "high"}]},
                    }
                ]
            },
        ))
        with_sa = calculate_risk(**_base_kwargs(
            spamassassin=sa,
            attachment_analysis={
                "items": [
                    {
                        "filename": "invoice.docm",
                        "flags": ["macro_enabled_document"],
                        "yara": {"matches": [{"rule": "X", "severity": "high"}]},
                    }
                ]
            },
        ))
        assert without_sa["level"] == "CRITICAL"
        assert with_sa["level"] == "CRITICAL"
        assert any(
            o["override"] == "yara_high_severity_malicious" for o in with_sa["calculation"]["overrides_applied"]
        )
        # SpamAssassin never introduces an override/floor of its own.
        sa_related_overrides = [
            o for o in with_sa["calculation"]["overrides_applied"] if "spamassassin" in o["override"].lower()
        ]
        sa_related_floors = [
            f for f in with_sa["calculation"]["floors_applied"] if "spamassassin" in f["floor"].lower()
        ]
        assert sa_related_overrides == []
        assert sa_related_floors == []


# ---------------------------------------------------------------------------
# H. Cannot override confirmed threat-intelligence evidence
# ---------------------------------------------------------------------------
class TestCannotOverrideThreatIntel:
    def test_phishtank_critical_override_unaffected_by_spamassassin(self):
        sa = _sa(score=1000.0, threshold=5.0, is_spam=True)
        result = calculate_risk(**_base_kwargs(
            spamassassin=sa,
            m3={"phishtank": [{"listed": True, "url": "http://bad.example.test"}]},
        ))
        assert result["level"] == "CRITICAL"
        assert any(
            o["override"] == "confirmed_malicious_url_threat_intel"
            for o in result["calculation"]["overrides_applied"]
        )


# ---------------------------------------------------------------------------
# I. Cannot override serious BEC evidence
# ---------------------------------------------------------------------------
class TestCannotOverrideBec:
    """Builds the BEC evidence dict directly (in the same shape
    `bec_detector.detect_bec()` returns) rather than importing the BEC
    detector, since this file must not depend on it."""

    _SERIOUS_BEC = {
        "categories": {
            "executive_impersonation": True,
            "supplier_banking_change": True,
            "secrecy_urgency": True,
        },
        "category_count": 3,
    }

    def test_bec_extreme_combo_floor_unaffected_by_spamassassin(self):
        sa = _sa(score=1000.0, threshold=5.0, is_spam=True)
        result = calculate_risk(**_base_kwargs(
            spamassassin=sa,
            m2={"phishing_probability": 5.0, "threat_categories": {}},
            bec_analysis=self._SERIOUS_BEC,
        ))
        assert result["score"] >= RISK_CONFIG["floors"]["bec_extreme_combo_floor"]
        assert any(
            f["floor"] == "bec_extreme_combo_floor" for f in result["calculation"]["floors_applied"]
        )

    def test_bec_critical_override_with_identity_mismatch_unaffected_by_spamassassin(self):
        sa = _sa(score=1000.0, threshold=5.0, is_spam=True)
        result = calculate_risk(**_base_kwargs(
            spamassassin=sa,
            m1={"spf": "fail", "dkim": "fail", "dmarc": "fail"},
            m2={"phishing_probability": 5.0, "threat_categories": {}},
            bec_analysis=self._SERIOUS_BEC,
        ))
        assert result["level"] == "CRITICAL"
        assert any(
            o["override"] == "extreme_bec_with_identity_mismatch"
            for o in result["calculation"]["overrides_applied"]
        )


# ---------------------------------------------------------------------------
# J. Explanation/evidence structure always surfaces the signal distinctly
# ---------------------------------------------------------------------------
class TestExplainability:
    def test_calculation_contains_distinct_spamassassin_item(self):
        sa = _sa(score=9.0, threshold=5.0, is_spam=True, matched_rules=["BAYES_99", "HTML_MESSAGE"])
        result = calculate_risk(**_base_kwargs(spamassassin=sa))
        item = next(
            i for i in result["calculation"]["items"] if i["signal"] == "SpamAssassin spam score"
        )
        assert item["input"] == 9.0
        assert item["multiplier"] == SA_CFG["score_multiplier"]
        assert item["threshold"] == 5.0
        assert item["matched_rules"] == ["BAYES_99", "HTML_MESSAGE"]
        assert item["is_spam"] is True
        assert item["engine"] == "spamassassin"
        assert item["contribution"] > 0

    def test_calculation_shows_item_even_when_contribution_is_zero(self):
        """Explainability must show that SpamAssassin ran even when it
        didn't move the score, not just when it did."""
        sa = _sa(score=1.0, threshold=5.0, is_spam=False)
        result = calculate_risk(**_base_kwargs(spamassassin=sa))
        item = next(
            i for i in result["calculation"]["items"] if i["signal"] == "SpamAssassin spam score"
        )
        assert item["contribution"] == 0

    def test_calculation_exposes_before_and_after_spamassassin(self):
        sa = _sa(score=9.0, threshold=5.0, is_spam=True)
        result = calculate_risk(**_base_kwargs(
            m2={"phishing_probability": 50.0, "threat_categories": {}},
            spamassassin=sa,
        ))
        calc = result["calculation"]
        assert calc["score_before_spamassassin"] + calc["spamassassin_contribution"] == calc["raw_score"]

    def test_no_calculation_item_when_no_result_supplied(self):
        result = calculate_risk(**_base_kwargs())
        assert not any(
            i["signal"] == "SpamAssassin spam score" for i in result["calculation"]["items"]
        )


# ---------------------------------------------------------------------------
# K. Backward compatibility: omitting `spamassassin` entirely (every
#    pre-existing call site/test) is completely unaffected.
# ---------------------------------------------------------------------------
class TestBackwardCompatibility:
    def test_omitting_spamassassin_argument_entirely_still_works(self):
        # Mirrors test_risk_engine_config.py's/test_risk_scoring_safety.py's
        # calling convention, which never passes `spamassassin=`.
        result = calculate_risk(
            m1={"spf": "pass", "dkim": "pass", "dmarc": "pass"},
            m2={"phishing_probability": 0, "threat_categories": {}},
            m3={},
            header_analysis={},
            attachment_analysis={"items": []},
        )
        assert result["score"] == 0
        assert result["level"] == "LOW"
        assert result["reasons"] == ["No significant risk indicators found"]

    def test_high_ai_without_independent_evidence_is_not_critical(self):
        """Spot-check straight from test_risk_scoring_safety.py, run
        with no `spamassassin` argument, to confirm this addition does
        not disturb existing hardening behavior."""
        result = calculate_risk(**_base_kwargs(
            m2={"phishing_probability": 99.97, "threat_categories": {"spam": 90}},
        ))
        assert result["score"] >= 40
        assert result["level"] != "CRITICAL"

    def test_config_version_bumped(self):
        from backend.app.services.risk_engine import RISK_CONFIG_VERSION

        assert RISK_CONFIG_VERSION == "1.2.0"

    def test_partial_config_override_still_carries_spamassassin_section(self):
        """A caller overriding only an unrelated section (e.g.
        "weights") must not lose the spamassassin defaults - the merge
        in `_cfg()` is additive per top-level section."""
        result = calculate_risk(**_base_kwargs(
            spamassassin=_sa(score=9.0, threshold=5.0, is_spam=True),
        ), config={"weights": {"spf_fail": 100}})
        assert result["calculation"]["spamassassin_contribution"] > 0
