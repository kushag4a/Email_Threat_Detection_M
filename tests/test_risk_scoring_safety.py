from backend.app.services.risk_engine import calculate_risk
from backend.app.threat_intel.local_engine import analyze_url


def _risk(*, m1=None, m2=None, m3=None, header=None, attachment=None):
    return calculate_risk(
        m1=m1 or {"spf": "pass", "dkim": "pass", "dmarc": "pass"},
        m2=m2 or {"phishing_probability": 0, "threat_categories": {}},
        m3=m3 or {},
        header_analysis=header or {},
        attachment_analysis=attachment or {"items": []},
    )


def test_high_ai_without_independent_evidence_is_not_critical():
    result = _risk(
        m2={
            "phishing_probability": 99.97,
            "threat_categories": {"spam": 90},
        }
    )
    assert result["score"] >= 40
    assert result["level"] != "CRITICAL"


def test_redirector_on_known_esp_is_not_flagged_by_local_heuristic():
    result = analyze_url(
        "https://post.pinterest.com/f/click?url=https%3A%2F%2Fwww.pinterest.com%2Fpin%2F12345"
    )
    assert "redirector_with_nested_destination" not in result["flags"]


def test_brand_lookalike_can_reach_medium_without_double_counting():
    result = _risk(
        m2={"phishing_probability": 29.0, "threat_categories": {}},
        m3={
            "local_heuristics": [
                {
                    "flags": ["brand_lookalike_domain"],
                    "local_score": 30,
                }
            ]
        },
    )
    assert result["level"] in {"MEDIUM", "HIGH"}


def test_uri_obfuscation_can_reach_medium_without_becoming_critical_alone():
    result = _risk(
        m2={"phishing_probability": 29.0, "threat_categories": {}},
        m3={
            "local_heuristics": [
                {
                    "flags": ["userinfo_in_url", "uri_userinfo_obfuscation"],
                    "local_score": 20,
                }
            ]
        },
    )
    assert result["level"] in {"MEDIUM", "HIGH"}
    assert result["level"] != "CRITICAL"


def test_redirect_signal_plus_reply_to_mismatch_reaches_medium():
    result = _risk(
        m2={"phishing_probability": 6.0, "threat_categories": {}},
        m3={
            "local_heuristics": [
                {
                    "flags": ["redirector_with_nested_destination"],
                    "local_score": 20,
                }
            ]
        },
        header={"reply_to_mismatch": True},
    )
    assert result["level"] in {"MEDIUM", "HIGH"}
