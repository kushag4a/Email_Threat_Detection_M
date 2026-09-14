from __future__ import annotations

from pathlib import Path
import sys

PROJECT_ROOT = Path(__file__).resolve().parents[1]

if str(PROJECT_ROOT) not in sys.path:
    sys.path.insert(0, str(PROJECT_ROOT))

from email.utils import parseaddr

import joblib

from backend.app.forensic.m1_header_analyzer import analyze_email as m1_analyze
from backend.app.services.attachment_analysis import analyze_attachments
from backend.app.services.email_parser import parse_rfc822_bytes
from backend.app.services.m1_adapter import prepare_m1_input
from backend.app.services.ml_classifier import (
    build_analysis_text,
)
from backend.app.services.risk_engine import calculate_risk
from backend.app.services.threat_classifier import detect_threats
from backend.app.threat_intel.aggregator import analyze_threat_intelligence




MODEL_DIR = PROJECT_ROOT / "backend" / "app" / "models"
V1_DIR = MODEL_DIR / "v1_current"
V2_DIR = MODEL_DIR / "v2"

FIXTURE_DIR = PROJECT_ROOT / "tests" / "fixtures" / "phishing_eml_suite"


def load_model_pair(model_dir: Path):
    model = joblib.load(model_dir / "phishing_model.pkl")
    vectorizer = joblib.load(model_dir / "phishing_vectorizer.pkl")
    return model, vectorizer


def load_multithreat_v1():
    """
    V2 currently contains only the newly trained phishing model/vectorizer.

    To make this comparison fair and isolate the phishing-model change,
    both V1 and V2 use the SAME existing multithreat model/vectorizer.
    """
    model = joblib.load(V1_DIR / "multithreat_model.pkl")
    vectorizer = joblib.load(V1_DIR / "multithreat_vectorizer.pkl")
    return model, vectorizer


def header_analysis(email) -> dict:
    """
    Exact equivalent of analysis_service._header_analysis().
    Compare actual addresses rather than raw header strings.
    """
    sender = parseaddr(email.sender or "")[1].lower()
    reply_to = parseaddr(email.reply_to or "")[1].lower()
    return_path = parseaddr(email.return_path or "")[1].lower()

    return {
        "reply_to_mismatch": bool(
            reply_to and sender and reply_to != sender
        ),
        "return_path_mismatch": bool(
            return_path and sender and return_path != sender
        ),
    }


def classify_with_model(
    analysis_text: str,
    phishing_model,
    phishing_vectorizer,
    multithreat_model,
    multithreat_vectorizer,
    force_rule_based: bool,
) -> dict:
    """
    Reproduce the current classify_email() behavior while allowing
    us to inject either V1 or V2 phishing model.

    Multithreat model is deliberately shared between both runs because
    V2 currently provides only phishing_model.pkl + phishing_vectorizer.pkl.
    """

    phishing_vector = phishing_vectorizer.transform([analysis_text])
    phishing_probabilities = phishing_model.predict_proba(phishing_vector)[0]

    safe_probability = float(phishing_probabilities[0])
    phishing_probability = float(phishing_probabilities[1])

    threat_vector = multithreat_vectorizer.transform([analysis_text])
    threat_probabilities = multithreat_model.predict_proba(threat_vector)[0]
    threat_classes = multithreat_model.classes_

    threat_categories = {
        category: round(float(probability) * 100, 2)
        for category, probability in zip(
            threat_classes,
            threat_probabilities,
        )
    }

    # Current ml_classifier.py behavior:
    # rule-based detection ALWAYS runs. The attachment flag only
    # controls the informational forensics_triggered state.
    forensics_triggered = (
        phishing_probability >= 0.40 or force_rule_based
    )

    rule_based_threats = detect_threats(analysis_text)

    if not threat_categories:
        top_category = "unknown"
        top_probability = 0.0
    else:
        top_category = max(
            threat_categories,
            key=threat_categories.get,
        )
        top_probability = threat_categories[top_category] / 100.0

    return {
        "safe_probability": round(safe_probability * 100, 2),
        "phishing_probability": round(phishing_probability * 100, 2),
        "threat_categories": threat_categories,
        "rule_based_threats": rule_based_threats,
        "top_classification": {
            "label": top_category,
            "probability": top_probability,
        },
        "forensics_triggered": forensics_triggered,
        "forensics_forced_by_attachment": (
            force_rule_based and phishing_probability < 0.40
        ),
    }


def run_common_pipeline(email):
    """
    Run every non-ML stage once.

    These outputs are then reused for both V1 and V2 so the comparison
    changes only the phishing classifier.
    """

    # ------------------------------------------------------------
    # Attachments FIRST
    # ------------------------------------------------------------
    attachment_result = analyze_attachments(
        [a.model_dump() for a in email.attachments]
    )

    # ------------------------------------------------------------
    # M1
    # ------------------------------------------------------------
    m1_input = prepare_m1_input(email)
    m1_result = m1_analyze(m1_input.model_dump())
    header_result = header_analysis(email)

    # ------------------------------------------------------------
    # M3
    # ------------------------------------------------------------
    ips = (
        [m1_result["origin_ip"]]
        if m1_result.get("origin_ip")
        else []
    )

    m3_result = analyze_threat_intelligence(
        ips=ips,
        urls=email.urls,
    )

    # ------------------------------------------------------------
    # M4
    # ------------------------------------------------------------
    # The real analysis_service deliberately defers geolocation.
    # Therefore there is no synchronous geo lookup here.
    geo_results = []

    return {
        "attachment_result": attachment_result,
        "m1_result": m1_result,
        "header_result": header_result,
        "m3_result": m3_result,
        "geo_results": geo_results,
    }


def run_pipeline_variant(
    email,
    analysis_text: str,
    common: dict,
    phishing_model,
    phishing_vectorizer,
    multithreat_model,
    multithreat_vectorizer,
) -> dict:

    attachment_result = common["attachment_result"]
    m1_result = common["m1_result"]
    header_result = common["header_result"]
    m3_result = common["m3_result"]

    # ------------------------------------------------------------
    # M2
    # ------------------------------------------------------------
    m2_result = classify_with_model(
        analysis_text=analysis_text,
        phishing_model=phishing_model,
        phishing_vectorizer=phishing_vectorizer,
        multithreat_model=multithreat_model,
        multithreat_vectorizer=multithreat_vectorizer,
        force_rule_based=attachment_result["has_high_severity"],
    )

    # ------------------------------------------------------------
    # Risk engine
    # ------------------------------------------------------------
    risk = calculate_risk(
        m1=m1_result,
        m2=m2_result,
        m3=m3_result,
        header_analysis=header_result,
        attachment_analysis=attachment_result,
    )

    return {
        "m2": m2_result,
        "risk": risk,
    }


def print_common_evidence(common: dict):
    attachment_result = common["attachment_result"]
    m1_result = common["m1_result"]
    header_result = common["header_result"]
    m3_result = common["m3_result"]

    listed_urls = [
        item
        for item in m3_result.get("phishtank", [])
        if item.get("listed")
    ]

    listed_ips = [
        item
        for item in m3_result.get("spamhaus", [])
        if item.get("listed")
    ]

    heuristics = m3_result.get("local_heuristics", [])

    print("  COMMON PIPELINE EVIDENCE")
    print(f"    SPF:                 {m1_result.get('spf')}")
    print(f"    DKIM:                {m1_result.get('dkim')}")
    print(f"    DMARC:               {m1_result.get('dmarc')}")
    print(
        f"    Origin IP:           "
        f"{m1_result.get('origin_ip') or 'None'}"
    )
    print(
        f"    Reply-To mismatch:   "
        f"{header_result.get('reply_to_mismatch')}"
    )
    print(
        f"    Return-Path mismatch:{header_result.get('return_path_mismatch')}"
    )
    print(
    f"    URLs extracted:      "
    f"{len(common['_email'].urls)}"
)
    print(
        f"    Attachments:         "
        f"{len(attachment_result.get('items', []))}"
    )
    print(
        f"    Attachment scan:     "
        f"{attachment_result.get('scanned')}"
    )
    print(
        f"    High attachment:     "
        f"{attachment_result.get('has_high_severity')}"
    )
    print(f"    PhishTank matches:   {len(listed_urls)}")
    print(f"    Spamhaus matches:    {len(listed_ips)}")
    print(f"    Local heuristics:    {len(heuristics)}")


def print_variant(name: str, result: dict):
    m2 = result["m2"]
    risk = result["risk"]

    print(f"\n  {name}")
    print(
        f"    ML phishing:         "
        f"{m2['phishing_probability']:.2f}%"
    )
    print(
        f"    ML safe:             "
        f"{m2['safe_probability']:.2f}%"
    )

    threat_categories = m2.get("threat_categories", {})
    if threat_categories:
        formatted = ", ".join(
            f"{k}={v:.2f}%"
            for k, v in sorted(threat_categories.items())
        )
        print(f"    Threat categories:   {formatted}")

    print(
        f"    Rule-based threats:  "
        f"{m2.get('rule_based_threats') or {}}"
    )

    print(
        f"    Risk score:          "
        f"{risk['score']}/100"
    )
    print(
        f"    Risk level:          "
        f"{risk['level']}"
    )

    print(
        f"    Risk modules:        "
        f"{', '.join(risk.get('contributing_modules', [])) or 'None'}"
    )

    print("    Reasons:")
    for reason in risk.get("reasons", []):
        print(f"      - {reason}")


def main():
    if not FIXTURE_DIR.exists():
        print(f"ERROR: Fixture directory not found:\n{FIXTURE_DIR}")
        sys.exit(1)

    fixtures = sorted(FIXTURE_DIR.glob("*.eml"))

    if len(fixtures) != 8:
        print(
            f"WARNING: Expected 8 fixtures, found {len(fixtures)}"
        )

    print("=" * 110)
    print("V1 vs V2 — FULL VALORPROTECTS PIPELINE SHADOW TEST")
    print("=" * 110)
    print(f"Fixture directory: {FIXTURE_DIR}")
    print(f"Fixtures found:    {len(fixtures)}")
    print()
    print(
        "IMPORTANT: V1 and V2 share the same M1, M3, attachment, "
        "rule-based, and multithreat stages."
    )
    print(
        "Only the phishing_model.pkl + phishing_vectorizer.pkl pair "
        "changes between V1 and V2."
    )
    print()

    # ------------------------------------------------------------
    # Load models
    # ------------------------------------------------------------
    v1_phishing_model, v1_phishing_vectorizer = load_model_pair(V1_DIR)
    v2_phishing_model, v2_phishing_vectorizer = load_model_pair(V2_DIR)

    multithreat_model, multithreat_vectorizer = load_multithreat_v1()

    summary_rows = []

    for fixture in fixtures:
        print("\n" + "=" * 110)
        print(fixture.name)
        print("=" * 110)

        try:
            raw_bytes = fixture.read_bytes()

            email = parse_rfc822_bytes(
                raw_bytes,
                provider="fixture",
                message_id=fixture.stem,
            )

            analysis_text = build_analysis_text(email)

            common = run_common_pipeline(email)

            # Store email temporarily for URL count display.
            common["_email"] = email

            print_common_evidence(common)

            v1_result = run_pipeline_variant(
                email=email,
                analysis_text=analysis_text,
                common=common,
                phishing_model=v1_phishing_model,
                phishing_vectorizer=v1_phishing_vectorizer,
                multithreat_model=multithreat_model,
                multithreat_vectorizer=multithreat_vectorizer,
            )

            v2_result = run_pipeline_variant(
                email=email,
                analysis_text=analysis_text,
                common=common,
                phishing_model=v2_phishing_model,
                phishing_vectorizer=v2_phishing_vectorizer,
                multithreat_model=multithreat_model,
                multithreat_vectorizer=multithreat_vectorizer,
            )

            print_variant("V1 RESULT", v1_result)
            print_variant("V2 RESULT", v2_result)

            v1_risk = v1_result["risk"]
            v2_risk = v2_result["risk"]

            changed = (
                v1_risk["score"] != v2_risk["score"]
                or v1_risk["level"] != v2_risk["level"]
            )

            summary_rows.append(
                {
                    "fixture": fixture.name,
                    "v1_ml": v1_result["m2"]["phishing_probability"],
                    "v2_ml": v2_result["m2"]["phishing_probability"],
                    "v1_score": v1_risk["score"],
                    "v2_score": v2_risk["score"],
                    "v1_level": v1_risk["level"],
                    "v2_level": v2_risk["level"],
                    "changed": changed,
                }
            )

        except Exception as exc:
            print(f"\nERROR processing {fixture.name}: {exc}")

    # ------------------------------------------------------------
    # Final summary
    # ------------------------------------------------------------
    print("\n\n" + "=" * 110)
    print("FINAL COMPARISON SUMMARY")
    print("=" * 110)

    print(
        f"{'Fixture':35} "
        f"{'V1 ML':>8} "
        f"{'V2 ML':>8} "
        f"{'V1 Risk':>10} "
        f"{'V2 Risk':>10} "
        f"{'V1':>9} "
        f"{'V2':>9}"
    )

    print("-" * 110)

    for row in summary_rows:
        print(
            f"{row['fixture'][:35]:35} "
            f"{row['v1_ml']:7.2f}% "
            f"{row['v2_ml']:7.2f}% "
            f"{row['v1_score']:>3}/100 {row['v1_level']:<6} "
            f"{row['v2_score']:>3}/100 {row['v2_level']:<6}"
        )

    print("\nLegend:")
    print("  V1 ML  = V1 phishing-model probability")
    print("  V2 ML  = V2 phishing-model probability")
    print("  V1 Risk = full pipeline risk using V1 phishing model")
    print("  V2 Risk = full pipeline risk using V2 phishing model")
    print()
    print(
        "No production model was changed. This script is a shadow/offline comparison."
    )


if __name__ == "__main__":
    main()