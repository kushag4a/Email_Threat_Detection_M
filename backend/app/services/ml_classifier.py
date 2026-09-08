"""
M2 - AI / phishing / threat classification.

Reuses the already-trained models exactly as they were:
phishing_model.pkl / phishing_vectorizer.pkl and
multithreat_model.pkl / multithreat_vectorizer.pkl (from
gmail_pipeline.py), plus the rule-based keyword classifier
(threat_classifier.py). No new ML was introduced.

Models are loaded once at import time, matching the original
gmail_pipeline.py behavior.
"""

from pathlib import Path

import joblib

from backend.app.services.threat_classifier import detect_threats

MODELS_DIR = Path(__file__).parent.parent / "models"

_phishing_model = joblib.load(MODELS_DIR / "phishing_model.pkl")
_phishing_vectorizer = joblib.load(MODELS_DIR / "phishing_vectorizer.pkl")

_multithreat_model = joblib.load(MODELS_DIR / "multithreat_model.pkl")
_multithreat_vectorizer = joblib.load(MODELS_DIR / "multithreat_vectorizer.pkl")

# Forensics/rule-based threat scoring only runs above this phishing
# probability, matching the original gmail_pipeline.py threshold.
FORENSICS_TRIGGER_THRESHOLD = 0.40


def classify_email(analysis_text: str, *, force_rule_based: bool = False) -> dict:
    """
    force_rule_based=True (set by the orchestrator when
    attachment_analysis.has_high_severity is True) makes this run the
    deeper rule-based keyword scan even if the ML phishing probability
    is below FORENSICS_TRIGGER_THRESHOLD. This is the "conditional"
    half of the attachment-first/conditional canonical order: a
    suspicious attachment can only ever add scanning, never remove it.
    """
    phishing_vector = _phishing_vectorizer.transform([analysis_text])
    phishing_probabilities = _phishing_model.predict_proba(phishing_vector)[0]

    safe_probability = float(phishing_probabilities[0])
    phishing_probability = float(phishing_probabilities[1])

    threat_vector = _multithreat_vectorizer.transform([analysis_text])
    threat_probabilities = _multithreat_model.predict_proba(threat_vector)[0]
    threat_classes = _multithreat_model.classes_

    threat_categories = {
        category: round(float(probability) * 100, 2)
        for category, probability in zip(threat_classes, threat_probabilities)
    }

    forensics_triggered = phishing_probability >= FORENSICS_TRIGGER_THRESHOLD or force_rule_based

    rule_based_threats = {}
    if forensics_triggered:
        rule_based_threats = detect_threats(analysis_text)

    top_category = max(threat_categories, key=threat_categories.get)

    return {
        "safe_probability": round(safe_probability * 100, 2),
        "phishing_probability": round(phishing_probability * 100, 2),
        "threat_categories": threat_categories,
        "rule_based_threats": rule_based_threats,
        "top_classification": {
            "label": top_category,
            "probability": threat_categories[top_category] / 100,
        },
        "forensics_triggered": forensics_triggered,
        "forensics_forced_by_attachment": force_rule_based and phishing_probability < FORENSICS_TRIGGER_THRESHOLD,
    }


def build_analysis_text(email) -> str:
    """Matches the text gmail_pipeline.py fed to the models."""
    return (
        f"From: {email.sender}\n"
        f"Reply-To: {email.reply_to or ''}\n"
        f"Return-Path: {email.return_path or ''}\n"
        f"Subject: {email.subject}\n\n"
        f"{email.body}"
    )
