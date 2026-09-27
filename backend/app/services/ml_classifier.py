"""
AI-based email classification.

Production phishing detection uses the V2 model.
The separate multithreat classifier remains the V1 snapshot in
models/v1_current because no newer multithreat model was promoted.
"""

from pathlib import Path
import re
from html.parser import HTMLParser

import joblib

from backend.app.services.threat_classifier import detect_threats


MODELS_DIR = Path(__file__).parent.parent / "models"

# V2 is the production phishing model.
PHISHING_MODEL_DIR = MODELS_DIR / "v2"

# The multithreat model has not been replaced by a newer version.
MULTITHREAT_MODEL_DIR = MODELS_DIR / "v1_current"

_phishing_model = joblib.load(
    PHISHING_MODEL_DIR / "phishing_model.pkl"
)
_phishing_vectorizer = joblib.load(
    PHISHING_MODEL_DIR / "phishing_vectorizer.pkl"
)

_multithreat_model = joblib.load(
    MULTITHREAT_MODEL_DIR / "multithreat_model.pkl"
)
_multithreat_vectorizer = joblib.load(
    MULTITHREAT_MODEL_DIR / "multithreat_vectorizer.pkl"
)

# Used to report when the deeper rule-based stage would normally be triggered.
# Rule-based detection itself always runs because it is cheap and provides
# an independent source of evidence.
FORENSICS_TRIGGER_THRESHOLD = 0.40


class _VisibleTextExtractor(HTMLParser):
    """Extract readable text from HTML while ignoring non-visible sections."""

    _SKIP_TAGS = {"script", "style", "head", "title"}

    def __init__(self):
        super().__init__(convert_charrefs=True)
        self._skip_stack: list[str] = []
        self._chunks: list[str] = []

    def handle_starttag(self, tag, attrs):
        if tag.lower() in self._SKIP_TAGS:
            self._skip_stack.append(tag.lower())

    def handle_endtag(self, tag):
        if self._skip_stack and self._skip_stack[-1] == tag.lower():
            self._skip_stack.pop()

    def handle_data(self, data):
        if not self._skip_stack:
            self._chunks.append(data)

    def get_text(self) -> str:
        text = " ".join(
            chunk.strip() for chunk in self._chunks if chunk.strip()
        )
        return re.sub(r"\s+", " ", text).strip()


def extract_visible_text_from_html(html: str) -> str:
    """Return readable HTML text without tags, scripts, or styles."""
    if not html:
        return ""

    parser = _VisibleTextExtractor()

    try:
        parser.feed(html)
        parser.close()
    except Exception:
        return ""

    return parser.get_text()


def classify_email(
    analysis_text: str,
    *,
    force_rule_based: bool = False,
) -> dict:
    """
    Run the phishing model, multithreat model, and rule-based detector.

    A high-severity attachment can force the informational forensics flag,
    but the rule-based detector itself always runs.
    """
    # Production phishing classification: V2.
    phishing_vector = _phishing_vectorizer.transform([analysis_text])
    phishing_probabilities = _phishing_model.predict_proba(phishing_vector)[0]

    safe_probability = float(phishing_probabilities[0])
    phishing_probability = float(phishing_probabilities[1])

    # Separate model for threat categories.
    threat_vector = _multithreat_vectorizer.transform([analysis_text])
    threat_probabilities = _multithreat_model.predict_proba(threat_vector)[0]
    threat_classes = _multithreat_model.classes_

    threat_categories = {
        category: round(float(probability) * 100, 2)
        for category, probability in zip(
            threat_classes,
            threat_probabilities,
        )
    }

    # This flag describes whether the normal forensics threshold was met.
    # Rule-based detection always runs regardless of this value.
    forensics_triggered = (
        phishing_probability >= FORENSICS_TRIGGER_THRESHOLD
        or force_rule_based
    )

    rule_based_threats = detect_threats(analysis_text)

    top_category = max(
        threat_categories,
        key=threat_categories.get,
    )

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
        "forensics_forced_by_attachment": (
            force_rule_based
            and phishing_probability < FORENSICS_TRIGGER_THRESHOLD
        ),
    }


def build_analysis_text(email) -> str:
    """
    Build the text passed to the ML models.

    Prefer the plaintext body. For HTML-only emails, use visible HTML text
    so the classifier still receives the actual message content.
    """
    body_text = email.body or extract_visible_text_from_html(
        email.html_body
    )

    return (
        f"From: {email.sender}\n"
        f"Reply-To: {email.reply_to or ''}\n"
        f"Return-Path: {email.return_path or ''}\n"
        f"Subject: {email.subject}\n\n"
        f"{body_text}"
    )