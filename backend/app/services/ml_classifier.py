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
import re
from html.parser import HTMLParser

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


class _VisibleTextExtractor(HTMLParser):
    """
    Strips an HTML document down to roughly what a reader actually
    sees: drops <script>/<style>/<head>/<title> content, keeps text
    nodes, collapses whitespace. Not full-fidelity text extraction -
    just enough that markup, CSS, and namespace declarations never
    reach the classifier as if they were message content. See
    build_analysis_text() below for why/when this is used.
    """

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
        text = " ".join(chunk.strip() for chunk in self._chunks if chunk.strip())
        return re.sub(r"\s+", " ", text).strip()


def extract_visible_text_from_html(html: str) -> str:
    """Return the visible, readable text of an HTML document, with
    script/style/head content and all markup/attributes removed."""
    if not html:
        return ""
    parser = _VisibleTextExtractor()
    try:
        parser.feed(html)
        parser.close()
    except Exception:
        return ""
    return parser.get_text()


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
    """
    Matches the text gmail_pipeline.py fed to the models, with one fix
    (see below): headers + body.

    BUG FIX (Twitch false positive / ML input normalization - see
    DIAGNOSTIC_EVIDENCE.md): `email.body` is the plaintext part of the
    message. A large fraction of real marketing/notification email -
    confirmed directly against a real Twitch notification, which is
    Content-Type: text/html with no multipart/plaintext alternative at
    all - has NO plaintext part, so `email.body` was simply empty and
    the classifier received nothing but the header block for those
    messages. That is a materially different (and strictly worse)
    input than either real plaintext or real visible text - it starves
    the model of the one thing (actual message content) it needs to
    make any judgment, for an unpredictable, arbitrary subset of real
    mail.

    Fix: when there is no plaintext part, fall back to a stripped,
    visible-text rendering of `email.html_body` (script/style/head and
    all markup/attributes removed) instead of leaving the body empty.
    When a real plaintext part exists, it is used unchanged, exactly
    as before - this only changes behavior for HTML-only messages.

    IMPORTANT, measured and reported honestly (see CHANGES.md): testing
    this change against the real trained model with the real Twitch
    email showed the visible-text input scores as MORE phishing-like
    (99.99%) than the previous empty-body input (96.36%), not less.
    This change is kept anyway because feeding the model real content
    instead of nothing is the architecturally correct fix regardless of
    its effect on any single email's score, and because the model's
    demonstrated tendency to score generic bulk-marketing/unsubscribe
    language as highly phishing-like is a separate, deeper limitation
    of the model's own training data - not something this input-plumbing
    fix can or should paper over (see risk_engine.py and CHANGES.md for
    why that is handled, if at all, at the evidence-combination layer,
    never by suppressing or hardcoding the model's output).
    """
    body_text = email.body or extract_visible_text_from_html(email.html_body)
    return (
        f"From: {email.sender}\n"
        f"Reply-To: {email.reply_to or ''}\n"
        f"Return-Path: {email.return_path or ''}\n"
        f"Subject: {email.subject}\n\n"
        f"{body_text}"
    )
