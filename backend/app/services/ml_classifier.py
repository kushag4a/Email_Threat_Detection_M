"""
M2 - AI / phishing / threat classification.

Reuses the already-trained models exactly as they were:
phishing_model.pkl / phishing_vectorizer.pkl and
multithreat_model.pkl / multithreat_vectorizer.pkl (from
gmail_pipeline.py), plus the rule-based keyword classifier
(threat_classifier.py). No new ML was introduced.

Models are loaded once at import time, matching the original
gmail_pipeline.py behavior.

--------------------------------------------------------------------
PRODUCTION MODEL WIRING (2026 risk-hardening review)
--------------------------------------------------------------------
The approved final ML decision is: the PHISHING (binary) model is
V2 (backend/app/models/v2/) - not V2.1 (backend/app/models/v2_1/,
evaluated and NOT promoted) and not the older V1 snapshot preserved
at backend/app/models/v1_current/ for rollback.

Prior to this fix, this loader read phishing_model.pkl /
phishing_vectorizer.pkl from the flat MODELS_DIR
(backend/app/models/), which was verified (sha256) to still contain
the V1 artifacts - i.e. the "V2 is final" decision had never actually
been wired into the running application. See
PHISHING_MODEL_DIR below: it now points explicitly at
backend/app/models/v2/, the single source of truth for which
phishing model is live. This is a path/config change only - no
model files were copied, retrained, or deleted; the flat
backend/app/models/phishing_model.pkl / phishing_vectorizer.pkl
files still exist (identical to v1_current/) as an inert historical/
rollback copy, and are no longer read by this module.

The MULTITHREAT (multi-class category) model is a SEPARATE model
from the phishing V2/V2.1 decision above. No V2 (or any newer)
version of the multithreat model was trained or evaluated as part of
this review - backend/app/models/v2/ and v2_1/ contain phishing-model
artifacts only. It therefore continues to load from the flat
MODELS_DIR, unchanged, exactly as before.
"""

from pathlib import Path
import re
from html.parser import HTMLParser

import joblib

from backend.app.services.threat_classifier import detect_threats

MODELS_DIR = Path(__file__).parent.parent / "models"

# Approved production phishing model - see docstring above. Change
# this single constant (and only this constant) to promote a future
# phishing model version; do not point it back at MODELS_DIR without
# first re-verifying (by hash) which artifact actually lives there.
PHISHING_MODEL_DIR = MODELS_DIR / "v2"

_phishing_model = joblib.load(PHISHING_MODEL_DIR / "phishing_model.pkl")
_phishing_vectorizer = joblib.load(PHISHING_MODEL_DIR / "phishing_vectorizer.pkl")

# Multithreat model - unrelated to the phishing V2/V2.1 decision;
# no newer version exists, so this intentionally still loads from the
# flat MODELS_DIR.
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

    # BUG FIX (rule-based detection previously gated behind ML
    # confidence - see MERGE_LOG.md Task 3): detect_threats() is a
    # cheap keyword scan (a handful of `in` checks over the message
    # text), not an expensive deep scan, so there is no performance
    # reason to skip it. Gating it behind phishing_probability >= 40%
    # meant a message the ML model was unsure about never got scanned
    # for BEC/credential-theft/financial-fraud keyword patterns at all,
    # silently dropping a whole independent evidence source exactly
    # when the model's own signal was weakest. It now always runs;
    # `forensics_triggered` is kept as an informational flag (also
    # still forced True by a high-severity attachment finding) rather
    # than as a gate on rule_based_threats.
    forensics_triggered = phishing_probability >= FORENSICS_TRIGGER_THRESHOLD or force_rule_based
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
