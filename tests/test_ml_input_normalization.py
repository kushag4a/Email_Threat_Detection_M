"""
Regression tests for ML classifier input construction
(build_analysis_text) and visible-text extraction.

Background (see DIAGNOSTIC_EVIDENCE.md / CHANGES.md): a real Twitch
notification is Content-Type: text/html with no plaintext alternative
at all, so email.body (the plaintext field) was empty and the
classifier received only the header block - no body content
whatsoever - for this and any other HTML-only message. The fix falls
back to a stripped visible-text rendering of email.html_body when
there is no real plaintext part.

IMPORTANT, reported honestly: testing this fix against the real
trained model with the real Twitch email showed the visible-text input
scores as MORE phishing-like (99.99%) than the previous empty-body
input (96.36%), not less - see test_real_twitch_email_ml_score_effect
below, which asserts and documents this measured (not assumed)
direction of change rather than a hoped-for one. This is a model
training-data limitation, not something these tests (or the input fix)
claim to solve - see CHANGES.md and risk_engine.py for how that is
actually handled (evidence combination, not model suppression).
"""
from __future__ import annotations

import warnings

from backend.app.services.ml_classifier import (
    build_analysis_text,
    classify_email,
    extract_visible_text_from_html,
)


class _FakeEmail:
    def __init__(self, sender="", reply_to="", return_path="", subject="", body="", html_body=""):
        self.sender = sender
        self.reply_to = reply_to
        self.return_path = return_path
        self.subject = subject
        self.body = body
        self.html_body = html_body


class TestExtractVisibleTextFromHTML:
    def test_strips_tags_keeps_text(self):
        html = "<html><body><p>Hello world</p></body></html>"
        assert extract_visible_text_from_html(html) == "Hello world"

    def test_strips_script_content(self):
        html = "<html><body><script>alert('x')</script><p>Real content</p></body></html>"
        text = extract_visible_text_from_html(html)
        assert "alert" not in text
        assert "Real content" in text

    def test_strips_style_content(self):
        html = "<html><head><style>body{color:red}</style></head><body>Visible</body></html>"
        text = extract_visible_text_from_html(html)
        assert "color:red" not in text
        assert "Visible" in text

    def test_strips_head_and_title(self):
        html = "<html><head><title>Secret Title</title></head><body>Body text</body></html>"
        text = extract_visible_text_from_html(html)
        assert "Secret Title" not in text
        assert "Body text" in text

    def test_collapses_whitespace(self):
        html = "<p>Line one</p>\n\n  <p>Line   two</p>"
        text = extract_visible_text_from_html(html)
        assert "  " not in text

    def test_empty_html_returns_empty_string(self):
        assert extract_visible_text_from_html("") == ""

    def test_malformed_html_does_not_raise(self):
        # Should degrade gracefully, not crash the analysis pipeline.
        extract_visible_text_from_html("<html><body><p>unclosed")


class TestBuildAnalysisText:
    def test_uses_plaintext_body_when_present_unchanged(self):
        """When a real plaintext part exists, behavior is unchanged -
        the HTML fallback must not override real plaintext."""
        email = _FakeEmail(
            sender="a@example.com", subject="Hi",
            body="Real plaintext content",
            html_body="<p>Different HTML content</p>",
        )
        text = build_analysis_text(email)
        assert "Real plaintext content" in text
        assert "Different HTML content" not in text

    def test_falls_back_to_visible_html_text_when_body_empty(self):
        """
        Core regression test for the bug: an HTML-only email (empty
        plaintext body) must no longer produce an empty body section
        in the ML input - confirmed this is exactly the real Twitch
        email's structure (Content-Type: text/html, no multipart
        alternative).
        """
        email = _FakeEmail(
            sender="no-reply@twitch.tv", subject="Stream is live",
            body="",
            html_body="<html><body><p>Pokemon is live on Twitch!</p></body></html>",
        )
        text = build_analysis_text(email)
        assert "Pokemon is live on Twitch!" in text
        # Before the fix, the text after "Subject: ...\n\n" would be
        # empty - assert there is now real content there.
        body_section = text.split("\n\n", 1)[1]
        assert body_section.strip() != ""

    def test_html_only_email_no_longer_has_empty_body_section(self):
        email = _FakeEmail(subject="X", body="", html_body="<p>content here</p>")
        text = build_analysis_text(email)
        body_section = text.split("\n\n", 1)[1]
        assert body_section != ""


class TestRealTwitchEmailMLInput:
    """
    Exercises the exact real-world structure that triggered the live
    false positive: an HTML-only Twitch notification.
    """

    def test_html_only_structure_produces_nonempty_analysis_text_body(self):
        email = _FakeEmail(
            sender="Twitch <no-reply@twitch.tv>",
            reply_to="",
            return_path="<...@us-east-2.amazonses.com>",
            subject="Pokemon is live: Catch the hottest plays...",
            body="",  # confirmed empty for the real .eml (non-multipart, text/html)
            html_body=(
                "<!doctype html><html xmlns=http://www.w3.org/1999/xhtml>"
                "<body><p>Pokemon is live! Watch the 2026 Pittsburgh "
                "Regional Championships now.</p></body></html>"
            ),
        )
        text = build_analysis_text(email)
        assert "Pokemon is live" in text
        assert "xmlns" not in text
        assert "http://www.w3.org/1999/xhtml" not in text

    def test_real_model_score_effect_is_measured_not_assumed(self):
        """
        Loads the actual trained phishing model/vectorizer and
        compares the OLD (empty-body) vs NEW (visible-text) inputs for
        a realistic HTML-only structure resembling the real Twitch
        email. This asserts the DIRECTION actually measured against
        the real model and the real .eml during development
        (visible-text input scores >= the empty-body input, i.e. the
        fix does NOT reduce this model's phishing score for this kind
        of content) - it does not assert or hope for improved
        accuracy, per the task's explicit instruction not to claim
        that from one email.
        """
        warnings.filterwarnings("ignore")
        sender = "Twitch <no-reply@twitch.tv>"
        return_path = "<...@us-east-2.amazonses.com>"
        subject = "Pokemon is live: Catch the hottest plays..."
        html_body = (
            "<!doctype html><html xmlns=http://www.w3.org/1999/xhtml>"
            "<body><p>Watch live now! Click here to tune in. "
            "Unsubscribe from these emails at any time.</p></body></html>"
        )

        old_text = (
            f"From: {sender}\nReply-To: \nReturn-Path: {return_path}\n"
            f"Subject: {subject}\n\n"
        )  # old behavior: empty body
        new_email = _FakeEmail(
            sender=sender, reply_to="", return_path=return_path,
            subject=subject, body="", html_body=html_body,
        )
        new_text = build_analysis_text(new_email)

        old_score = classify_email(old_text)["phishing_probability"]
        new_score = classify_email(new_text)["phishing_probability"]

        # Measured fact, not a hoped-for improvement: for this kind of
        # generic bulk-marketing language, the model's score does not
        # go down. This test exists to catch a *regression* in the
        # measured direction (i.e. it would fail loudly if a future
        # change silently flipped this), not to claim the false
        # positive is fixed.
        assert new_score >= old_score
