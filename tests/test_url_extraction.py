"""
Regression tests for URL extraction from HTML email bodies.

Background (see DIAGNOSTIC_EVIDENCE.md / CHANGES.md): the old extractor
ran one regex over the raw concatenation of plain_body + html_body, so
it treated XML/XHTML namespace declarations (e.g.
`xmlns="http://www.w3.org/1999/xhtml"`) as if they were destination
URLs - verified directly against a real Twitch marketing email, where
`http://www.w3.org/1999/xhtml` was extracted alongside the message's
18 genuine href/src destinations. The fix parses HTML with the stdlib
html.parser and only pulls URLs from actual navigable attributes
(href, src, action, ...) plus visible text - never from namespace or
other non-destination attributes.
"""
from __future__ import annotations

from backend.app.services.url_extractor import (
    extract_urls,
    extract_urls_from_html,
    extract_urls_from_text,
)


class TestHTMLNamespaceExclusion:
    def test_xmlns_attribute_is_not_extracted(self):
        html = '<html xmlns="http://www.w3.org/1999/xhtml"><body>hi</body></html>'
        urls = extract_urls_from_html(html)
        assert "http://www.w3.org/1999/xhtml" not in urls

    def test_xmlns_without_quotes_is_not_extracted(self):
        """The real Twitch email's xmlns attribute was unquoted
        (`xmlns=http://www.w3.org/1999/xhtml`), not
        `xmlns="..."` - the parser must handle both forms."""
        html = '<html xmlns=http://www.w3.org/1999/xhtml><body>hi</body></html>'
        urls = extract_urls_from_html(html)
        assert "http://www.w3.org/1999/xhtml" not in urls

    def test_other_namespace_declarations_are_not_extracted(self):
        html = (
            '<html xmlns:o="urn:schemas-microsoft-com:office:office" '
            'xmlns:v="http://www.w3schools.com/vml">body text</html>'
        )
        urls = extract_urls_from_html(html)
        assert not any("w3schools.com" in u for u in urls)

    def test_css_url_in_style_attribute_is_not_extracted_as_destination(self):
        """A CSS background-image isn't a link a recipient can click -
        only href/src/action/etc. (see _URL_ATTRS) count as
        destinations."""
        html = '<div style="background-image: url(http://cdn.example.com/bg.png)">x</div>'
        urls = extract_urls_from_html(html)
        assert "http://cdn.example.com/bg.png" not in urls


class TestLegitimateURLsPreserved:
    def test_href_url_is_extracted(self):
        html = '<a href="https://example.com/click">Click here</a>'
        urls = extract_urls_from_html(html)
        assert "https://example.com/click" in urls

    def test_src_url_is_extracted(self):
        html = '<img src="https://cdn.example.com/logo.png">'
        urls = extract_urls_from_html(html)
        assert "https://cdn.example.com/logo.png" in urls

    def test_action_url_is_extracted(self):
        html = '<form action="https://example.com/submit">'
        urls = extract_urls_from_html(html)
        assert "https://example.com/submit" in urls

    def test_plaintext_url_in_visible_text_is_extracted(self):
        html = "<p>Copy this link: https://example.com/verify-account</p>"
        urls = extract_urls_from_html(html)
        assert "https://example.com/verify-account" in urls

    def test_srcset_candidate_url_is_extracted(self):
        html = '<img srcset="https://example.com/img-1x.png 1x, https://example.com/img-2x.png 2x">'
        urls = extract_urls_from_html(html)
        assert "https://example.com/img-1x.png" in urls
        assert "https://example.com/img-2x.png" in urls

    def test_plaintext_url_extractor_still_works_for_plain_body(self):
        text = "Visit https://example.com/newsletter for more."
        urls = extract_urls_from_text(text)
        assert urls == ["https://example.com/newsletter"]

    def test_does_not_blindly_delete_all_urls(self):
        """A minimal safety check: a realistic HTML email with several
        legitimate links must still return several URLs, not zero -
        the fix narrows *which attributes* count, it does not
        suppress URL evidence altogether."""
        html = (
            "<html xmlns=\"http://www.w3.org/1999/xhtml\">"
            "<body>"
            '<a href="https://example.com/one">one</a>'
            '<a href="https://example.com/two">two</a>'
            '<img src="https://cdn.example.com/pixel.gif">'
            "</body></html>"
        )
        urls = extract_urls_from_html(html)
        assert len(urls) == 3
        assert "http://www.w3.org/1999/xhtml" not in urls


class TestRealTwitchEmail:
    """Exercises the exact HTML from the real, attached Twitch .eml
    reported as a live false positive. The raw HTML fixture below is a
    trimmed excerpt reproducing the specific construct that triggered
    the bug (unquoted xmlns + real href/src destinations), not the
    full original message."""

    HTML_EXCERPT = (
        "<!doctype html><html xmlns=http://www.w3.org/1999/xhtml "
        'style="background-color: #efeef1" dir=ltr><head>'
        "<base target=\u201c_blank\u201d>"
        "<meta charset=utf-8></head><body>"
        '<a href="https://www.twitch.tv/r/e/example?tt_medium=email">Watch now</a>'
        '<img src="https://static-cdn.jtvnw.net/growth-assets/email_twitch_logo_uv">'
        "</body></html>"
    )

    def test_xmlns_excluded_real_construct(self):
        urls = extract_urls_from_html(self.HTML_EXCERPT)
        assert "http://www.w3.org/1999/xhtml" not in urls

    def test_real_destinations_preserved(self):
        urls = extract_urls_from_html(self.HTML_EXCERPT)
        assert any(u.startswith("https://www.twitch.tv/r/e/") for u in urls)
        assert any(u.startswith("https://static-cdn.jtvnw.net/") for u in urls)


class TestBackwardCompatibility:
    def test_plain_extract_urls_unchanged_for_plaintext(self):
        """extract_urls() (the original plain-regex function) is kept
        for backward compatibility with any caller that already has
        pure plaintext - its behavior is unchanged."""
        text = "Visit https://example.com/a and https://example.com/b"
        assert extract_urls(text) == [
            "https://example.com/a",
            "https://example.com/b",
        ]
