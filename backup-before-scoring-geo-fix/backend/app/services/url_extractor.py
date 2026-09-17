"""
URL extraction for email bodies.

BUG FIX (Twitch false positive / URL extraction - see
DIAGNOSTIC_EVIDENCE.md): the previous implementation ran one regex
over the ENTIRE raw HTML source (tags, attributes, and all), so it
swept up anything shaped like a URL regardless of where it appeared -
including XML/XHTML namespace declarations like
`xmlns="http://www.w3.org/1999/xhtml"`, which is a namespace
identifier, not a destination a recipient could ever click or be
redirected to. Verified directly against a real Twitch marketing
email: the old extractor returned `http://www.w3.org/1999/xhtml` as if
it were forensic evidence, alongside the message's 18 genuine
href/src destination URLs.

Fix: for HTML content, only ever pull URLs out of attributes that are
actually navigable/loadable destinations (href, src, action, and a
handful of others below), using Python's stdlib html.parser instead of
a single blanket regex over the raw markup - so namespace
declarations, CSS, and other non-destination attributes are never
considered evidence. Bare plaintext URLs typed directly into a message
body (or appearing as visible text inside HTML) are still picked up,
since those ARE real destinations a recipient could read and click.
"""
from __future__ import annotations

import re
from html.parser import HTMLParser

URL_PATTERN = re.compile(
    r"https?://[^\s<>\"']+",
    re.IGNORECASE
)

# Attributes that can hold a navigable/loadable URL. Deliberately does
# NOT include xmlns/xmlns:*, xml:*, or any other declarative/namespace
# attribute - those are not destinations, they're markup metadata.
_URL_ATTRS = {"href", "src", "action", "formaction", "poster", "background", "cite"}


class _HTMLLinkExtractor(HTMLParser):
    """Collects URLs only from known URL-bearing attributes, plus
    plaintext URLs found in visible text nodes."""

    def __init__(self):
        super().__init__(convert_charrefs=True)
        self.urls: list[str] = []
        self._text_chunks: list[str] = []

    def handle_starttag(self, tag, attrs):
        for name, value in attrs:
            if value is None:
                continue
            lname = name.lower()
            if lname in _URL_ATTRS:
                self._collect(value)
            elif lname == "srcset":
                # srcset: "url1 1x, url2 2x, ..." - take the URL part
                # of each comma-separated candidate.
                for candidate in value.split(","):
                    part = candidate.strip().split(" ")[0].strip()
                    if part:
                        self._collect(part)

    def handle_data(self, data):
        # Visible text nodes can contain plaintext URLs a recipient
        # could read and click/copy - these ARE real destinations,
        # unlike attribute values that only exist for markup plumbing.
        self._text_chunks.append(data)

    def _collect(self, value: str):
        value = value.strip()
        if value.lower().startswith(("http://", "https://")):
            self.urls.append(value)

    def get_text_urls(self) -> list[str]:
        text = " ".join(self._text_chunks)
        return URL_PATTERN.findall(text)


def _extract_from_html(html: str) -> list[str]:
    parser = _HTMLLinkExtractor()
    try:
        parser.feed(html)
        parser.close()
    except Exception:
        # Malformed HTML shouldn't crash extraction - whatever was
        # parsed before the error is still returned below.
        pass
    return parser.urls + parser.get_text_urls()


def extract_urls_from_html(html: str) -> list[str]:
    """
    Extract navigable URLs from HTML content: href/src/action/etc.
    attribute values, plus plaintext URLs in visible text nodes. Never
    returns values from non-destination attributes like xmlns.
    """
    if not html:
        return []
    return list(dict.fromkeys(_extract_from_html(html)))


def extract_urls_from_text(text: str) -> list[str]:
    """Extract plaintext URLs from non-HTML text (e.g. the plaintext
    part of a multipart email). No markup awareness needed here since
    there are no tags/attributes to distinguish from content."""
    if not text:
        return []
    return list(dict.fromkeys(URL_PATTERN.findall(text)))


def extract_urls(text: str) -> list[str]:
    """
    Plain-text URL extractor (regex over the given string, no HTML
    awareness). Kept for backward compatibility with any caller that
    already has pure plaintext with no markup - new HTML-aware callers
    should use extract_urls_from_html/extract_urls_from_text instead
    (see email_parser.py, which now calls those directly rather than
    concatenating plaintext and HTML and running this blanket regex
    over the result).
    """
    if not text:
        return []
    return list(dict.fromkeys(URL_PATTERN.findall(text)))
