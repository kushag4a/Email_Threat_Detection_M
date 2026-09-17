"""
Pre-translation technical-token masking.

Before feeding email text to NLLB, structured tokens that must survive
translation verbatim (URLs, email addresses, domain names, hashes, and
dangerous-filenames) are replaced with Unicode placeholder tokens of the
form Unicode(URL_0) etc.  After translation the placeholders are restored.

Design decisions
----------------
* Patterns are ordered most-specific first (URL before DOMAIN) so the
  greedy match on broader patterns does not swallow sub-tokens already
  captured by a narrower one.
* Placeholders use the Unicode angle-bracket pair (U+27E8/U+27E9) so they
  are visually distinct from normal text and survive most tokenizers as
  unusual-but-intact byte sequences.
* Restoration is best-effort: if the model drops or mutates a placeholder
  it is left as-is in the output rather than silently disappearing or
  crashing the caller.
* This module has zero dependencies beyond the standard library and is
  independently testable.
"""
from __future__ import annotations

import re
from typing import NamedTuple


class MaskedText(NamedTuple):
    """Return value of mask_technical_tokens()."""
    text: str
    restoration_map: dict[str, str]  # placeholder -> original token


# ---------------------------------------------------------------------------
# Pattern definitions (ordered most-specific first)
# ---------------------------------------------------------------------------

_PATTERNS: list[tuple[str, re.Pattern[str]]] = [
    # Full URLs (http/https/ftp) -- must come before DOMAIN
    (
        "URL",
        re.compile(
            r"https?://[^\s<>\"'()\[\]{}|\\^`\x00-\x1f]+"
            r"|ftp://[^\s<>\"'()\[\]{}|\\^`\x00-\x1f]+",
            re.IGNORECASE,
        ),
    ),
    # Email addresses -- must come before DOMAIN
    (
        "EMAIL",
        re.compile(
            r"[a-zA-Z0-9._%+\-]+@[a-zA-Z0-9.\-]+\.[a-zA-Z]{2,}",
        ),
    ),
    # Hex hashes (MD5 / SHA-1 / SHA-256 range)
    (
        "HASH",
        re.compile(
            r"\b[0-9a-fA-F]{32,64}\b",
        ),
    ),
    # Filenames with security-relevant extensions
    (
        "FILENAME",
        re.compile(
            r"\b[\w\-]+\."
            r"(?:exe|pdf|doc|docx|xls|xlsx|zip|rar|7z|js|vbs|bat|sh|ps1|msi|apk|dmg|iso)\b",
            re.IGNORECASE,
        ),
    ),
    # Bare domain names (catch remaining after URL/EMAIL consumed)
    (
        "DOMAIN",
        re.compile(
            r"\b(?:[a-zA-Z0-9](?:[a-zA-Z0-9\-]{0,61}[a-zA-Z0-9])?\.)+[a-zA-Z]{2,}\b",
        ),
    ),
]

# Pattern that matches any placeholder we inserted, for restoration pass.
_PLACEHOLDER_RE = re.compile(r"\u27E8(URL|EMAIL|HASH|FILENAME|DOMAIN)_(\d+)\u27E9")


def mask_technical_tokens(text: str) -> MaskedText:
    """
    Replace technical tokens in *text* with numbered placeholders.

    Returns MaskedText(text=masked, restoration_map={placeholder: original}).
    Pass the masked text to the model, then call restore_technical_tokens()
    on the model output to recover originals.
    """
    restoration_map: dict[str, str] = {}
    counters: dict[str, int] = {}
    result = text

    for kind, pattern in _PATTERNS:
        def _replace(m: re.Match, _kind: str = kind) -> str:
            original = m.group(0)
            idx = counters.get(_kind, 0)
            counters[_kind] = idx + 1
            placeholder = f"\u27E8{_kind}_{idx}\u27E9"
            restoration_map[placeholder] = original
            return placeholder

        result = pattern.sub(_replace, result)

    return MaskedText(text=result, restoration_map=restoration_map)


def restore_technical_tokens(translated: str, restoration_map: dict[str, str]) -> str:
    """
    Replace placeholders in *translated* back with their originals.

    Placeholders the model dropped or corrupted are left as-is in the output
    rather than silently disappearing -- the caller sees a readable trace.
    """
    def _restore(m: re.Match) -> str:
        return restoration_map.get(m.group(0), m.group(0))

    return _PLACEHOLDER_RE.sub(_restore, translated)
