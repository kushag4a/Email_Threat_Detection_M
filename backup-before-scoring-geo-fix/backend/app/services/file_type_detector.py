"""
Static file-type detection via magic bytes (file signatures) - no
external library, no execution of the file, just reading its first
few bytes.

Used to catch "invoice.pdf" that is actually a PE executable, or a
".jpg" that is actually a script - a real, independent risk signal
distinct from the filename/extension alone (which an attacker fully
controls).
"""

from __future__ import annotations

# (signature bytes, offset, detected_type, detected_category)
_SIGNATURES: list[tuple[bytes, int, str, str]] = [
    (b"%PDF-", 0, "application/pdf", "document"),
    (b"MZ", 0, "application/x-msdownload", "executable"),
    (b"\x7fELF", 0, "application/x-elf", "executable"),
    (b"\xd0\xcf\x11\xe0\xa1\xb1\x1a\xe1", 0, "application/x-ole-storage", "legacy_office_or_ole"),
    (b"PK\x03\x04", 0, "application/zip", "zip_or_ooxml"),
    (b"PK\x05\x06", 0, "application/zip", "zip_or_ooxml"),
    (b"\x89PNG\r\n\x1a\n", 0, "image/png", "image"),
    (b"\xff\xd8\xff", 0, "image/jpeg", "image"),
    (b"GIF87a", 0, "image/gif", "image"),
    (b"GIF89a", 0, "image/gif", "image"),
    (b"%!PS", 0, "application/postscript", "document"),
    (b"{\\rtf1", 0, "application/rtf", "document"),
]

# Which detected_category is "expected" for a given extension. Used
# only to flag a mismatch - never to prove a file is safe.
_EXPECTED_CATEGORY_BY_EXTENSION: dict[str, set[str]] = {
    ".pdf": {"document"},
    ".doc": {"legacy_office_or_ole"},
    ".xls": {"legacy_office_or_ole"},
    ".ppt": {"legacy_office_or_ole"},
    ".docx": {"zip_or_ooxml"},
    ".xlsx": {"zip_or_ooxml"},
    ".pptx": {"zip_or_ooxml"},
    ".docm": {"zip_or_ooxml"},
    ".xlsm": {"zip_or_ooxml"},
    ".pptm": {"zip_or_ooxml"},
    ".zip": {"zip_or_ooxml"},
    ".png": {"image"},
    ".jpg": {"image"}, ".jpeg": {"image"},
    ".gif": {"image"},
}


def detect_file_type(content_bytes: bytes | None) -> dict:
    """
    Returns {"detected_type": mime-ish str, "detected_category": str}.
    Never raises. Unknown/empty content is reported as such, not
    guessed.
    """
    if not content_bytes:
        return {"detected_type": "unknown", "detected_category": "unknown"}

    for signature, offset, detected_type, category in _SIGNATURES:
        chunk = content_bytes[offset: offset + len(signature)]
        if chunk == signature:
            return {"detected_type": detected_type, "detected_category": category}

    # Cheap printable-text heuristic - not authoritative, just a label.
    sample = content_bytes[:512]
    try:
        sample.decode("utf-8")
        return {"detected_type": "text/plain", "detected_category": "text"}
    except UnicodeDecodeError:
        return {"detected_type": "application/octet-stream", "detected_category": "unknown_binary"}


def check_extension_mismatch(extension: str, detected_category: str) -> bool:
    """
    True only when we have a specific expectation for this extension
    AND the detected category clearly doesn't match it. Extensions
    with no entry (unknown extensions) never produce a mismatch flag -
    absence of a signature match is not evidence of anything on its
    own.
    """
    expected = _EXPECTED_CATEGORY_BY_EXTENSION.get((extension or "").lower())
    if not expected:
        return False
    if detected_category in ("unknown", "text"):
        # Genuinely can't tell (empty/plain-text content) - not a mismatch claim.
        return False
    return detected_category not in expected
