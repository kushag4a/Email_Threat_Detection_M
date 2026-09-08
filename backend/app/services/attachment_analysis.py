"""
Attachment analysis - the FIRST stage of the pipeline (see
analysis_service.py), not an afterthought computed inside the risk
engine, and now genuinely CONDITIONAL: if an email has no
attachments, this returns immediately with scanned=False and never
touches the YARA module or the file-type detector at all.

Pipeline for an email WITH attachments (per attachment):
  1. filename / content_type / extension / size (already parsed)
  2. magic-byte file-type detection (file_type_detector.py)
  3. extension vs detected-type mismatch check
  4. SHA-256 (already computed at parse time)
  5. YARA scan (security/yara/scanner.py) - static, in-memory only,
     never executes the file

This is the single source of truth for "is this attachment
suspicious" - risk_engine.py has no attachment-severity logic of its
own; it consumes this module's output.

A high-severity finding here (executable/script extension,
macro-enabled document, disguised double extension, extension/type
mismatch, or a YARA match) is used to conditionally force the deeper
rule-based text scan in M2/ai_analysis even when the ML phishing
probability alone is low. This is strictly additive: it can only turn
on *more* scanning for a borderline email, never less.
"""

from __future__ import annotations

from backend.app.security.yara import scanner as yara_scanner
from backend.app.services import file_type_detector

EXECUTABLE_EXTENSIONS = {".exe", ".scr", ".bat", ".js", ".vbs", ".jar", ".msi", ".ps1"}
ARCHIVE_EXTENSIONS = {".zip", ".rar", ".7z", ".gz", ".tar"}
MACRO_DOCUMENT_EXTENSIONS = {".docm", ".xlsm", ".pptm"}
DOCUMENT_EXTENSIONS = {".pdf", ".doc", ".docx", ".xls", ".xlsx", ".ppt", ".pptx", ".txt"}
IMAGE_EXTENSIONS = {".png", ".jpg", ".jpeg", ".gif", ".bmp", ".svg"}


def _has_disguised_extension(filename: str, real_extension: str) -> bool:
    """Catches the 'invoice.pdf.exe' trick - the real extension is the last one."""
    if not filename or not real_extension:
        return False
    stem = filename[: -len(real_extension)] if filename.lower().endswith(real_extension) else filename
    for fake_ext in DOCUMENT_EXTENSIONS | IMAGE_EXTENSIONS:
        if stem.lower().endswith(fake_ext):
            return True
    return False


def _categorize(extension: str) -> str:
    ext = (extension or "").lower()
    if ext in EXECUTABLE_EXTENSIONS:
        return "executable_or_script"
    if ext in MACRO_DOCUMENT_EXTENSIONS:
        return "macro_enabled_document"
    if ext in ARCHIVE_EXTENSIONS:
        return "archive"
    if ext in DOCUMENT_EXTENSIONS:
        return "document"
    if ext in IMAGE_EXTENSIONS:
        return "image"
    return "unknown"


def analyze_attachments(attachments: list[dict]) -> dict:
    """
    attachments: list of {filename, content_type, extension, size_bytes,
    sha256, content_bytes} (content_bytes is transient - see
    schemas/email_message.py - and is NEVER included in this
    function's output).

    Returns:
      no attachments -> {"scanned": False, "reason": "No attachments",
                          "items": [], "has_high_severity": False,
                          "high_severity_filenames": []}
      with attachments -> {"scanned": True, "reason": None, "items": [...], ...}
    """

    if not attachments:
        return {
            "scanned": False,
            "reason": "No attachments",
            "items": [],
            "has_high_severity": False,
            "high_severity_filenames": [],
        }

    items = []
    has_high_severity = False

    for a in attachments:
        filename = a.get("filename", "")
        declared_type = a.get("content_type", "")
        extension = (a.get("extension") or "").lower()
        content_bytes = a.get("content_bytes")
        category = _categorize(extension)
        flags: list[str] = []

        if category == "executable_or_script":
            flags.append("executable_or_script_extension")
            has_high_severity = True

        if category == "macro_enabled_document":
            flags.append("macro_enabled_document")
            has_high_severity = True

        if _has_disguised_extension(filename, extension):
            flags.append("disguised_double_extension")
            has_high_severity = True

        # Magic-byte detection - independent of what the filename/MIME claims.
        type_info = file_type_detector.detect_file_type(content_bytes)
        if file_type_detector.check_extension_mismatch(extension, type_info["detected_category"]):
            flags.append("extension_content_type_mismatch")
            has_high_severity = True

        # YARA - static, in-memory, never executes the attachment.
        yara_result = yara_scanner.scan_bytes(content_bytes)
        if yara_result["matches"]:
            flags.append("yara_rule_match")
            severity = yara_scanner.highest_severity(yara_result["matches"])
            if severity in ("high", "medium"):
                has_high_severity = True

        # A PDF/DOCX/XLSX/image by itself, with matching magic bytes and
        # no YARA hit, is explicitly NOT suspicious - matches the
        # project's false-positive requirement (SCOPE newsletter's PDF
        # attachment must not raise risk on its own).
        items.append({
            "filename": filename,
            "declared_type": declared_type,
            "detected_type": type_info["detected_type"],
            "extension": extension,
            "category": category,
            "size_bytes": a.get("size_bytes", 0),
            "sha256": a.get("sha256"),
            "flags": flags,
            "yara": {
                "scanned": yara_result["scanned"],
                "matches": yara_result["matches"],
                "reason": yara_result["reason"],
            },
        })

    return {
        "scanned": True,
        "reason": None,
        "items": items,
        "has_high_severity": has_high_severity,
        "high_severity_filenames": [i["filename"] for i in items if i["flags"]],
    }
