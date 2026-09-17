"""
YARA scanner - an offline, rule-based static analysis engine for
detecting known suspicious byte/string patterns. This is NOT an ML
model and NOT a guaranteed virus detector; "no matching rule" means
exactly that, never "file is safe" (see analysis_service.py's wording
and the dashboard copy in static/app.js).

Design constraints (see PROJECT_CONTEXT.md):
- Static analysis only. The attachment is never executed, never
  opened with an external application, never has macros enabled.
- Rules are trusted, locally-managed project artifacts
  (rules/demo_rules.yar) - never fetched or compiled from an
  untrusted/remote source at runtime.
- Compiled ruleset is a lazy singleton - loaded once per process, not
  once per email.
- A size limit is enforced before scanning; oversized attachments are
  reported as scanned=False with a reason, not silently skipped.
- If the `yara` package (yara-python) isn't installed in this
  environment, every call degrades to scanned=False with a clear
  reason - it never fakes a match or a clean result.
"""

from __future__ import annotations

from pathlib import Path

RULES_DIR = Path(__file__).parent / "rules"
MAX_SCAN_BYTES = 20 * 1024 * 1024  # 20MB - static string/byte matching gets slow well before this
SCAN_TIMEOUT_SECONDS = 5

_compiled_rules = None
_yara_import_error: str | None = None
_yara_module = None


def _get_yara_module():
    global _yara_module, _yara_import_error
    if _yara_module is not None or _yara_import_error is not None:
        return _yara_module
    try:
        import yara  # type: ignore
        _yara_module = yara
    except ImportError as exc:
        _yara_import_error = str(exc)
    return _yara_module


def _get_compiled_rules():
    global _compiled_rules
    if _compiled_rules is not None:
        return _compiled_rules

    yara = _get_yara_module()
    if yara is None:
        return None

    rule_files = sorted(RULES_DIR.glob("*.yar"))
    if not rule_files:
        return None

    # Rule files are trusted project artifacts (see module docstring) -
    # this compiles source text we ship, never a downloaded/compiled
    # binary ruleset from an untrusted source.
    filepaths = {f.stem: str(f) for f in rule_files}
    _compiled_rules = yara.compile(filepaths=filepaths)
    return _compiled_rules


def scan_bytes(content_bytes: bytes | None) -> dict:
    """
    Returns:
      {"scanned": True,  "matches": [{"rule": str, "severity": str}], "reason": None}
      {"scanned": False, "matches": [], "reason": "<why not scanned>"}
    """

    if not content_bytes:
        return {"scanned": False, "matches": [], "reason": "No content to scan"}

    if len(content_bytes) > MAX_SCAN_BYTES:
        return {"scanned": False, "matches": [], "reason": "Attachment exceeds YARA scan size limit"}

    yara = _get_yara_module()
    if yara is None:
        return {
            "scanned": False,
            "matches": [],
            "reason": f"yara-python is not installed in this environment ({_yara_import_error})",
        }

    rules = _get_compiled_rules()
    if rules is None:
        return {"scanned": False, "matches": [], "reason": "No local YARA rules available"}

    try:
        raw_matches = rules.match(data=content_bytes, timeout=SCAN_TIMEOUT_SECONDS)
    except Exception as exc:  # yara.TimeoutError and friends - never let a scan crash the pipeline
        return {"scanned": False, "matches": [], "reason": f"YARA scan error: {exc}"}

    matches = [
        {"rule": m.rule, "severity": (m.meta or {}).get("severity", "unknown")}
        for m in raw_matches
    ]
    return {"scanned": True, "matches": matches, "reason": None}


def highest_severity(matches: list[dict]) -> str | None:
    order = {"high": 3, "medium": 2, "low": 1, "unknown": 0}
    if not matches:
        return None
    return max(matches, key=lambda m: order.get(m.get("severity", "unknown"), 0)).get("severity")
