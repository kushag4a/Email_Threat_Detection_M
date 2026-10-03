"""Tests for the isolated SpamAssassin adapter (`backend.app.spam`).

These tests exercise `backend/app/spam/spamassassin.py`,
`backend/app/spam/config.py`, and `backend/app/spam/result_schema.py` in
complete isolation from any other part of the system. Per the module's
own docstrings, this component is not wired into the risk engine, NLLB,
the V2 phishing model, `analysis_service`, threat intelligence, or the
attachment scanner -- so no other production code is imported or
exercised here.

No real SpamAssassin installation is required or assumed: every test
that would otherwise invoke the `spamassassin` binary instead mocks
`shutil.which` and `subprocess.run` at the module level, so the suite
runs fully offline and deterministically in any environment.
"""

from __future__ import annotations

import subprocess
import sys
from pathlib import Path
from unittest.mock import MagicMock

import pytest

# Make `backend.app.spam` importable without requiring the repository to
# be installed as a package, mirroring the same defensive sys.path
# handling used by `tools/scripts/spamassassin_cli.py`.
_REPO_ROOT = Path(__file__).resolve().parent.parent
if str(_REPO_ROOT) not in sys.path:
    sys.path.insert(0, str(_REPO_ROOT))

from backend.app.spam import spamassassin as sa  # noqa: E402
from backend.app.spam.config import (  # noqa: E402
    DEFAULT_ARGS,
    DEFAULT_EXECUTABLE,
    DEFAULT_TIMEOUT_SECONDS,
    ENV_ARGS,
    ENV_EXECUTABLE,
    ENV_TIMEOUT_SECONDS,
    SpamAssassinConfig,
    get_spamassassin_config,
)
from backend.app.spam.result_schema import SpamAssassinResult  # noqa: E402

# --- Sample SpamAssassin output -------------------------------------------------
# Real `--test-mode` output: an `X-Spam-Status` header followed by other
# headers and the (echoed) message body. The `tests=` list is wrapped
# across a continuation line (leading tab) the way SpamAssassin wraps
# long header values, to exercise the adapter's unfolding logic.
SAMPLE_SPAM_STDOUT = (
    "Return-Path: <spammer@example.com>\n"
    "X-Spam-Checker-Version: SpamAssassin 3.4.6 (2021-04-09) on host.example.com\n"
    "X-Spam-Level: ***************\n"
    "X-Spam-Status: Yes, score=15.3 required=5.0 tests=BAYES_99,HTML_MESSAGE,\n"
    "\tMIME_HTML_ONLY,URIBL_BLACK autolearn=no autolearn_force=no\n"
    "\tversion=3.4.6\n"
    "X-Spam-Flag: YES\n"
    "Subject: ***SPAM*** Buy now!!!\n"
    "\n"
    "This is the spam body.\n"
)

SAMPLE_HAM_STDOUT = (
    "Return-Path: <friend@example.com>\n"
    "X-Spam-Checker-Version: SpamAssassin 3.4.6 (2021-04-09) on host.example.com\n"
    "X-Spam-Status: No, score=-0.5 required=5.0 tests=BAYES_00 autolearn=ham"
    " autolearn_force=no version=3.4.6\n"
    "Subject: Hello\n"
    "\n"
    "This is a normal message.\n"
)

SAMPLE_NO_RULES_STDOUT = (
    "X-Spam-Status: No, score=0.0 required=5.0 tests=NONE autolearn=ham"
    " autolearn_force=no version=3.4.6\n"
    "Subject: Hello\n"
    "\n"
    "Body.\n"
)

SAMPLE_MALFORMED_STDOUT = "This does not look like spamassassin output at all.\n"


# --- Fixtures ---------------------------------------------------------------


@pytest.fixture(autouse=True)
def _clean_spamassassin_env(monkeypatch):
    """Ensure no `SPAMASSASSIN_*` env var leaks between tests or from the host."""
    for var in (ENV_EXECUTABLE, ENV_ARGS, ENV_TIMEOUT_SECONDS):
        monkeypatch.delenv(var, raising=False)


@pytest.fixture
def config():
    """A deterministic config pointing at a fake executable name."""
    return SpamAssassinConfig(
        executable="fake-spamassassin",
        args=("--test-mode", "--local", "--nocreate-prefs"),
        timeout_seconds=5.0,
    )


@pytest.fixture
def mock_which_found(monkeypatch):
    """Make `shutil.which` resolve the fake executable to a fake path."""
    fake_path = "/usr/bin/fake-spamassassin"
    monkeypatch.setattr(
        sa.shutil, "which", lambda exe: fake_path if exe == "fake-spamassassin" else None
    )
    return fake_path


@pytest.fixture
def mock_which_missing(monkeypatch):
    """Make `shutil.which` fail to resolve any executable."""
    monkeypatch.setattr(sa.shutil, "which", lambda exe: None)


def _completed(returncode=0, stdout=b"", stderr=b""):
    """Build a real `subprocess.CompletedProcess` without running anything."""
    return subprocess.CompletedProcess(
        args=["fake-spamassassin"], returncode=returncode, stdout=stdout, stderr=stderr
    )


def _mock_run(monkeypatch, **kwargs):
    """Patch `subprocess.run` inside the adapter module and return the mock."""
    mock_run = MagicMock(**kwargs)
    monkeypatch.setattr(sa.subprocess, "run", mock_run)
    return mock_run


# --- 1/2/3/4/5. Successful output parsing: score, threshold, decision, rules ----


def test_analyze_email_parses_successful_spam_output(config, mock_which_found, monkeypatch):
    mock_run = _mock_run(
        monkeypatch, return_value=_completed(0, stdout=SAMPLE_SPAM_STDOUT.encode("utf-8"))
    )

    result = sa.analyze_email(b"raw email bytes", config=config)

    assert isinstance(result, SpamAssassinResult)
    assert result.available is True
    assert result.error is None
    assert result.is_spam is True
    assert result.score == 15.3
    assert result.threshold == 5.0
    assert result.matched_rules == ["BAYES_99", "HTML_MESSAGE", "MIME_HTML_ONLY", "URIBL_BLACK"]
    assert result.raw_status is not None
    assert result.raw_status.startswith("X-Spam-Status: Yes,")
    assert result.engine == "spamassassin"
    mock_run.assert_called_once()


def test_analyze_email_parses_successful_ham_output(config, mock_which_found, monkeypatch):
    _mock_run(monkeypatch, return_value=_completed(0, stdout=SAMPLE_HAM_STDOUT.encode("utf-8")))

    result = sa.analyze_email("raw email text", config=config)

    assert result.available is True
    assert result.error is None
    assert result.is_spam is False
    assert result.score == -0.5
    assert result.threshold == 5.0
    assert result.matched_rules == ["BAYES_00"]


def test_score_parsing_handles_negative_and_decimal_values(config, mock_which_found, monkeypatch):
    stdout = (
        "X-Spam-Status: No, score=-3.457 required=5.0 tests=BAYES_00"
        " autolearn=ham version=3.4.6\n\nBody.\n"
    )
    _mock_run(monkeypatch, return_value=_completed(0, stdout=stdout.encode("utf-8")))

    result = sa.analyze_email("email", config=config)

    assert result.score == -3.457


def test_threshold_parsing_reflects_required_field(config, mock_which_found, monkeypatch):
    stdout = (
        "X-Spam-Status: Yes, score=9.1 required=7.5 tests=BAYES_99"
        " autolearn=no version=3.4.6\n\nBody.\n"
    )
    _mock_run(monkeypatch, return_value=_completed(0, stdout=stdout.encode("utf-8")))

    result = sa.analyze_email("email", config=config)

    assert result.threshold == 7.5


def test_spam_decision_parsing_yes_is_true(config, mock_which_found, monkeypatch):
    _mock_run(monkeypatch, return_value=_completed(0, stdout=SAMPLE_SPAM_STDOUT.encode("utf-8")))
    result = sa.analyze_email("email", config=config)
    assert result.is_spam is True


def test_spam_decision_parsing_no_is_false(config, mock_which_found, monkeypatch):
    _mock_run(monkeypatch, return_value=_completed(0, stdout=SAMPLE_HAM_STDOUT.encode("utf-8")))
    result = sa.analyze_email("email", config=config)
    assert result.is_spam is False


def test_matched_rule_extraction_unfolds_wrapped_continuation_line(
    config, mock_which_found, monkeypatch
):
    _mock_run(monkeypatch, return_value=_completed(0, stdout=SAMPLE_SPAM_STDOUT.encode("utf-8")))
    result = sa.analyze_email("email", config=config)
    # The `tests=` list spans a folded continuation line in the fixture;
    # all four rule names must still be recovered, in order, with no
    # spurious whitespace introduced by the fold.
    assert result.matched_rules == ["BAYES_99", "HTML_MESSAGE", "MIME_HTML_ONLY", "URIBL_BLACK"]


def test_matched_rule_extraction_single_rule(config, mock_which_found, monkeypatch):
    _mock_run(monkeypatch, return_value=_completed(0, stdout=SAMPLE_HAM_STDOUT.encode("utf-8")))
    result = sa.analyze_email("email", config=config)
    assert result.matched_rules == ["BAYES_00"]


def test_matched_rule_extraction_none_matched_yields_empty_list(
    config, mock_which_found, monkeypatch
):
    _mock_run(
        monkeypatch, return_value=_completed(0, stdout=SAMPLE_NO_RULES_STDOUT.encode("utf-8"))
    )
    result = sa.analyze_email("email", config=config)
    assert result.matched_rules == []


# --- 6. Bytes input handling -------------------------------------------------


def test_analyze_email_accepts_bytes_input_directly(config, mock_which_found, monkeypatch):
    mock_run = _mock_run(
        monkeypatch, return_value=_completed(0, stdout=SAMPLE_HAM_STDOUT.encode("utf-8"))
    )
    raw_bytes = b"From: a@b.com\r\n\r\nHello"

    result = sa.analyze_email(raw_bytes, config=config)

    assert result.error is None
    _, call_kwargs = mock_run.call_args
    assert call_kwargs["input"] == raw_bytes


def test_analyze_email_encodes_str_input_as_utf8_with_replace(
    config, mock_which_found, monkeypatch
):
    mock_run = _mock_run(
        monkeypatch, return_value=_completed(0, stdout=SAMPLE_HAM_STDOUT.encode("utf-8"))
    )
    raw_str = "Subject: caf\u00e9 \u2603\n\nBody"

    sa.analyze_email(raw_str, config=config)

    _, call_kwargs = mock_run.call_args
    assert call_kwargs["input"] == raw_str.encode("utf-8", errors="replace")


# --- 7. Empty input -----------------------------------------------------------


def test_analyze_email_empty_string_input_short_circuits(config, mock_which_found, monkeypatch):
    mock_run = _mock_run(monkeypatch)

    result = sa.analyze_email("", config=config)

    assert result.error == "empty input: no email content was provided"
    assert result.score is None
    assert result.is_spam is None
    assert result.available is True  # executable was found by check_available()
    mock_run.assert_not_called()


def test_analyze_email_empty_bytes_input_short_circuits(config, mock_which_missing, monkeypatch):
    mock_run = _mock_run(monkeypatch)

    result = sa.analyze_email(b"", config=config)

    assert result.error == "empty input: no email content was provided"
    assert result.available is False  # executable not found either
    mock_run.assert_not_called()


# --- 8. Executable missing -----------------------------------------------------


def test_analyze_email_executable_missing(config, mock_which_missing, monkeypatch):
    mock_run = _mock_run(monkeypatch)

    result = sa.analyze_email("some raw email", config=config)

    assert result.available is False
    assert result.error == "spamassassin executable 'fake-spamassassin' was not found"
    assert result.score is None
    assert result.is_spam is None
    mock_run.assert_not_called()


# --- 9. Timeout ----------------------------------------------------------------


def test_analyze_email_timeout(config, mock_which_found, monkeypatch):
    _mock_run(
        monkeypatch,
        side_effect=subprocess.TimeoutExpired(cmd="fake-spamassassin", timeout=5.0),
    )

    result = sa.analyze_email("some raw email", config=config)

    assert result.available is True
    assert result.error == "spamassassin timed out after 5.0s"
    assert result.score is None
    assert result.is_spam is None


# --- 10. Non-zero exit code -----------------------------------------------------


def test_analyze_email_non_zero_exit_code_reports_stderr(config, mock_which_found, monkeypatch):
    _mock_run(
        monkeypatch,
        return_value=_completed(returncode=2, stdout=b"", stderr=b"fatal: bad config file\n"),
    )

    result = sa.analyze_email("some raw email", config=config)

    assert result.available is True
    assert result.error == "spamassassin exited with code 2: fatal: bad config file"
    assert result.score is None
    assert result.is_spam is None


def test_analyze_email_non_zero_exit_code_with_no_stderr(config, mock_which_found, monkeypatch):
    _mock_run(monkeypatch, return_value=_completed(returncode=1, stdout=b"", stderr=b""))

    result = sa.analyze_email("some raw email", config=config)

    assert result.error == "spamassassin exited with code 1: "


# --- 11. Malformed output --------------------------------------------------------


def test_analyze_email_malformed_output_missing_status_header(
    config, mock_which_found, monkeypatch
):
    _mock_run(
        monkeypatch, return_value=_completed(0, stdout=SAMPLE_MALFORMED_STDOUT.encode("utf-8"))
    )

    result = sa.analyze_email("some raw email", config=config)

    assert result.available is True
    assert result.error == "unexpected spamassassin output: no X-Spam-Status header found"
    assert result.score is None
    assert result.is_spam is None
    assert result.matched_rules == []


def test_analyze_email_blank_stdout_reports_no_output(config, mock_which_found, monkeypatch):
    _mock_run(monkeypatch, return_value=_completed(0, stdout=b"   \n\t\n"))

    result = sa.analyze_email("some raw email", config=config)

    assert result.error == "spamassassin produced no output"


# --- 12. Unavailable engine result (check_available) ----------------------------


def test_check_available_true_when_executable_on_path(config, mock_which_found):
    assert sa.check_available(config) is True


def test_check_available_false_when_executable_missing(config, mock_which_missing):
    assert sa.check_available(config) is False


def test_check_available_does_not_invoke_subprocess(config, mock_which_found, monkeypatch):
    mock_run = _mock_run(monkeypatch)
    sa.check_available(config)
    mock_run.assert_not_called()


# --- 13. Configuration defaults/overrides ---------------------------------------


def test_get_spamassassin_config_defaults(monkeypatch):
    cfg = get_spamassassin_config()
    assert cfg.executable == DEFAULT_EXECUTABLE
    assert cfg.args == DEFAULT_ARGS
    assert cfg.timeout_seconds == DEFAULT_TIMEOUT_SECONDS


def test_get_spamassassin_config_executable_override(monkeypatch):
    monkeypatch.setenv(ENV_EXECUTABLE, "/opt/spamassassin/bin/spamassassin")
    cfg = get_spamassassin_config()
    assert cfg.executable == "/opt/spamassassin/bin/spamassassin"


def test_get_spamassassin_config_args_override(monkeypatch):
    monkeypatch.setenv(ENV_ARGS, "--foo --bar=baz")
    cfg = get_spamassassin_config()
    assert cfg.args == ("--foo", "--bar=baz")


def test_get_spamassassin_config_timeout_override(monkeypatch):
    monkeypatch.setenv(ENV_TIMEOUT_SECONDS, "42.5")
    cfg = get_spamassassin_config()
    assert cfg.timeout_seconds == 42.5


def test_get_spamassassin_config_blank_env_vars_fall_back_to_defaults(monkeypatch):
    monkeypatch.setenv(ENV_EXECUTABLE, "   ")
    monkeypatch.setenv(ENV_ARGS, "   ")
    monkeypatch.setenv(ENV_TIMEOUT_SECONDS, "   ")
    cfg = get_spamassassin_config()
    assert cfg.executable == DEFAULT_EXECUTABLE
    assert cfg.args == DEFAULT_ARGS
    assert cfg.timeout_seconds == DEFAULT_TIMEOUT_SECONDS


def test_get_spamassassin_config_malformed_timeout_falls_back_to_default(monkeypatch):
    monkeypatch.setenv(ENV_TIMEOUT_SECONDS, "not-a-number")
    cfg = get_spamassassin_config()
    assert cfg.timeout_seconds == DEFAULT_TIMEOUT_SECONDS


def test_spamassassin_config_is_immutable():
    cfg = SpamAssassinConfig()
    with pytest.raises(Exception):
        cfg.executable = "something-else"  # dataclass(frozen=True)


# --- 14. No shell=True behavior --------------------------------------------------


def test_analyze_email_never_uses_shell(config, mock_which_found, monkeypatch):
    mock_run = _mock_run(
        monkeypatch, return_value=_completed(0, stdout=SAMPLE_HAM_STDOUT.encode("utf-8"))
    )

    sa.analyze_email("some raw email", config=config)

    call_args, call_kwargs = mock_run.call_args
    assert call_kwargs["shell"] is False
    # The command must be an argv list of strings, never a pre-joined
    # shell string, so no shell metacharacter in the input can be
    # interpreted.
    command = call_args[0]
    assert isinstance(command, list)
    assert all(isinstance(part, str) for part in command)
    assert command[0] == "/usr/bin/fake-spamassassin"
    assert command[1:] == ["--test-mode", "--local", "--nocreate-prefs"]


def test_analyze_email_passes_timeout_from_config(config, mock_which_found, monkeypatch):
    mock_run = _mock_run(
        monkeypatch, return_value=_completed(0, stdout=SAMPLE_HAM_STDOUT.encode("utf-8"))
    )
    sa.analyze_email("some raw email", config=config)
    _, call_kwargs = mock_run.call_args
    assert call_kwargs["timeout"] == config.timeout_seconds


# --- 15. Result schema stability -------------------------------------------------


def test_result_schema_field_names_are_stable():
    expected_fields = {
        "available",
        "score",
        "threshold",
        "is_spam",
        "matched_rules",
        "raw_status",
        "error",
        "engine",
    }
    assert set(SpamAssassinResult().model_dump().keys()) == expected_fields


def test_result_schema_defaults():
    result = SpamAssassinResult()
    assert result.available is False
    assert result.score is None
    assert result.threshold is None
    assert result.is_spam is None
    assert result.matched_rules == []
    assert result.raw_status is None
    assert result.error is None
    assert result.engine == "spamassassin"


def test_result_schema_success_shape_matches_failure_shape(
    config, mock_which_found, monkeypatch
):
    """Successful and failed analyses must produce the same field set."""
    _mock_run(monkeypatch, return_value=_completed(0, stdout=SAMPLE_HAM_STDOUT.encode("utf-8")))
    success = sa.analyze_email("email", config=config)

    _mock_run(monkeypatch, return_value=_completed(returncode=1, stdout=b"", stderr=b"boom"))
    failure = sa.analyze_email("email", config=config)

    assert set(success.model_dump().keys()) == set(failure.model_dump().keys())


# --- 16. Deterministic behavior --------------------------------------------------


def test_analyze_email_is_deterministic_for_identical_input(config, mock_which_found, monkeypatch):
    _mock_run(monkeypatch, return_value=_completed(0, stdout=SAMPLE_SPAM_STDOUT.encode("utf-8")))

    first = sa.analyze_email("identical raw email", config=config)
    second = sa.analyze_email("identical raw email", config=config)

    assert first.model_dump() == second.model_dump()


def test_analyze_email_results_do_not_share_mutable_state(config, mock_which_found, monkeypatch):
    _mock_run(monkeypatch, return_value=_completed(0, stdout=SAMPLE_SPAM_STDOUT.encode("utf-8")))

    first = sa.analyze_email("identical raw email", config=config)
    second = sa.analyze_email("identical raw email", config=config)

    assert first.matched_rules is not second.matched_rules
    first.matched_rules.append("MUTATED")
    assert "MUTATED" not in second.matched_rules


# --- Bonus: OSError launching the process ----------------------------------------


def test_analyze_email_os_error_launching_process_is_reported(
    config, mock_which_found, monkeypatch
):
    _mock_run(monkeypatch, side_effect=OSError("executable removed mid-race"))

    result = sa.analyze_email("some raw email", config=config)

    assert result.available is False
    assert "failed to execute spamassassin" in result.error
    assert result.score is None
    assert result.is_spam is None
