"""Safe subprocess adapter around a locally installed SpamAssassin.

This module is an ISOLATED component: it is not imported by, and does not
call into, the risk engine, NLLB, the V2 phishing model, `analysis_service`,
threat intelligence, or the attachment scanner. It is not wired into any
production analysis flow yet.

Safety properties:
  * The raw email is passed to SpamAssassin over stdin as bytes. It is
    never interpreted as a shell command and no shell is invoked
    (`subprocess.run(..., shell=False)`, and the command is an argv list,
    never a formatted string).
  * No network calls are made by this module itself. (The default CLI
    arguments also pass `--local` to ask SpamAssassin to skip its own
    network-backed rules; if a deployment overrides `SPAMASSASSIN_ARGS` to
    remove that flag, any resulting network activity is a property of the
    SpamAssassin configuration, not of this wrapper.)
  * Every expected failure mode (missing executable, timeout, non-zero
    exit, empty input, unparsable output) is caught and reported through
    the returned `SpamAssassinResult` rather than raised.

Public API:
    check_available() -> bool
    analyze_email(raw_email) -> SpamAssassinResult
"""

from __future__ import annotations

import logging
import re
import shutil
import subprocess
from typing import Final

from .config import SpamAssassinConfig, get_spamassassin_config
from .result_schema import SpamAssassinResult

logger = logging.getLogger(__name__)

# Matches SpamAssassin's standard header, e.g.:
#   X-Spam-Status: Yes, score=15.3 required=5.0 tests=BAYES_99,HTML_MESSAGE
#       autolearn=no autolearn_force=no version=3.4.6
# Applied to header text that has already been "unfolded" (continuation
# lines joined back onto a single logical line).
_STATUS_HEADER_RE: Final = re.compile(
    r"^X-Spam-Status:\s*(?P<verdict>Yes|No)\s*,\s*(?P<fields>.*)$",
    re.IGNORECASE | re.MULTILINE,
)

# Simple numeric fields within the X-Spam-Status value.
_SCORE_RE: Final = re.compile(r"\bscore=(?P<value>-?[0-9.]+)", re.IGNORECASE)
_REQUIRED_RE: Final = re.compile(r"\brequired=(?P<value>-?[0-9.]+)", re.IGNORECASE)

# The `tests=` field is a comma-separated rule-name list. SpamAssassin line
# -wraps long header values, and unfolding a wrapped line inserts a space
# at the wrap point -- including mid-list, e.g. "...HTML_MESSAGE,\n\tFOO"
# becomes "...HTML_MESSAGE, FOO". A plain "non-whitespace" match on the
# value would stop at that inserted space and silently drop rule names.
# Instead, capture everything after "tests=" up to the next recognizable
# lowercase "key=" token (rule names are conventionally upper-case), then
# strip whitespace from the captured span before splitting on commas.
_TESTS_RE: Final = re.compile(r"\btests=(?P<tests>.*?)(?=\s+[a-z][a-z_]*=|\Z)", re.DOTALL)


def check_available(config: SpamAssassinConfig | None = None) -> bool:
    """Check whether the configured SpamAssassin executable can be found.

    This only resolves the executable on `PATH` (or as an absolute path);
    it does not invoke it, so it cannot itself time out or fail at
    runtime.

    Args:
        config: Optional explicit configuration. Defaults to the
            environment-derived configuration from `get_spamassassin_config()`.

    Returns:
        `True` if the executable was found, `False` otherwise.
    """
    cfg = config or get_spamassassin_config()
    return shutil.which(cfg.executable) is not None


def analyze_email(
    raw_email: str | bytes,
    config: SpamAssassinConfig | None = None,
) -> SpamAssassinResult:
    """Run SpamAssassin against a single raw email and return a structured result.

    The message is streamed to SpamAssassin over stdin (never as a shell
    command, never via string interpolation into a command line) and the
    process's stdout is parsed for SpamAssassin's standard
    `X-Spam-Status` header. This is spam-oriented evidence only -- the
    returned score is SpamAssassin's own heuristic score, not a phishing
    probability, and should not be treated as one by callers.

    Args:
        raw_email: The full raw email (headers + body), as `str` or
            `bytes`. `str` input is encoded as UTF-8 (with `errors="replace"`)
            before being sent to the subprocess.
        config: Optional explicit configuration. Defaults to the
            environment-derived configuration from `get_spamassassin_config()`.

    Returns:
        A `SpamAssassinResult`. This function does not raise for any of
        the expected failure modes (missing executable, timeout,
        non-zero exit code, empty input, or output that doesn't match the
        expected SpamAssassin format); those are all reported via the
        result's `error` field instead.
    """
    cfg = config or get_spamassassin_config()

    if not raw_email:
        logger.info("spamassassin.analyze_email called with empty input; skipping invocation")
        return SpamAssassinResult(
            available=check_available(cfg),
            error="empty input: no email content was provided",
        )

    if isinstance(raw_email, str):
        payload = raw_email.encode("utf-8", errors="replace")
    else:
        payload = raw_email

    executable_path = shutil.which(cfg.executable)
    if executable_path is None:
        logger.warning("SpamAssassin executable %r was not found on PATH", cfg.executable)
        return SpamAssassinResult(
            available=False,
            error=f"spamassassin executable '{cfg.executable}' was not found",
        )

    command = [executable_path, *cfg.args]

    try:
        completed = subprocess.run(  # noqa: S603 - argv list, shell=False, no untrusted string is executed
            command,
            input=payload,
            capture_output=True,
            timeout=cfg.timeout_seconds,
            shell=False,
            check=False,
        )
    except subprocess.TimeoutExpired:
        logger.warning("SpamAssassin timed out after %s seconds", cfg.timeout_seconds)
        return SpamAssassinResult(
            available=True,
            error=f"spamassassin timed out after {cfg.timeout_seconds}s",
        )
    except OSError as exc:
        # Covers races (executable removed between the `which` check and
        # exec) and other OS-level failures to launch the process.
        logger.exception("Failed to execute SpamAssassin")
        return SpamAssassinResult(
            available=False,
            error=f"failed to execute spamassassin: {exc}",
        )

    if completed.returncode != 0:
        stderr_text = completed.stderr.decode("utf-8", errors="replace").strip() if completed.stderr else ""
        logger.warning("SpamAssassin exited with code %s: %s", completed.returncode, stderr_text)
        return SpamAssassinResult(
            available=True,
            error=f"spamassassin exited with code {completed.returncode}: {stderr_text[:500]}",
        )

    stdout_text = completed.stdout.decode("utf-8", errors="replace") if completed.stdout else ""
    return _parse_output(stdout_text)


def _parse_output(stdout_text: str) -> SpamAssassinResult:
    """Parse SpamAssassin's stdout into a `SpamAssassinResult`.

    Looks for the `X-Spam-Status:` header that SpamAssassin inserts into
    every message it processes in test mode, after unfolding wrapped
    header continuation lines (SpamAssassin wraps long `tests=` lists
    across multiple lines).

    Args:
        stdout_text: Decoded stdout from a successful (`returncode == 0`)
            SpamAssassin invocation.

    Returns:
        A `SpamAssassinResult` with `available=True`. If the expected
        header cannot be found or the message body was empty, `error` is
        set and the score/verdict fields are left `None`.
    """
    if not stdout_text.strip():
        logger.warning("SpamAssassin produced no output")
        return SpamAssassinResult(available=True, error="spamassassin produced no output")

    # Unfold RFC 5322 header continuation lines: a wrapped line starts
    # with whitespace, so join it back onto the previous line with a
    # single space.
    unfolded = re.sub(r"\r?\n[ \t]+", " ", stdout_text)

    match = _STATUS_HEADER_RE.search(unfolded)
    if match is None:
        logger.warning("Could not find an X-Spam-Status header in spamassassin output")
        return SpamAssassinResult(
            available=True,
            error="unexpected spamassassin output: no X-Spam-Status header found",
        )

    fields_text = match.group("fields")
    is_spam = match.group("verdict").strip().lower() == "yes"

    score = _extract_float(_SCORE_RE, fields_text)
    threshold = _extract_float(_REQUIRED_RE, fields_text)
    matched_rules = _extract_matched_rules(fields_text)

    return SpamAssassinResult(
        available=True,
        score=score,
        threshold=threshold,
        is_spam=is_spam,
        matched_rules=matched_rules,
        raw_status=match.group(0).strip(),
    )


def _extract_float(pattern: re.Pattern[str], fields_text: str) -> float | None:
    """Extract and parse a single numeric field, returning `None` if absent or malformed."""
    found = pattern.search(fields_text)
    if not found:
        return None
    try:
        return float(found.group("value"))
    except ValueError:
        return None


def _extract_matched_rules(fields_text: str) -> list[str]:
    """Extract the `tests=` rule-name list, tolerating SpamAssassin's line wrapping."""
    found = _TESTS_RE.search(fields_text)
    if not found:
        return []
    raw_tests = re.sub(r"\s+", "", found.group("tests"))
    if not raw_tests or raw_tests.lower() == "none":
        return []
    return [rule for rule in raw_tests.split(",") if rule]
