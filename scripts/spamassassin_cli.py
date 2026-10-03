#!/usr/bin/env python3
"""Command-line tool for running the isolated SpamAssassin adapter on a single .eml file.

This is a thin, standalone wrapper around ``backend.app.spam`` (the isolated
SpamAssassin adapter). It does NOT modify, import from, or otherwise touch
the risk engine, NLLB, the V2 classifier/model, ``analysis_service.py``, or
any existing tests/datasets. It exists purely as an operator/debugging tool
for exercising the adapter against a real email file from the command line.

Usage:
    python scripts/spamassassin_cli.py path/to/message.eml
    python scripts/spamassassin_cli.py path/to/message.eml --rules
    python scripts/spamassassin_cli.py path/to/message.eml --json
    python scripts/spamassassin_cli.py path/to/message.eml --timeout 30

Exit codes:
    0  Analysis completed successfully; message was NOT classified as spam.
    1  Analysis completed successfully; message WAS classified as spam.
    2  The adapter could not produce a verdict (executable missing, the
       subprocess timed out, SpamAssassin exited non-zero, or its output
       could not be parsed). See the printed ``error`` field.
    3  Usage/input error: the file does not exist, is not a file, or could
       not be read.

Notes:
    SpamAssassin's score is spam-oriented evidence only. It is a distinct
    signal from phishing probability produced elsewhere in this project's
    pipeline (e.g. the V2 phishing model) and this tool makes no attempt to
    reconcile or merge the two.
"""

from __future__ import annotations

import argparse
import json
import sys
from pathlib import Path

# Make the isolated adapter importable when this script is run directly
# (e.g. `python scripts/spamassassin_cli.py ...`) without requiring the
# repository to be installed as a package. This only adjusts `sys.path`;
# it does not modify anything under backend/app/spam.
_REPO_ROOT = Path(__file__).resolve().parent.parent
if str(_REPO_ROOT) not in sys.path:
    sys.path.insert(0, str(_REPO_ROOT))

try:
    from backend.app.spam import (
        SpamAssassinResult,
        analyze_email,
        check_available,
        get_spamassassin_config,
    )
except ImportError as exc:  # pragma: no cover - environment/setup error, not adapter logic
    print(
        f"error: could not import the SpamAssassin adapter (backend.app.spam): {exc}\n"
        f"       expected it to be importable from repository root: {_REPO_ROOT}",
        file=sys.stderr,
    )
    sys.exit(3)


EXIT_HAM = 0
EXIT_SPAM = 1
EXIT_ADAPTER_ERROR = 2
EXIT_USAGE_ERROR = 3


def build_arg_parser() -> argparse.ArgumentParser:
    """Build the CLI's argument parser."""
    parser = argparse.ArgumentParser(
        prog="spamassassin_cli.py",
        description=(
            "Run the isolated SpamAssassin adapter against a single raw email "
            "(.eml) file and print a compact, structured result."
        ),
    )
    parser.add_argument(
        "eml_file",
        type=Path,
        help="Path to a raw email file (.eml) to analyze.",
    )
    parser.add_argument(
        "--rules",
        action="store_true",
        help="Also print the list of SpamAssassin rules that matched.",
    )
    parser.add_argument(
        "--json",
        action="store_true",
        help="Print the result as a single JSON object instead of plain text.",
    )
    parser.add_argument(
        "--timeout",
        type=float,
        default=None,
        metavar="SECONDS",
        help=(
            "Override the subprocess timeout in seconds for this run "
            "(defaults to the adapter's configured/env-derived timeout)."
        ),
    )
    parser.add_argument(
        "--executable",
        type=str,
        default=None,
        metavar="PATH",
        help=(
            "Override which SpamAssassin executable to invoke for this run "
            "(defaults to the adapter's configured/env-derived executable)."
        ),
    )
    return parser


def _read_eml_bytes(path: Path) -> bytes:
    """Read raw email bytes from ``path``, raising ``ValueError`` on any input problem."""
    if not path.exists():
        raise ValueError(f"file not found: {path}")
    if not path.is_file():
        raise ValueError(f"not a file: {path}")
    try:
        data = path.read_bytes()
    except OSError as exc:
        raise ValueError(f"could not read file: {exc}") from exc
    if not data:
        raise ValueError(f"file is empty: {path}")
    return data


def _format_text_result(path: Path, result: "SpamAssassinResult", show_rules: bool) -> str:
    """Render a `SpamAssassinResult` as a compact, human-readable block."""
    lines = [
        f"file:        {path}",
        f"engine:      {result.engine}",
        f"available:   {result.available}",
    ]
    if result.error:
        lines.append(f"error:       {result.error}")
    lines.append(f"is_spam:     {result.is_spam if result.is_spam is not None else 'n/a'}")
    lines.append(f"score:       {result.score if result.score is not None else 'n/a'}")
    lines.append(f"threshold:   {result.threshold if result.threshold is not None else 'n/a'}")
    lines.append(f"rules_hit:   {len(result.matched_rules)}")
    if show_rules:
        if result.matched_rules:
            lines.append("matched_rules:")
            lines.extend(f"  - {rule}" for rule in result.matched_rules)
        else:
            lines.append("matched_rules:  (none)")
    return "\n".join(lines)


def main(argv: list[str] | None = None) -> int:
    parser = build_arg_parser()
    args = parser.parse_args(argv)

    try:
        raw_email = _read_eml_bytes(args.eml_file)
    except ValueError as exc:
        print(f"error: {exc}", file=sys.stderr)
        return EXIT_USAGE_ERROR

    config = get_spamassassin_config()
    if args.timeout is not None or args.executable is not None:
        config = config.__class__(
            executable=args.executable or config.executable,
            args=config.args,
            timeout_seconds=args.timeout if args.timeout is not None else config.timeout_seconds,
        )

    if not check_available(config):
        message = f"spamassassin executable '{config.executable}' was not found"
        if args.json:
            print(json.dumps({"available": False, "error": message, "engine": "spamassassin"}))
        else:
            print(f"error: {message}", file=sys.stderr)
        return EXIT_ADAPTER_ERROR

    result = analyze_email(raw_email, config=config)

    if args.json:
        print(result.model_dump_json())
    else:
        print(_format_text_result(args.eml_file, result, args.rules))

    if result.error is not None or result.is_spam is None:
        return EXIT_ADAPTER_ERROR
    return EXIT_SPAM if result.is_spam else EXIT_HAM


if __name__ == "__main__":
    sys.exit(main())
