#!/usr/bin/env python3
"""Benchmark the isolated SpamAssassin adapter over a local dataset of .eml files.

This is a standalone evaluation tool for ``backend.app.spam`` (the isolated
SpamAssassin adapter). It does NOT modify, import from, or otherwise touch
the risk engine, NLLB, the V2 classifier/model, ``analysis_service.py``, any
existing tests, or the contents of any existing dataset. It only *reads*
`.eml` files (and, optionally, a labels manifest) that the caller points it
at.

IMPORTANT -- spam vs. phishing:
    SpamAssassin's verdict is spam-oriented evidence produced by its own
    heuristic rule base. It is NOT a phishing classifier, and this script
    never treats a "phishing" ground-truth label as if it were a "spam"
    ground-truth label. False positive/negative rates are only computed
    against an explicit, correctly-named spam ground-truth column
    (``spam_label``). If a dataset only has a ``phishing_label`` column,
    that is reported purely as descriptive context (e.g. "how often did
    SpamAssassin flag messages that happen to be labeled phishing"), never
    folded into accuracy/precision/recall-style statistics.

Dataset input:
    A directory of raw email files (``--dataset-dir``), each ending in
    ``.eml`` by default (configurable via ``--extension``). Files are
    processed in sorted (deterministic) filename order.

Optional labels manifest (``--manifest``):
    A CSV file with a header row and at least a ``filename`` column
    (matched against the basename of files in the dataset directory).
    Recognized optional columns:
        spam_label       -- ground-truth spam/ham label for this message.
        phishing_label    -- ground-truth phishing/benign label for this
                              message. Informational only; never used as a
                              spam ground truth.
    Label values are parsed case-insensitively; accepted truthy values are
    {"1", "true", "yes", "spam", "phishing"} and falsy values are
    {"0", "false", "no", "ham", "benign"}. Anything else is treated as
    "unlabeled" for that row/column, with a warning.

Smoke-test mode (``--smoke-test``):
    Processes only the first N files (default 5, override with
    ``--smoke-test-size``) in sorted order, for a fast, deterministic
    sanity check that the adapter and dataset wiring both work.

Safety:
    This script makes no network calls itself. The underlying adapter also
    invokes SpamAssassin with ``--local`` by default (see
    ``backend/app/spam/config.py``); if that default is overridden via the
    ``SPAMASSASSIN_ARGS`` environment variable, any resulting network
    activity is a property of that SpamAssassin configuration, not of this
    script.

Usage:
    python scripts/spamassassin_benchmark.py --dataset-dir data/emails
    python scripts/spamassassin_benchmark.py --dataset-dir data/emails --manifest labels.csv
    python scripts/spamassassin_benchmark.py --dataset-dir data/emails --smoke-test
    python scripts/spamassassin_benchmark.py --dataset-dir data/emails --json
"""

from __future__ import annotations

import argparse
import csv
import json
import statistics
import sys
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any

_REPO_ROOT = Path(__file__).resolve().parent.parent
if str(_REPO_ROOT) not in sys.path:
    sys.path.insert(0, str(_REPO_ROOT))

try:
    from backend.app.spam import SpamAssassinConfig, analyze_email, check_available, get_spamassassin_config
except ImportError as exc:  # pragma: no cover - environment/setup error, not adapter logic
    print(
        f"error: could not import the SpamAssassin adapter (backend.app.spam): {exc}\n"
        f"       expected it to be importable from repository root: {_REPO_ROOT}",
        file=sys.stderr,
    )
    sys.exit(3)


DEFAULT_SMOKE_TEST_SIZE = 5

_TRUTHY = {"1", "true", "yes", "spam", "phishing"}
_FALSY = {"0", "false", "no", "ham", "benign"}


def _parse_bool_label(raw: str | None) -> bool | None:
    """Parse a manifest label cell into True/False/None (unlabeled)."""
    if raw is None:
        return None
    normalized = raw.strip().lower()
    if not normalized:
        return None
    if normalized in _TRUTHY:
        return True
    if normalized in _FALSY:
        return False
    return None


@dataclass
class ManifestEntry:
    spam_label: bool | None = None
    phishing_label: bool | None = None


def load_manifest(path: Path) -> dict[str, ManifestEntry]:
    """Load an optional CSV labels manifest keyed by filename.

    Recognized columns: ``filename`` (required), ``spam_label`` (optional),
    ``phishing_label`` (optional). Unrecognized columns are ignored. Rows
    missing ``filename`` are skipped with a warning.
    """
    entries: dict[str, ManifestEntry] = {}
    with path.open(newline="", encoding="utf-8", errors="replace") as handle:
        reader = csv.DictReader(handle)
        if reader.fieldnames is None or "filename" not in reader.fieldnames:
            raise ValueError(f"manifest {path} must have a header row containing a 'filename' column")
        for row_number, row in enumerate(reader, start=2):  # header is line 1
            filename = (row.get("filename") or "").strip()
            if not filename:
                print(f"warning: manifest row {row_number} has no filename, skipping", file=sys.stderr)
                continue
            entries[filename] = ManifestEntry(
                spam_label=_parse_bool_label(row.get("spam_label")),
                phishing_label=_parse_bool_label(row.get("phishing_label")),
            )
    return entries


@dataclass
class SampleOutcome:
    filename: str
    available: bool
    error: str | None
    is_spam: bool | None
    score: float | None
    threshold: float | None
    matched_rule_count: int
    spam_label: bool | None = None
    phishing_label: bool | None = None


@dataclass
class BenchmarkReport:
    total_files: int
    processed: int
    failed: int
    smoke_test: bool
    spam_decisions: dict[str, int]
    score_summary: dict[str, float | int | None]
    ground_truth: dict[str, Any]
    failures: list[dict[str, str]] = field(default_factory=list)

    def to_dict(self) -> dict[str, Any]:
        return {
            "total_files": self.total_files,
            "processed": self.processed,
            "failed": self.failed,
            "smoke_test": self.smoke_test,
            "spam_decisions": self.spam_decisions,
            "score_summary": self.score_summary,
            "ground_truth": self.ground_truth,
            "failures": self.failures,
        }


def discover_dataset_files(dataset_dir: Path, extension: str) -> list[Path]:
    """Return dataset files with the given extension, sorted for determinism."""
    suffix = extension if extension.startswith(".") else f".{extension}"
    return sorted(p for p in dataset_dir.iterdir() if p.is_file() and p.suffix.lower() == suffix.lower())


def run_benchmark(
    files: list[Path],
    manifest: dict[str, ManifestEntry],
    config: SpamAssassinConfig,
) -> list[SampleOutcome]:
    """Run the adapter over each file in order and collect per-sample outcomes."""
    outcomes: list[SampleOutcome] = []
    for path in files:
        entry = manifest.get(path.name, ManifestEntry())
        try:
            raw_email = path.read_bytes()
        except OSError as exc:
            outcomes.append(
                SampleOutcome(
                    filename=path.name,
                    available=False,
                    error=f"could not read file: {exc}",
                    is_spam=None,
                    score=None,
                    threshold=None,
                    matched_rule_count=0,
                    spam_label=entry.spam_label,
                    phishing_label=entry.phishing_label,
                )
            )
            continue

        result = analyze_email(raw_email, config=config)
        outcomes.append(
            SampleOutcome(
                filename=path.name,
                available=result.available,
                error=result.error,
                is_spam=result.is_spam,
                score=result.score,
                threshold=result.threshold,
                matched_rule_count=len(result.matched_rules),
                spam_label=entry.spam_label,
                phishing_label=entry.phishing_label,
            )
        )
    return outcomes


def summarize_scores(outcomes: list[SampleOutcome]) -> dict[str, float | int | None]:
    """Summarize the distribution of numeric SpamAssassin scores among successful runs."""
    scores = [o.score for o in outcomes if o.score is not None]
    if not scores:
        return {"count": 0, "min": None, "max": None, "mean": None, "median": None, "stdev": None}
    return {
        "count": len(scores),
        "min": min(scores),
        "max": max(scores),
        "mean": round(statistics.fmean(scores), 4),
        "median": round(statistics.median(scores), 4),
        "stdev": round(statistics.pstdev(scores), 4) if len(scores) > 1 else 0.0,
    }


def summarize_spam_decisions(outcomes: list[SampleOutcome]) -> dict[str, int]:
    """Count SpamAssassin's own spam/ham/unknown verdicts."""
    counts = {"spam": 0, "ham": 0, "unknown": 0}
    for outcome in outcomes:
        if outcome.is_spam is True:
            counts["spam"] += 1
        elif outcome.is_spam is False:
            counts["ham"] += 1
        else:
            counts["unknown"] += 1
    return counts


def summarize_ground_truth(outcomes: list[SampleOutcome]) -> dict[str, Any]:
    """Summarize ground-truth-related statistics.

    Spam-vs-ham accuracy figures (false positives/negatives) are computed
    ONLY against `spam_label` -- never against `phishing_label`, since a
    message being labeled phishing does not make it spam ground truth.
    `phishing_label` is summarized separately, purely as descriptive
    context about how SpamAssassin's verdict overlapped with a *different*
    ground truth, not as an accuracy claim about SpamAssassin-as-a-
    phishing-detector.
    """
    has_spam_labels = any(o.spam_label is not None for o in outcomes)
    has_phishing_labels = any(o.phishing_label is not None for o in outcomes)

    result: dict[str, Any] = {
        "spam_ground_truth_available": has_spam_labels,
        "phishing_ground_truth_available": has_phishing_labels,
    }

    if has_spam_labels:
        tp = fp = tn = fn = unlabeled_or_unavailable = 0
        for o in outcomes:
            if o.spam_label is None or o.is_spam is None:
                unlabeled_or_unavailable += 1
                continue
            if o.spam_label and o.is_spam:
                tp += 1
            elif not o.spam_label and o.is_spam:
                fp += 1
            elif not o.spam_label and not o.is_spam:
                tn += 1
            elif o.spam_label and not o.is_spam:
                fn += 1
        scored = tp + fp + tn + fn
        result["spam_vs_ham"] = {
            "true_positives": tp,
            "false_positives": fp,
            "true_negatives": tn,
            "false_negatives": fn,
            "excluded_unlabeled_or_unavailable": unlabeled_or_unavailable,
            "accuracy": round((tp + tn) / scored, 4) if scored else None,
        }
    else:
        result["spam_vs_ham"] = None

    if has_phishing_labels:
        # Descriptive overlap only -- explicitly NOT called precision/recall
        # or false positive/negative, because phishing_label is not spam
        # ground truth.
        phishing_and_flagged_spam = 0
        phishing_and_not_flagged_spam = 0
        benign_and_flagged_spam = 0
        benign_and_not_flagged_spam = 0
        excluded = 0
        for o in outcomes:
            if o.phishing_label is None or o.is_spam is None:
                excluded += 1
                continue
            if o.phishing_label and o.is_spam:
                phishing_and_flagged_spam += 1
            elif o.phishing_label and not o.is_spam:
                phishing_and_not_flagged_spam += 1
            elif not o.phishing_label and o.is_spam:
                benign_and_flagged_spam += 1
            else:
                benign_and_not_flagged_spam += 1
        result["phishing_label_overlap"] = {
            "note": (
                "Descriptive overlap between SpamAssassin's spam verdict and a "
                "phishing/benign label. NOT an accuracy, precision, or recall "
                "claim -- SpamAssassin is a spam detector, not a phishing "
                "detector, and 'phishing' is not spam ground truth."
            ),
            "phishing_labeled_and_flagged_spam": phishing_and_flagged_spam,
            "phishing_labeled_and_not_flagged_spam": phishing_and_not_flagged_spam,
            "benign_labeled_and_flagged_spam": benign_and_flagged_spam,
            "benign_labeled_and_not_flagged_spam": benign_and_not_flagged_spam,
            "excluded_unlabeled_or_unavailable": excluded,
        }
    else:
        result["phishing_label_overlap"] = None

    return result


def build_report(outcomes: list[SampleOutcome], total_files: int, smoke_test: bool) -> BenchmarkReport:
    failed = [o for o in outcomes if o.error is not None]
    return BenchmarkReport(
        total_files=total_files,
        processed=len(outcomes),
        failed=len(failed),
        smoke_test=smoke_test,
        spam_decisions=summarize_spam_decisions(outcomes),
        score_summary=summarize_scores(outcomes),
        ground_truth=summarize_ground_truth(outcomes),
        failures=[{"filename": o.filename, "error": o.error or ""} for o in failed],
    )


def format_text_report(report: BenchmarkReport) -> str:
    lines = [
        "SpamAssassin benchmark report",
        "==============================",
        f"smoke_test:        {report.smoke_test}",
        f"total_files_found: {report.total_files}",
        f"processed:         {report.processed}",
        f"failed:            {report.failed}",
        "",
        "Spam decisions (SpamAssassin's own verdict):",
        f"  spam:    {report.spam_decisions['spam']}",
        f"  ham:     {report.spam_decisions['ham']}",
        f"  unknown: {report.spam_decisions['unknown']}",
        "",
        "Score distribution:",
    ]
    summary = report.score_summary
    lines.append(f"  count:  {summary['count']}")
    lines.append(f"  min:    {summary['min']}")
    lines.append(f"  max:    {summary['max']}")
    lines.append(f"  mean:   {summary['mean']}")
    lines.append(f"  median: {summary['median']}")
    lines.append(f"  stdev:  {summary['stdev']}")

    gt = report.ground_truth
    lines.append("")
    lines.append("Ground truth:")
    if gt["spam_vs_ham"] is None:
        lines.append("  spam_label ground truth: not provided (no false-positive/negative stats computed)")
    else:
        sv = gt["spam_vs_ham"]
        lines.append("  spam_label ground truth (spam vs. ham):")
        lines.append(f"    true_positives:  {sv['true_positives']}")
        lines.append(f"    false_positives: {sv['false_positives']}")
        lines.append(f"    true_negatives:  {sv['true_negatives']}")
        lines.append(f"    false_negatives: {sv['false_negatives']}")
        lines.append(f"    excluded:        {sv['excluded_unlabeled_or_unavailable']}")
        lines.append(f"    accuracy:        {sv['accuracy']}")

    if gt["phishing_label_overlap"] is None:
        lines.append("  phishing_label ground truth: not provided")
    else:
        po = gt["phishing_label_overlap"]
        lines.append("  phishing_label overlap (descriptive only, NOT spam accuracy):")
        lines.append(f"    phishing & flagged spam:     {po['phishing_labeled_and_flagged_spam']}")
        lines.append(f"    phishing & not flagged spam: {po['phishing_labeled_and_not_flagged_spam']}")
        lines.append(f"    benign & flagged spam:       {po['benign_labeled_and_flagged_spam']}")
        lines.append(f"    benign & not flagged spam:   {po['benign_labeled_and_not_flagged_spam']}")
        lines.append(f"    excluded:                    {po['excluded_unlabeled_or_unavailable']}")

    if report.failures:
        lines.append("")
        lines.append(f"Failures ({len(report.failures)}):")
        for failure in report.failures[:20]:
            lines.append(f"  - {failure['filename']}: {failure['error']}")
        if len(report.failures) > 20:
            lines.append(f"  ... and {len(report.failures) - 20} more")

    return "\n".join(lines)


def build_arg_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(
        prog="spamassassin_benchmark.py",
        description=(
            "Run the isolated SpamAssassin adapter over a local dataset of "
            ".eml files and report aggregate statistics."
        ),
    )
    parser.add_argument(
        "--dataset-dir",
        type=Path,
        required=True,
        help="Directory containing raw email files to evaluate.",
    )
    parser.add_argument(
        "--extension",
        type=str,
        default=".eml",
        help="File extension (within --dataset-dir) to treat as email samples. Default: .eml",
    )
    parser.add_argument(
        "--manifest",
        type=Path,
        default=None,
        help=(
            "Optional CSV file with a 'filename' column and optional "
            "'spam_label' / 'phishing_label' ground-truth columns."
        ),
    )
    parser.add_argument(
        "--smoke-test",
        action="store_true",
        help=f"Only process the first N files (default N={DEFAULT_SMOKE_TEST_SIZE}) for a quick sanity check.",
    )
    parser.add_argument(
        "--smoke-test-size",
        type=int,
        default=DEFAULT_SMOKE_TEST_SIZE,
        help=f"Number of files to process in --smoke-test mode. Default: {DEFAULT_SMOKE_TEST_SIZE}",
    )
    parser.add_argument(
        "--json",
        action="store_true",
        help="Print the report as JSON instead of plain text.",
    )
    return parser


def main(argv: list[str] | None = None) -> int:
    parser = build_arg_parser()
    args = parser.parse_args(argv)

    if not args.dataset_dir.exists() or not args.dataset_dir.is_dir():
        print(f"error: --dataset-dir does not exist or is not a directory: {args.dataset_dir}", file=sys.stderr)
        return 3

    config = get_spamassassin_config()
    if not check_available(config):
        print(
            f"error: spamassassin executable '{config.executable}' was not found; "
            "cannot run benchmark",
            file=sys.stderr,
        )
        return 2

    manifest: dict[str, ManifestEntry] = {}
    if args.manifest is not None:
        try:
            manifest = load_manifest(args.manifest)
        except (OSError, ValueError) as exc:
            print(f"error: could not load manifest {args.manifest}: {exc}", file=sys.stderr)
            return 3

    all_files = discover_dataset_files(args.dataset_dir, args.extension)
    if not all_files:
        print(f"error: no files with extension '{args.extension}' found in {args.dataset_dir}", file=sys.stderr)
        return 3

    files_to_run = all_files[: args.smoke_test_size] if args.smoke_test else all_files

    outcomes = run_benchmark(files_to_run, manifest, config)
    report = build_report(outcomes, total_files=len(all_files), smoke_test=args.smoke_test)

    if args.json:
        print(json.dumps(report.to_dict(), indent=2, sort_keys=False))
    else:
        print(format_text_report(report))

    return 0


if __name__ == "__main__":
    sys.exit(main())
