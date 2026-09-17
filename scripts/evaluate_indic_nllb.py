#!/usr/bin/env python
"""
ValorProtects -- Indic NLLB Evaluation Harness
==============================================

Compares two classification paths over the synthetic Indic evaluation set:

    Path A (baseline)     raw Indic text -------------------------> V2
    Path B (translation)  Indic text --> NLLB-200 --> English ----> V2

The same email is evaluated by both paths, so the comparison is *paired* at
the sample level.

Design contract
---------------
* Nothing in this script modifies production behaviour.  It calls the
  production classifier read-only and the NLLB prototype read-only.
* Every operation has an explicit status.  A failed translation or a failed
  classifier call is NEVER silently converted into a "legitimate" prediction:
  the prediction stays ``None`` and the sample is excluded from the metric
  denominators (and counted as a failure instead).
* Every metric carries its own explicit denominator (``*_evaluated_n``).
* Ordering is deterministic: samples are sorted by (language, id) and all
  outputs are emitted in that order.
* No hidden global state.  The classifier and translator are injected into
  :func:`evaluate_samples`; the defaults are resolved lazily so that importing
  this module never loads the V2 pickles or the NLLB weights.  This keeps the
  unit tests model-free.

Usage
-----
    # Full benchmark on the real machine (loads V2 + NLLB):
    python scripts/evaluate_indic_nllb.py

    # Quick smoke test with no model at all:
    python scripts/evaluate_indic_nllb.py --dry-run --max-per-lang 5

    # Single language:
    python scripts/evaluate_indic_nllb.py --lang hin_Deva

Outputs (written to datasets/evaluation/indic/results/ unless --no-save):
    indic_nllb_benchmark.json    full machine-readable report
    indic_nllb_benchmark.csv     per-language + macro/micro metric rows
    indic_nllb_per_sample.csv    one row per sample, incl. translated text

ADVISORY
--------
Path-B numbers are prototype-only.  They are the production V2 classifier
applied to NLLB output for offline evaluation.  They do not affect any risk
score, stored scan result, or live pipeline, and -- because the dataset is
synthetic and template-derived -- they are NOT evidence of production accuracy.
"""
from __future__ import annotations

import argparse
import csv
import hashlib
import json
import math
import platform
import statistics
import sys
import time
from dataclasses import asdict, dataclass, field
from enum import Enum
from pathlib import Path
from typing import Callable, Iterable, Optional, Sequence

# ---------------------------------------------------------------------------
# Path setup
# ---------------------------------------------------------------------------
_SCRIPT_DIR = Path(__file__).resolve().parent
_PROJECT_ROOT = _SCRIPT_DIR.parent
if str(_PROJECT_ROOT) not in sys.path:
    sys.path.insert(0, str(_PROJECT_ROOT))

# language_codes is a pure-data module (no torch, no pickles) so importing it
# at module level is safe for model-free tests.
from backend.app.multilingual.language_codes import SUPPORTED_LANGUAGES

HARNESS_VERSION = "2.0.0"

# ---------------------------------------------------------------------------
# Constants
# ---------------------------------------------------------------------------
DEFAULT_DATASET = _PROJECT_ROOT / "datasets" / "evaluation" / "indic" / "indic_eval.csv"
DEFAULT_RESULTS_DIR = _PROJECT_ROOT / "datasets" / "evaluation" / "indic" / "results"

JSON_FILENAME = "indic_nllb_benchmark.json"
CSV_FILENAME = "indic_nllb_benchmark.csv"
PER_SAMPLE_FILENAME = "indic_nllb_per_sample.csv"

#: phishing_probability is on a 0-100 scale; >= threshold means "phishing".
PHISHING_THRESHOLD = 50.0

#: Identifier of the classifier under test (recorded in the run metadata).
CLASSIFIER_PATH = "backend/app/models/v2"
CLASSIFIER_ENTRYPOINT = "backend.app.services.ml_classifier.classify_email"

REQUIRED_COLUMNS = ("id", "language", "text", "label")

#: Number of disagreement examples stored per direction by default.
DEFAULT_EXAMPLE_LIMIT = 10

#: Characters of source/translated text kept in the disagreement examples.
EXAMPLE_TEXT_CHARS = 400


# ---------------------------------------------------------------------------
# Status enums
# ---------------------------------------------------------------------------

class OpStatus(str, Enum):
    """Outcome of a single classifier call."""

    OK = "ok"
    FAILED = "failed"
    #: Not attempted because an upstream step (translation) did not succeed.
    SKIPPED = "skipped"


class TransStatus(str, Enum):
    """
    Outcome of the translation step, mirroring
    :class:`backend.app.multilingual.nllb_translator.TranslationStatus`
    plus the two statuses this harness can produce on its own.
    """

    TRANSLATED = "translated"
    ENGLISH_BYPASS = "english_bypass"
    UNSUPPORTED_LANGUAGE = "unsupported_language"
    TRANSLATION_FAILED = "translation_failed"
    #: --dry-run stub produced this result; no model was loaded.
    DRY_RUN = "dry_run"
    #: --dry-run stub deliberately simulated a failure.
    DRY_RUN_FAILED = "dry_run_failed"


# ---------------------------------------------------------------------------
# Dataset structures
# ---------------------------------------------------------------------------

@dataclass(frozen=True)
class Sample:
    """One validated dataset row."""

    id: int
    language: str
    language_name: str
    text: str
    label: int
    source: str = "synthetic"
    notes: str = ""


@dataclass(frozen=True)
class DatasetIssue:
    """A malformed row. Reported, never silently dropped."""

    row_number: int  # 1-based, excluding the header
    sample_id: Optional[str]
    reason: str


@dataclass(frozen=True)
class DatasetLoad:
    """Result of :func:`load_dataset`."""

    samples: list[Sample]
    issues: list[DatasetIssue]
    rows_read: int
    path: str
    sha256: str


# ---------------------------------------------------------------------------
# Operation outcomes (injectable boundaries)
# ---------------------------------------------------------------------------

@dataclass(frozen=True)
class ClassifyOutcome:
    """Result of one classifier call. Never raises to the caller."""

    status: OpStatus
    phishing_probability: Optional[float]
    latency_s: Optional[float]
    error: Optional[str] = None


@dataclass(frozen=True)
class TranslateOutcome:
    """Result of one translation call. Never raises to the caller."""

    status: TransStatus
    translated_text: Optional[str]
    latency_s: Optional[float]
    error: Optional[str] = None

    @property
    def ok(self) -> bool:
        return self.status is TransStatus.TRANSLATED and bool(self.translated_text)


ClassifierFn = Callable[[str], ClassifyOutcome]
TranslatorFn = Callable[[str, str], TranslateOutcome]


# ---------------------------------------------------------------------------
# Per-sample record
# ---------------------------------------------------------------------------

@dataclass
class SampleResult:
    """
    Complete record for one email, covering both paths.

    Correctness fields are ``None`` whenever the corresponding path did not
    produce a prediction.  ``None`` means "no verdict", never "legitimate".
    """

    id: int
    language: str
    language_name: str
    label: int

    # Path A
    baseline_status: str
    baseline_phishing_prob: Optional[float]
    baseline_pred: Optional[int]
    baseline_latency_s: Optional[float]
    baseline_error: Optional[str]

    # Path B, step 1: translation
    translation_status: str
    translated_text: Optional[str]
    translation_latency_s: Optional[float]
    translation_error: Optional[str]

    # Path B, step 2: classification of the translated text
    translated_status: str
    translated_phishing_prob: Optional[float]
    translated_pred: Optional[int]
    translated_classifier_latency_s: Optional[float]
    translated_error: Optional[str]

    # Derived
    path_b_total_latency_s: Optional[float]
    baseline_correct: Optional[bool]
    path_b_correct: Optional[bool]
    paired_evaluable: bool

    @property
    def translation_ok(self) -> bool:
        return self.translation_status == TransStatus.TRANSLATED.value

    @property
    def path_b_evaluated(self) -> bool:
        return self.translated_pred is not None


# ---------------------------------------------------------------------------
# Metric structures
# ---------------------------------------------------------------------------

@dataclass(frozen=True)
class ConfusionMetrics:
    """
    Binary metrics with the positive class = phishing (label 1).

    ``n`` is the explicit denominator: the number of samples that produced a
    usable prediction.  Failures are not in here.  ``None`` means undefined
    (empty denominator), which is different from 0.0.
    """

    n: int
    tp: int
    tn: int
    fp: int
    fn: int
    n_actual_positive: int
    n_actual_negative: int
    n_predicted_positive: int
    accuracy: Optional[float]
    precision: Optional[float]
    recall: Optional[float]
    f1: Optional[float]


@dataclass(frozen=True)
class LatencyStats:
    """Latency summary over SUCCESSFUL operations only."""

    count: int
    mean_s: Optional[float]
    median_s: Optional[float]
    p95_s: Optional[float]


@dataclass(frozen=True)
class PairedCounts:
    """
    Sample-level paired outcome counts.

    Only samples where BOTH paths produced a prediction are counted.
    """

    n_paired: int
    both_correct: int
    a_correct_b_wrong: int
    b_correct_a_wrong: int
    both_wrong: int


@dataclass(frozen=True)
class McNemarResult:
    """
    McNemar's test on the discordant pairs.

    ``valid`` is False when the test is not mathematically applicable
    (no discordant pairs).  ``p_value`` is then None and must not be
    interpreted or reported as a significance claim.
    """

    valid: bool
    method: str
    b: int  # A correct, B wrong
    c: int  # A wrong, B correct
    statistic: Optional[float]
    p_value: Optional[float]
    note: str


@dataclass(frozen=True)
class LanguageMetrics:
    """All metrics for one language, with explicit denominators."""

    language: str
    language_name: str

    n: int
    n_legitimate: int
    n_phishing: int

    # Path A
    baseline_evaluated_n: int
    baseline_failures: int
    baseline: ConfusionMetrics

    # Path B
    path_b_evaluated_n: int
    translation_failures: int
    translated_classifier_failures: int
    translation_success_n: int
    translation_success_rate: Optional[float]
    path_b: ConfusionMetrics

    # Paired subset (both paths produced a prediction) -- the only fair
    # denominator for a delta.
    paired_n: int
    paired_baseline: ConfusionMetrics
    paired_path_b: ConfusionMetrics
    delta_accuracy: Optional[float]
    delta_precision: Optional[float]
    delta_recall: Optional[float]
    delta_f1: Optional[float]
    paired_counts: PairedCounts
    mcnemar: McNemarResult

    # Latency (successful operations only)
    baseline_latency: LatencyStats
    translation_latency: LatencyStats
    translated_classifier_latency: LatencyStats
    path_b_total_latency: LatencyStats


@dataclass(frozen=True)
class MacroAverages:
    """
    Unweighted mean across languages.

    ``languages_included`` records how many languages actually contributed a
    defined value, so a macro figure is never mistaken for a full-coverage one.
    """

    languages_included: int
    accuracy: Optional[float]
    precision: Optional[float]
    recall: Optional[float]
    f1: Optional[float]


@dataclass(frozen=True)
class Aggregate:
    """Macro and micro aggregates. Both are reported; neither is preferred."""

    n_languages: int
    n_samples: int
    n_legitimate: int
    n_phishing: int

    baseline_evaluated_n: int
    baseline_failures: int
    path_b_evaluated_n: int
    translation_failures: int
    translated_classifier_failures: int
    translation_success_n: int
    translation_attempted_n: int
    translation_success_rate: Optional[float]

    # Micro / pooled: every valid prediction contributes one unit.
    micro_baseline: ConfusionMetrics
    micro_path_b: ConfusionMetrics
    micro_paired_n: int
    micro_paired_baseline: ConfusionMetrics
    micro_paired_path_b: ConfusionMetrics
    micro_delta_accuracy: Optional[float]
    micro_delta_precision: Optional[float]
    micro_delta_recall: Optional[float]
    micro_delta_f1: Optional[float]

    # Macro: each language counts once, regardless of how many samples it
    # contributed or how many failures it had.
    macro_baseline: MacroAverages
    macro_path_b: MacroAverages
    macro_delta_accuracy: Optional[float]
    macro_delta_precision: Optional[float]
    macro_delta_recall: Optional[float]
    macro_delta_f1: Optional[float]
    macro_delta_languages_included: int

    paired_counts: PairedCounts
    mcnemar: McNemarResult

    baseline_latency: LatencyStats
    translation_latency: LatencyStats
    translated_classifier_latency: LatencyStats
    path_b_total_latency: LatencyStats


@dataclass(frozen=True)
class DisagreementExample:
    """One diagnostic case where the two paths disagreed."""

    id: int
    language: str
    language_name: str
    label: int
    baseline_pred: int
    path_b_pred: int
    baseline_phishing_prob: Optional[float]
    translated_phishing_prob: Optional[float]
    source_text_excerpt: str
    translated_text_excerpt: str


@dataclass(frozen=True)
class DisagreementSummary:
    """Counts plus a bounded sample of both disagreement directions."""

    n_a_correct_b_wrong: int
    n_b_correct_a_wrong: int
    per_language: dict[str, dict[str, int]]
    examples_a_correct_b_wrong: list[DisagreementExample]
    examples_b_correct_a_wrong: list[DisagreementExample]


@dataclass(frozen=True)
class BenchmarkReport:
    """Everything a run produces."""

    run_metadata: dict
    dataset_issues: list[DatasetIssue]
    per_language: list[LanguageMetrics]
    aggregate: Aggregate
    disagreements: DisagreementSummary
    per_sample: list[SampleResult] = field(repr=False, default_factory=list)


# ---------------------------------------------------------------------------
# Dataset loading
# ---------------------------------------------------------------------------

def file_sha256(path: Path) -> str:
    """Stable content identifier for the dataset, recorded in run metadata."""
    h = hashlib.sha256()
    with open(path, "rb") as f:
        for chunk in iter(lambda: f.read(65536), b""):
            h.update(chunk)
    return h.hexdigest()


def load_dataset(
    path: Path,
    languages: Optional[Sequence[str]] = None,
    max_per_language: Optional[int] = None,
    max_rows: Optional[int] = None,
) -> DatasetLoad:
    """
    Load and validate the evaluation CSV.

    Malformed rows are collected into ``DatasetLoad.issues`` with a reason and
    a 1-based row number; they are excluded from the samples but never dropped
    silently.  Samples are returned in deterministic (language, id) order.

    Raises
    ------
    FileNotFoundError
        If *path* does not exist.
    ValueError
        If required columns are missing from the header -- there is no
        meaningful per-row recovery in that case.
    """
    path = Path(path)
    if not path.exists():
        raise FileNotFoundError(
            f"Dataset not found at {path}. Expected the checked-in evaluation "
            f"set at datasets/evaluation/indic/indic_eval.csv."
        )

    issues: list[DatasetIssue] = []
    samples: list[Sample] = []
    seen_ids: set[int] = set()
    rows_read = 0

    wanted = set(languages) if languages else None

    with open(path, newline="", encoding="utf-8") as f:
        reader = csv.DictReader(f)
        fieldnames = reader.fieldnames or []
        missing = [c for c in REQUIRED_COLUMNS if c not in fieldnames]
        if missing:
            raise ValueError(
                f"Dataset {path} is missing required column(s): {missing}. "
                f"Found columns: {fieldnames}."
            )

        for row_number, row in enumerate(reader, start=1):
            rows_read += 1
            raw_id = (row.get("id") or "").strip()

            try:
                sample_id = int(raw_id)
            except (TypeError, ValueError):
                issues.append(DatasetIssue(row_number, raw_id or None,
                                           f"id is not an integer: {raw_id!r}"))
                continue

            if sample_id in seen_ids:
                issues.append(DatasetIssue(row_number, raw_id,
                                           f"duplicate id {sample_id}"))
                continue

            language = (row.get("language") or "").strip()
            if language not in SUPPORTED_LANGUAGES:
                issues.append(DatasetIssue(row_number, raw_id,
                                           f"unknown language code {language!r}"))
                continue

            text = row.get("text") or ""
            if not text.strip():
                issues.append(DatasetIssue(row_number, raw_id, "empty text"))
                continue

            raw_label = (row.get("label") or "").strip()
            if raw_label not in ("0", "1"):
                issues.append(DatasetIssue(row_number, raw_id,
                                           f"label must be 0 or 1, got {raw_label!r}"))
                continue

            seen_ids.add(sample_id)

            if wanted is not None and language not in wanted:
                continue

            samples.append(Sample(
                id=sample_id,
                language=language,
                language_name=row.get("language_name") or SUPPORTED_LANGUAGES[language],
                text=text,
                label=int(raw_label),
                source=row.get("source") or "synthetic",
                notes=row.get("notes") or "",
            ))

    # Deterministic ordering, independent of file order.
    samples.sort(key=lambda s: (s.language, s.id))

    if max_per_language is not None:
        capped: list[Sample] = []
        counts: dict[str, int] = {}
        for s in samples:
            if counts.get(s.language, 0) < max_per_language:
                capped.append(s)
                counts[s.language] = counts.get(s.language, 0) + 1
        samples = capped

    if max_rows is not None:
        samples = samples[:max_rows]

    return DatasetLoad(
        samples=samples,
        issues=issues,
        rows_read=rows_read,
        path=str(path),
        sha256=file_sha256(path),
    )


# ---------------------------------------------------------------------------
# Default (real) classifier / translator adapters -- lazily imported
# ---------------------------------------------------------------------------

def make_real_classifier() -> ClassifierFn:
    """
    Build a classifier callable backed by the production V2 classifier.

    The import happens here, not at module scope, so that importing this
    module (as the unit tests do) never loads the V2 pickles.
    """
    from backend.app.services.ml_classifier import classify_email  # noqa: PLC0415

    def _classify(text: str) -> ClassifyOutcome:
        t0 = time.perf_counter()
        try:
            raw = classify_email(text)
            prob = float(raw["phishing_probability"])
        except Exception as exc:  # noqa: BLE001 -- must not abort the benchmark
            return ClassifyOutcome(
                status=OpStatus.FAILED,
                phishing_probability=None,
                latency_s=round(time.perf_counter() - t0, 6),
                error=f"{type(exc).__name__}: {exc}",
            )
        return ClassifyOutcome(
            status=OpStatus.OK,
            phishing_probability=prob,
            latency_s=round(time.perf_counter() - t0, 6),
            error=None,
        )

    return _classify


def make_real_translator() -> TranslatorFn:
    """Build a translator callable backed by the NLLB-200 prototype."""
    from backend.app.multilingual.nllb_translator import (  # noqa: PLC0415
        TranslationStatus,
        translate,
    )

    _status_map = {
        TranslationStatus.TRANSLATED: TransStatus.TRANSLATED,
        TranslationStatus.ENGLISH_BYPASS: TransStatus.ENGLISH_BYPASS,
        TranslationStatus.UNSUPPORTED_LANGUAGE: TransStatus.UNSUPPORTED_LANGUAGE,
        TranslationStatus.TRANSLATION_FAILED: TransStatus.TRANSLATION_FAILED,
    }

    def _translate(text: str, src_lang: str) -> TranslateOutcome:
        t0 = time.perf_counter()
        try:
            result = translate(text, src_lang)
        except Exception as exc:  # noqa: BLE001 -- translate() should not raise, but belt and braces
            return TranslateOutcome(
                status=TransStatus.TRANSLATION_FAILED,
                translated_text=None,
                latency_s=round(time.perf_counter() - t0, 6),
                error=f"{type(exc).__name__}: {exc}",
            )
        latency = round(time.perf_counter() - t0, 6)
        status = _status_map.get(result.status, TransStatus.TRANSLATION_FAILED)
        return TranslateOutcome(
            status=status,
            translated_text=result.translated_text if status is TransStatus.TRANSLATED else None,
            latency_s=latency,
            error=result.error,
        )

    return _translate


def make_dry_run_classifier(threshold: float = PHISHING_THRESHOLD) -> ClassifierFn:
    """
    Deterministic stub classifier for --dry-run.

    The score is derived from a SHA-256 of the text, so a dry run is
    byte-for-byte reproducible.  It carries no predictive meaning whatsoever
    and exists purely to exercise the harness plumbing.
    """

    def _classify(text: str) -> ClassifyOutcome:
        digest = hashlib.sha256(text.encode("utf-8")).digest()
        prob = (int.from_bytes(digest[:4], "big") % 10_001) / 100.0
        return ClassifyOutcome(
            status=OpStatus.OK,
            phishing_probability=prob,
            latency_s=0.0,
            error=None,
        )

    return _classify


def make_dry_run_translator(failure_rate_denominator: int = 10) -> TranslatorFn:
    """
    Deterministic stub translator for --dry-run. No model is loaded.

    Every Nth sample (by content hash) is failed on purpose so the failure
    handling paths are exercised without randomness.
    """

    def _translate(text: str, src_lang: str) -> TranslateOutcome:
        digest = hashlib.sha256(f"{src_lang}|{text}".encode("utf-8")).digest()
        bucket = digest[0] % failure_rate_denominator
        if bucket == 0:
            return TranslateOutcome(
                status=TransStatus.DRY_RUN_FAILED,
                translated_text=None,
                latency_s=0.0,
                error="dry-run: simulated translation failure",
            )
        return TranslateOutcome(
            status=TransStatus.TRANSLATED,
            translated_text=f"[dry-run translation of {len(text)} chars]",
            latency_s=0.0,
            error=None,
        )

    return _translate


# ---------------------------------------------------------------------------
# Prediction helper
# ---------------------------------------------------------------------------

def pred_from_prob(prob: Optional[float],
                   threshold: float = PHISHING_THRESHOLD) -> Optional[int]:
    """
    Binarise a phishing probability (0-100 scale).

    ``None`` in, ``None`` out: a missing score never becomes a "legitimate"
    prediction.
    """
    if prob is None:
        return None
    return 1 if prob >= threshold else 0


# ---------------------------------------------------------------------------
# Core evaluation loop
# ---------------------------------------------------------------------------

def safe_classify(classifier: ClassifierFn, text: str) -> ClassifyOutcome:
    """
    Call *classifier* and convert any escaping exception into a FAILED outcome.

    The built-in adapters already catch their own exceptions, but
    :func:`evaluate_samples` accepts arbitrary injected callables, so the
    boundary is enforced here rather than trusted.  A callable that raises --
    or that returns something which is not a :class:`ClassifyOutcome` -- must
    not be able to terminate a 1,100-sample benchmark run.

    The result is always FAILED with ``phishing_probability=None`` on error, so
    the sample is excluded from the metric denominator.  It is never coerced
    into a score, and therefore never into a "legitimate" prediction.
    """
    t0 = time.perf_counter()
    try:
        outcome = classifier(text)
    except KeyboardInterrupt:
        # The operator asked to stop a long GPU run. Containment is for model
        # failures, not for the abort key.
        raise
    except BaseException as exc:  # noqa: BLE001 -- the benchmark must survive anything else
        return ClassifyOutcome(
            status=OpStatus.FAILED,
            phishing_probability=None,
            latency_s=round(time.perf_counter() - t0, 6),
            error=f"classifier raised {type(exc).__name__}: {exc}",
        )
    if not isinstance(outcome, ClassifyOutcome):
        return ClassifyOutcome(
            status=OpStatus.FAILED,
            phishing_probability=None,
            latency_s=round(time.perf_counter() - t0, 6),
            error=(f"classifier returned {type(outcome).__name__}, "
                   f"expected ClassifyOutcome"),
        )
    return outcome


def safe_translate(translator: TranslatorFn, text: str,
                   src_lang: str) -> TranslateOutcome:
    """
    Call *translator* and convert any escaping exception into a
    TRANSLATION_FAILED outcome.

    Same contract as :func:`safe_classify`: the sample is recorded as a
    translation failure and excluded from the Path B denominator, and the run
    moves on to the next sample.
    """
    t0 = time.perf_counter()
    try:
        outcome = translator(text, src_lang)
    except KeyboardInterrupt:
        raise
    except BaseException as exc:  # noqa: BLE001 -- the benchmark must survive anything else
        return TranslateOutcome(
            status=TransStatus.TRANSLATION_FAILED,
            translated_text=None,
            latency_s=round(time.perf_counter() - t0, 6),
            error=f"translator raised {type(exc).__name__}: {exc}",
        )
    if not isinstance(outcome, TranslateOutcome):
        return TranslateOutcome(
            status=TransStatus.TRANSLATION_FAILED,
            translated_text=None,
            latency_s=round(time.perf_counter() - t0, 6),
            error=(f"translator returned {type(outcome).__name__}, "
                   f"expected TranslateOutcome"),
        )
    return outcome


def evaluate_samples(
    samples: Sequence[Sample],
    classifier: ClassifierFn,
    translator: TranslatorFn,
    threshold: float = PHISHING_THRESHOLD,
    progress: Optional[Callable[[int, int, Sample], None]] = None,
) -> list[SampleResult]:
    """
    Run both paths over *samples* and return one :class:`SampleResult` each.

    Results are returned in the same order the samples were given (callers
    pass a (language, id)-sorted sequence).

    Fail-safe contract
    ------------------
    Nothing an injected classifier or translator does can abort the run.  Both
    are called through :func:`safe_classify` / :func:`safe_translate`, so an
    exception from any of the three model calls (Path A classify, translate,
    Path B classify) becomes an explicit FAILED status on that one sample and
    evaluation continues with the next.  A failed call yields a ``None``
    prediction, which is excluded from the metric denominators -- it is never
    turned into prediction 0.

    A ``progress`` callback that raises is also contained, for the same reason:
    a broken progress reporter is not a reason to lose an hour of GPU work.
    KeyboardInterrupt is deliberately NOT contained, so Ctrl-C still stops a
    long run.
    """
    results: list[SampleResult] = []
    total = len(samples)

    for index, sample in enumerate(samples, start=1):
        # ---- Path A: raw Indic text -> V2 -------------------------------
        base = safe_classify(classifier, sample.text)
        base_pred = pred_from_prob(base.phishing_probability, threshold) \
            if base.status is OpStatus.OK else None

        # ---- Path B step 1: translation ---------------------------------
        trans = safe_translate(translator, sample.text, sample.language)

        # ---- Path B step 2: classify the English text -------------------
        if trans.ok and trans.translated_text is not None:
            tcls = safe_classify(classifier, trans.translated_text)
            t_pred = pred_from_prob(tcls.phishing_probability, threshold) \
                if tcls.status is OpStatus.OK else None
            t_status = tcls.status
            t_prob = tcls.phishing_probability if tcls.status is OpStatus.OK else None
            t_latency = tcls.latency_s
            t_error = tcls.error
        else:
            t_status = OpStatus.SKIPPED
            t_pred = None
            t_prob = None
            t_latency = None
            t_error = None

        # Total Path B latency is only meaningful when both steps completed.
        if (trans.latency_s is not None and t_latency is not None
                and t_status is OpStatus.OK):
            path_b_total: Optional[float] = round(trans.latency_s + t_latency, 6)
        else:
            path_b_total = None

        results.append(SampleResult(
            id=sample.id,
            language=sample.language,
            language_name=sample.language_name,
            label=sample.label,

            baseline_status=base.status.value,
            baseline_phishing_prob=base.phishing_probability if base.status is OpStatus.OK else None,
            baseline_pred=base_pred,
            baseline_latency_s=base.latency_s,
            baseline_error=base.error,

            translation_status=trans.status.value,
            translated_text=trans.translated_text,
            translation_latency_s=trans.latency_s,
            translation_error=trans.error,

            translated_status=t_status.value,
            translated_phishing_prob=t_prob,
            translated_pred=t_pred,
            translated_classifier_latency_s=t_latency,
            translated_error=t_error,

            path_b_total_latency_s=path_b_total,
            baseline_correct=(base_pred == sample.label) if base_pred is not None else None,
            path_b_correct=(t_pred == sample.label) if t_pred is not None else None,
            paired_evaluable=(base_pred is not None and t_pred is not None),
        ))

        if progress is not None:
            try:
                progress(index, total, sample)
            except Exception:  # noqa: BLE001 -- reporting must not kill the run
                pass

    return results


# ---------------------------------------------------------------------------
# Metrics
# ---------------------------------------------------------------------------

def compute_metrics(labels: Sequence[int], preds: Sequence[int]) -> ConfusionMetrics:
    """
    Binary classification metrics, positive class = phishing (1).

    ``labels`` and ``preds`` must be the same length and contain only valid
    (non-failed) predictions -- filtering is the caller's job, so that the
    denominator ``n`` is always explicit and auditable.

    Undefined metrics return ``None`` rather than 0.0:
      * accuracy is undefined when n == 0
      * precision is undefined when nothing was predicted positive
      * recall is undefined when there are no actual positives
      * F1 is undefined when precision or recall is undefined, or both are 0
    """
    if len(labels) != len(preds):
        raise ValueError(
            f"labels/preds length mismatch: {len(labels)} vs {len(preds)}"
        )

    tp = sum(1 for l, p in zip(labels, preds) if l == 1 and p == 1)
    tn = sum(1 for l, p in zip(labels, preds) if l == 0 and p == 0)
    fp = sum(1 for l, p in zip(labels, preds) if l == 0 and p == 1)
    fn = sum(1 for l, p in zip(labels, preds) if l == 1 and p == 0)
    n = tp + tn + fp + fn

    accuracy = (tp + tn) / n if n else None
    precision = tp / (tp + fp) if (tp + fp) else None
    recall = tp / (tp + fn) if (tp + fn) else None
    if precision is None or recall is None or (precision + recall) == 0:
        f1 = None
    else:
        f1 = 2 * precision * recall / (precision + recall)

    return ConfusionMetrics(
        n=n, tp=tp, tn=tn, fp=fp, fn=fn,
        n_actual_positive=tp + fn,
        n_actual_negative=tn + fp,
        n_predicted_positive=tp + fp,
        accuracy=_round(accuracy),
        precision=_round(precision),
        recall=_round(recall),
        f1=_round(f1),
    )


def _round(value: Optional[float], digits: int = 6) -> Optional[float]:
    return None if value is None else round(value, digits)


def _delta(b: Optional[float], a: Optional[float]) -> Optional[float]:
    """Path B minus Path A. Undefined if either side is undefined."""
    if b is None or a is None:
        return None
    return round(b - a, 6)


def latency_stats(values: Iterable[Optional[float]]) -> LatencyStats:
    """
    Summarise latencies over successful operations only.

    ``None`` entries (failed / skipped operations) are dropped, so these
    figures never mix a fast failure into a timing average.
    """
    vals = sorted(v for v in values if v is not None)
    if not vals:
        return LatencyStats(count=0, mean_s=None, median_s=None, p95_s=None)
    return LatencyStats(
        count=len(vals),
        mean_s=_round(statistics.fmean(vals)),
        median_s=_round(statistics.median(vals)),
        p95_s=_round(_percentile(vals, 0.95)),
    )


def _percentile(sorted_values: Sequence[float], q: float) -> float:
    """Linear-interpolation percentile on an already-sorted sequence."""
    if len(sorted_values) == 1:
        return float(sorted_values[0])
    pos = q * (len(sorted_values) - 1)
    low = math.floor(pos)
    high = math.ceil(pos)
    if low == high:
        return float(sorted_values[int(pos)])
    frac = pos - low
    return float(sorted_values[low] * (1 - frac) + sorted_values[high] * frac)


def compute_paired_counts(results: Sequence[SampleResult]) -> PairedCounts:
    """
    2x2 paired outcome table over samples where BOTH paths produced a
    prediction. Samples missing either prediction are excluded entirely --
    they are failures, not evidence for either path.
    """
    both_correct = a_only = b_only = both_wrong = 0
    for r in results:
        if not r.paired_evaluable:
            continue
        a_ok = bool(r.baseline_correct)
        b_ok = bool(r.path_b_correct)
        if a_ok and b_ok:
            both_correct += 1
        elif a_ok and not b_ok:
            a_only += 1
        elif b_ok and not a_ok:
            b_only += 1
        else:
            both_wrong += 1
    return PairedCounts(
        n_paired=both_correct + a_only + b_only + both_wrong,
        both_correct=both_correct,
        a_correct_b_wrong=a_only,
        b_correct_a_wrong=b_only,
        both_wrong=both_wrong,
    )


def mcnemar_test(counts: PairedCounts, exact_threshold: int = 25) -> McNemarResult:
    """
    McNemar's test on the discordant cells (b = A right/B wrong,
    c = A wrong/B right).

    * b + c == 0  -> the test is not applicable; ``valid=False``, no p-value.
      The paths made identical errors, which is a real finding but not a
      significance result.
    * b + c < exact_threshold -> two-sided exact binomial test (the chi-square
      approximation is unreliable for few discordant pairs).
    * otherwise -> chi-square with Edwards' continuity correction, 1 d.o.f.

    The p-value describes ONLY this synthetic dataset. It says nothing about
    real-world traffic.
    """
    b, c = counts.a_correct_b_wrong, counts.b_correct_a_wrong
    n = b + c

    if counts.n_paired == 0:
        return McNemarResult(
            valid=False, method="none", b=b, c=c, statistic=None, p_value=None,
            note="No paired samples: at least one path produced no predictions.",
        )
    if n == 0:
        return McNemarResult(
            valid=False, method="none", b=b, c=c, statistic=None, p_value=None,
            note=("No discordant pairs (both paths agreed on every paired "
                  "sample); McNemar's test is undefined here."),
        )

    if n < exact_threshold:
        # Two-sided exact binomial under H0: p = 0.5.
        k = min(b, c)
        tail = sum(math.comb(n, i) for i in range(k + 1)) * (0.5 ** n)
        p = min(1.0, 2.0 * tail)
        return McNemarResult(
            valid=True, method="exact_binomial", b=b, c=c,
            statistic=float(k), p_value=_round(p),
            note=(f"Exact two-sided binomial on {n} discordant pairs "
                  f"(< {exact_threshold}, chi-square approximation not used)."),
        )

    chi2 = (abs(b - c) - 1) ** 2 / n
    # Survival function of chi-square with 1 d.o.f.
    p = math.erfc(math.sqrt(chi2 / 2.0))
    return McNemarResult(
        valid=True, method="chi_square_continuity_corrected", b=b, c=c,
        statistic=_round(chi2), p_value=_round(p),
        note=(f"Chi-square with continuity correction, 1 d.o.f., on {n} "
              f"discordant pairs."),
    )


def compute_language_metrics(
    language: str,
    results: Sequence[SampleResult],
) -> LanguageMetrics:
    """Compute the full metric block for one language."""
    rows = [r for r in results if r.language == language]
    language_name = rows[0].language_name if rows else SUPPORTED_LANGUAGES.get(language, language)

    n_legit = sum(1 for r in rows if r.label == 0)
    n_phish = sum(1 for r in rows if r.label == 1)

    # ---- Path A ---------------------------------------------------------
    base_rows = [r for r in rows if r.baseline_pred is not None]
    baseline = compute_metrics([r.label for r in base_rows],
                               [r.baseline_pred for r in base_rows])
    baseline_failures = len(rows) - len(base_rows)

    # ---- Path B ---------------------------------------------------------
    trans_ok = [r for r in rows if r.translation_ok]
    translation_failures = len(rows) - len(trans_ok)
    b_rows = [r for r in rows if r.translated_pred is not None]
    translated_cls_failures = len(trans_ok) - len(b_rows)
    path_b = compute_metrics([r.label for r in b_rows],
                             [r.translated_pred for r in b_rows])

    # ---- Paired subset (the only fair denominator for a delta) ----------
    paired = [r for r in rows if r.paired_evaluable]
    paired_baseline = compute_metrics([r.label for r in paired],
                                      [r.baseline_pred for r in paired])
    paired_path_b = compute_metrics([r.label for r in paired],
                                    [r.translated_pred for r in paired])
    counts = compute_paired_counts(rows)

    return LanguageMetrics(
        language=language,
        language_name=language_name,
        n=len(rows),
        n_legitimate=n_legit,
        n_phishing=n_phish,

        baseline_evaluated_n=len(base_rows),
        baseline_failures=baseline_failures,
        baseline=baseline,

        path_b_evaluated_n=len(b_rows),
        translation_failures=translation_failures,
        translated_classifier_failures=translated_cls_failures,
        translation_success_n=len(trans_ok),
        translation_success_rate=_round(len(trans_ok) / len(rows)) if rows else None,
        path_b=path_b,

        paired_n=len(paired),
        paired_baseline=paired_baseline,
        paired_path_b=paired_path_b,
        delta_accuracy=_delta(paired_path_b.accuracy, paired_baseline.accuracy),
        delta_precision=_delta(paired_path_b.precision, paired_baseline.precision),
        delta_recall=_delta(paired_path_b.recall, paired_baseline.recall),
        delta_f1=_delta(paired_path_b.f1, paired_baseline.f1),
        paired_counts=counts,
        mcnemar=mcnemar_test(counts),

        baseline_latency=latency_stats(
            r.baseline_latency_s for r in rows if r.baseline_pred is not None),
        translation_latency=latency_stats(
            r.translation_latency_s for r in rows if r.translation_ok),
        translated_classifier_latency=latency_stats(
            r.translated_classifier_latency_s for r in rows if r.translated_pred is not None),
        path_b_total_latency=latency_stats(r.path_b_total_latency_s for r in rows),
    )


def _macro(values: Sequence[Optional[float]]) -> tuple[Optional[float], int]:
    """Unweighted mean of the defined values; also returns how many there were."""
    defined = [v for v in values if v is not None]
    if not defined:
        return None, 0
    return round(statistics.fmean(defined), 6), len(defined)


def compute_aggregate(
    per_language: Sequence[LanguageMetrics],
    results: Sequence[SampleResult],
) -> Aggregate:
    """
    Build both aggregates.

    Micro (pooled) weights every valid prediction equally, so languages with
    more successful samples count for more.  Macro weights every language
    equally, so a language with many failures is not drowned out.  They can
    legitimately disagree; both are reported, neither is "the" number.
    """
    base_rows = [r for r in results if r.baseline_pred is not None]
    b_rows = [r for r in results if r.translated_pred is not None]
    paired = [r for r in results if r.paired_evaluable]

    micro_baseline = compute_metrics([r.label for r in base_rows],
                                     [r.baseline_pred for r in base_rows])
    micro_path_b = compute_metrics([r.label for r in b_rows],
                                   [r.translated_pred for r in b_rows])
    micro_paired_baseline = compute_metrics([r.label for r in paired],
                                            [r.baseline_pred for r in paired])
    micro_paired_path_b = compute_metrics([r.label for r in paired],
                                          [r.translated_pred for r in paired])

    macro_b_acc, macro_b_n = _macro([m.baseline.accuracy for m in per_language])
    macro_b_prec, _ = _macro([m.baseline.precision for m in per_language])
    macro_b_rec, _ = _macro([m.baseline.recall for m in per_language])
    macro_b_f1, _ = _macro([m.baseline.f1 for m in per_language])

    macro_t_acc, macro_t_n = _macro([m.path_b.accuracy for m in per_language])
    macro_t_prec, _ = _macro([m.path_b.precision for m in per_language])
    macro_t_rec, _ = _macro([m.path_b.recall for m in per_language])
    macro_t_f1, _ = _macro([m.path_b.f1 for m in per_language])

    macro_d_acc, macro_d_n = _macro([m.delta_accuracy for m in per_language])
    macro_d_prec, _ = _macro([m.delta_precision for m in per_language])
    macro_d_rec, _ = _macro([m.delta_recall for m in per_language])
    macro_d_f1, _ = _macro([m.delta_f1 for m in per_language])

    trans_ok = sum(m.translation_success_n for m in per_language)
    trans_attempted = sum(m.n for m in per_language)
    counts = compute_paired_counts(results)

    return Aggregate(
        n_languages=len(per_language),
        n_samples=len(results),
        n_legitimate=sum(1 for r in results if r.label == 0),
        n_phishing=sum(1 for r in results if r.label == 1),

        baseline_evaluated_n=len(base_rows),
        baseline_failures=sum(m.baseline_failures for m in per_language),
        path_b_evaluated_n=len(b_rows),
        translation_failures=sum(m.translation_failures for m in per_language),
        translated_classifier_failures=sum(
            m.translated_classifier_failures for m in per_language),
        translation_success_n=trans_ok,
        translation_attempted_n=trans_attempted,
        translation_success_rate=_round(trans_ok / trans_attempted) if trans_attempted else None,

        micro_baseline=micro_baseline,
        micro_path_b=micro_path_b,
        micro_paired_n=len(paired),
        micro_paired_baseline=micro_paired_baseline,
        micro_paired_path_b=micro_paired_path_b,
        micro_delta_accuracy=_delta(micro_paired_path_b.accuracy, micro_paired_baseline.accuracy),
        micro_delta_precision=_delta(micro_paired_path_b.precision, micro_paired_baseline.precision),
        micro_delta_recall=_delta(micro_paired_path_b.recall, micro_paired_baseline.recall),
        micro_delta_f1=_delta(micro_paired_path_b.f1, micro_paired_baseline.f1),

        macro_baseline=MacroAverages(macro_b_n, macro_b_acc, macro_b_prec, macro_b_rec, macro_b_f1),
        macro_path_b=MacroAverages(macro_t_n, macro_t_acc, macro_t_prec, macro_t_rec, macro_t_f1),
        macro_delta_accuracy=macro_d_acc,
        macro_delta_precision=macro_d_prec,
        macro_delta_recall=macro_d_rec,
        macro_delta_f1=macro_d_f1,
        macro_delta_languages_included=macro_d_n,

        paired_counts=counts,
        mcnemar=mcnemar_test(counts),

        baseline_latency=latency_stats(
            r.baseline_latency_s for r in results if r.baseline_pred is not None),
        translation_latency=latency_stats(
            r.translation_latency_s for r in results if r.translation_ok),
        translated_classifier_latency=latency_stats(
            r.translated_classifier_latency_s for r in results if r.translated_pred is not None),
        path_b_total_latency=latency_stats(r.path_b_total_latency_s for r in results),
    )


# ---------------------------------------------------------------------------
# Disagreement analysis
# ---------------------------------------------------------------------------

def _excerpt(text: Optional[str], limit: int = EXAMPLE_TEXT_CHARS) -> str:
    if not text:
        return ""
    flat = text.replace("\r\n", " / ").replace("\n", " / ").replace("\r", " / ")
    return flat if len(flat) <= limit else flat[:limit] + "..."


def summarise_disagreements(
    results: Sequence[SampleResult],
    samples_by_id: Optional[dict[int, Sample]] = None,
    limit: int = DEFAULT_EXAMPLE_LIMIT,
) -> DisagreementSummary:
    """
    Collect the two diagnostic buckets: A-correct/B-wrong and A-wrong/B-correct.

    These are the cases that actually tell you whether translation is helping
    or hurting, so the examples carry both the source text and the translated
    English text for manual inspection.  Examples are taken in (language, id)
    order, so the selection is deterministic rather than "first N encountered".
    """
    samples_by_id = samples_by_id or {}
    a_only: list[SampleResult] = []
    b_only: list[SampleResult] = []
    per_language: dict[str, dict[str, int]] = {}

    for r in sorted(results, key=lambda x: (x.language, x.id)):
        if not r.paired_evaluable:
            continue
        bucket = per_language.setdefault(
            r.language, {"a_correct_b_wrong": 0, "b_correct_a_wrong": 0})
        if r.baseline_correct and not r.path_b_correct:
            a_only.append(r)
            bucket["a_correct_b_wrong"] += 1
        elif r.path_b_correct and not r.baseline_correct:
            b_only.append(r)
            bucket["b_correct_a_wrong"] += 1

    def _build(rows: list[SampleResult]) -> list[DisagreementExample]:
        out: list[DisagreementExample] = []
        for r in rows[:limit]:
            sample = samples_by_id.get(r.id)
            out.append(DisagreementExample(
                id=r.id,
                language=r.language,
                language_name=r.language_name,
                label=r.label,
                baseline_pred=int(r.baseline_pred),   # type: ignore[arg-type]
                path_b_pred=int(r.translated_pred),   # type: ignore[arg-type]
                baseline_phishing_prob=r.baseline_phishing_prob,
                translated_phishing_prob=r.translated_phishing_prob,
                source_text_excerpt=_excerpt(sample.text if sample else None),
                translated_text_excerpt=_excerpt(r.translated_text),
            ))
        return out

    return DisagreementSummary(
        n_a_correct_b_wrong=len(a_only),
        n_b_correct_a_wrong=len(b_only),
        per_language=dict(sorted(per_language.items())),
        examples_a_correct_b_wrong=_build(a_only),
        examples_b_correct_a_wrong=_build(b_only),
    )


# ---------------------------------------------------------------------------
# Run metadata (reproducibility)
# ---------------------------------------------------------------------------

def build_run_metadata(
    dataset: DatasetLoad,
    languages: Sequence[str],
    threshold: float,
    dry_run: bool,
    argv: Sequence[str],
) -> dict:
    """
    Everything needed to reproduce or audit a run.

    NLLB configuration is read from the multilingual config module when it is
    importable; in --dry-run the import is skipped so that no model settings
    are implied for a run that loaded no model.
    """
    nllb: dict = {"dry_run": dry_run}
    if dry_run:
        nllb["note"] = "Dry run: no NLLB model and no V2 classifier were loaded."
    else:
        try:
            from backend.app.multilingual import config as nllb_config  # noqa: PLC0415
            nllb.update({
                "model_name": nllb_config.MODEL_NAME,
                "model_version": nllb_config.MODEL_VERSION,
                "device_mode": nllb_config.DEVICE_MODE,
                "max_input_tokens": nllb_config.MAX_INPUT_TOKENS,
                "max_output_tokens": nllb_config.MAX_OUTPUT_TOKENS,
                "enabled": nllb_config.ENABLED,
                "cache_dir": nllb_config.CACHE_DIR,
            })
        except Exception as exc:  # noqa: BLE001
            nllb["config_error"] = f"{type(exc).__name__}: {exc}"

    return {
        "harness_version": HARNESS_VERSION,
        "generated_at_utc": time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime()),
        "command": " ".join(argv),
        "dataset": {
            "path": dataset.path,
            "sha256": dataset.sha256,
            "rows_read": dataset.rows_read,
            "samples_evaluated": len(dataset.samples),
            "malformed_rows": len(dataset.issues),
        },
        "classifier": {
            "path": CLASSIFIER_PATH,
            "entrypoint": CLASSIFIER_ENTRYPOINT,
            "phishing_threshold_0_100": threshold,
            "positive_class": "phishing (label 1)",
        },
        "nllb": nllb,
        "languages": list(languages),
        "ordering": "samples sorted by (language, id); outputs follow that order",
        "python": sys.version.split()[0],
        "platform": platform.platform(),
        "advisory": (
            "PROTOTYPE EVALUATION ONLY. Path B applies the production V2 "
            "classifier to NLLB-translated text for offline comparison. These "
            "numbers do not affect any production risk score and, because the "
            "dataset is synthetic and template-derived, are not evidence of "
            "production accuracy."
        ),
    }


# ---------------------------------------------------------------------------
# Report assembly
# ---------------------------------------------------------------------------

def build_report(
    dataset: DatasetLoad,
    results: Sequence[SampleResult],
    threshold: float,
    dry_run: bool,
    argv: Sequence[str],
    example_limit: int = DEFAULT_EXAMPLE_LIMIT,
) -> BenchmarkReport:
    """Assemble per-language metrics, aggregates and diagnostics."""
    languages = sorted({r.language for r in results})
    per_language = [compute_language_metrics(lang, results) for lang in languages]
    aggregate = compute_aggregate(per_language, results)
    samples_by_id = {s.id: s for s in dataset.samples}
    disagreements = summarise_disagreements(results, samples_by_id, limit=example_limit)

    return BenchmarkReport(
        run_metadata=build_run_metadata(dataset, languages, threshold, dry_run, argv),
        dataset_issues=list(dataset.issues),
        per_language=per_language,
        aggregate=aggregate,
        disagreements=disagreements,
        per_sample=list(results),
    )


# ---------------------------------------------------------------------------
# Serialisation
# ---------------------------------------------------------------------------

def report_to_dict(report: BenchmarkReport, include_per_sample: bool = False) -> dict:
    payload = {
        "run_metadata": report.run_metadata,
        "dataset_issues": [asdict(i) for i in report.dataset_issues],
        "aggregate": asdict(report.aggregate),
        "per_language": [asdict(m) for m in report.per_language],
        "disagreements": asdict(report.disagreements),
    }
    if include_per_sample:
        payload["per_sample"] = [asdict(r) for r in report.per_sample]
    return payload


def save_json(path: Path, report: BenchmarkReport,
              include_per_sample: bool = False) -> Path:
    path = Path(path)
    path.parent.mkdir(parents=True, exist_ok=True)
    with open(path, "w", encoding="utf-8") as f:
        json.dump(report_to_dict(report, include_per_sample), f,
                  indent=2, ensure_ascii=False, sort_keys=False)
        f.write("\n")
    return path


#: Column order for the per-language / aggregate CSV.
SUMMARY_CSV_FIELDS = [
    "scope", "language", "language_name",
    "n", "n_legitimate", "n_phishing",
    "baseline_evaluated_n", "baseline_failures",
    "baseline_accuracy", "baseline_precision", "baseline_recall", "baseline_f1",
    "path_b_evaluated_n", "translation_failures", "translated_classifier_failures",
    "translation_success_rate",
    "path_b_accuracy", "path_b_precision", "path_b_recall", "path_b_f1",
    "paired_n",
    "paired_baseline_accuracy", "paired_baseline_precision",
    "paired_baseline_recall", "paired_baseline_f1",
    "paired_path_b_accuracy", "paired_path_b_precision",
    "paired_path_b_recall", "paired_path_b_f1",
    "delta_accuracy", "delta_precision", "delta_recall", "delta_f1",
    "both_correct", "a_correct_b_wrong", "b_correct_a_wrong", "both_wrong",
    "mcnemar_valid", "mcnemar_method", "mcnemar_statistic", "mcnemar_p_value",
    "baseline_latency_count", "baseline_latency_mean_s",
    "baseline_latency_median_s", "baseline_latency_p95_s",
    "translation_latency_count", "translation_latency_mean_s",
    "translation_latency_median_s", "translation_latency_p95_s",
    "translated_classifier_latency_count", "translated_classifier_latency_mean_s",
    "translated_classifier_latency_median_s", "translated_classifier_latency_p95_s",
    "path_b_total_latency_count", "path_b_total_latency_mean_s",
    "path_b_total_latency_median_s", "path_b_total_latency_p95_s",
]


def _lat_cols(prefix: str, s: LatencyStats) -> dict:
    return {
        f"{prefix}_count": s.count,
        f"{prefix}_mean_s": s.mean_s,
        f"{prefix}_median_s": s.median_s,
        f"{prefix}_p95_s": s.p95_s,
    }


def language_metrics_row(m: LanguageMetrics) -> dict:
    row: dict = {
        "scope": "language",
        "language": m.language,
        "language_name": m.language_name,
        "n": m.n,
        "n_legitimate": m.n_legitimate,
        "n_phishing": m.n_phishing,
        "baseline_evaluated_n": m.baseline_evaluated_n,
        "baseline_failures": m.baseline_failures,
        "baseline_accuracy": m.baseline.accuracy,
        "baseline_precision": m.baseline.precision,
        "baseline_recall": m.baseline.recall,
        "baseline_f1": m.baseline.f1,
        "path_b_evaluated_n": m.path_b_evaluated_n,
        "translation_failures": m.translation_failures,
        "translated_classifier_failures": m.translated_classifier_failures,
        "translation_success_rate": m.translation_success_rate,
        "path_b_accuracy": m.path_b.accuracy,
        "path_b_precision": m.path_b.precision,
        "path_b_recall": m.path_b.recall,
        "path_b_f1": m.path_b.f1,
        "paired_n": m.paired_n,
        "paired_baseline_accuracy": m.paired_baseline.accuracy,
        "paired_baseline_precision": m.paired_baseline.precision,
        "paired_baseline_recall": m.paired_baseline.recall,
        "paired_baseline_f1": m.paired_baseline.f1,
        "paired_path_b_accuracy": m.paired_path_b.accuracy,
        "paired_path_b_precision": m.paired_path_b.precision,
        "paired_path_b_recall": m.paired_path_b.recall,
        "paired_path_b_f1": m.paired_path_b.f1,
        "delta_accuracy": m.delta_accuracy,
        "delta_precision": m.delta_precision,
        "delta_recall": m.delta_recall,
        "delta_f1": m.delta_f1,
        "both_correct": m.paired_counts.both_correct,
        "a_correct_b_wrong": m.paired_counts.a_correct_b_wrong,
        "b_correct_a_wrong": m.paired_counts.b_correct_a_wrong,
        "both_wrong": m.paired_counts.both_wrong,
        "mcnemar_valid": m.mcnemar.valid,
        "mcnemar_method": m.mcnemar.method,
        "mcnemar_statistic": m.mcnemar.statistic,
        "mcnemar_p_value": m.mcnemar.p_value,
    }
    row.update(_lat_cols("baseline_latency", m.baseline_latency))
    row.update(_lat_cols("translation_latency", m.translation_latency))
    row.update(_lat_cols("translated_classifier_latency", m.translated_classifier_latency))
    row.update(_lat_cols("path_b_total_latency", m.path_b_total_latency))
    return row


def aggregate_rows(agg: Aggregate) -> list[dict]:
    """Two extra CSV rows: pooled (micro) and per-language mean (macro)."""
    micro: dict = {
        "scope": "MICRO_POOLED",
        "language": "ALL",
        "language_name": "All languages (pooled predictions)",
        "n": agg.n_samples,
        "n_legitimate": agg.n_legitimate,
        "n_phishing": agg.n_phishing,
        "baseline_evaluated_n": agg.baseline_evaluated_n,
        "baseline_failures": agg.baseline_failures,
        "baseline_accuracy": agg.micro_baseline.accuracy,
        "baseline_precision": agg.micro_baseline.precision,
        "baseline_recall": agg.micro_baseline.recall,
        "baseline_f1": agg.micro_baseline.f1,
        "path_b_evaluated_n": agg.path_b_evaluated_n,
        "translation_failures": agg.translation_failures,
        "translated_classifier_failures": agg.translated_classifier_failures,
        "translation_success_rate": agg.translation_success_rate,
        "path_b_accuracy": agg.micro_path_b.accuracy,
        "path_b_precision": agg.micro_path_b.precision,
        "path_b_recall": agg.micro_path_b.recall,
        "path_b_f1": agg.micro_path_b.f1,
        "paired_n": agg.micro_paired_n,
        "paired_baseline_accuracy": agg.micro_paired_baseline.accuracy,
        "paired_baseline_precision": agg.micro_paired_baseline.precision,
        "paired_baseline_recall": agg.micro_paired_baseline.recall,
        "paired_baseline_f1": agg.micro_paired_baseline.f1,
        "paired_path_b_accuracy": agg.micro_paired_path_b.accuracy,
        "paired_path_b_precision": agg.micro_paired_path_b.precision,
        "paired_path_b_recall": agg.micro_paired_path_b.recall,
        "paired_path_b_f1": agg.micro_paired_path_b.f1,
        "delta_accuracy": agg.micro_delta_accuracy,
        "delta_precision": agg.micro_delta_precision,
        "delta_recall": agg.micro_delta_recall,
        "delta_f1": agg.micro_delta_f1,
        "both_correct": agg.paired_counts.both_correct,
        "a_correct_b_wrong": agg.paired_counts.a_correct_b_wrong,
        "b_correct_a_wrong": agg.paired_counts.b_correct_a_wrong,
        "both_wrong": agg.paired_counts.both_wrong,
        "mcnemar_valid": agg.mcnemar.valid,
        "mcnemar_method": agg.mcnemar.method,
        "mcnemar_statistic": agg.mcnemar.statistic,
        "mcnemar_p_value": agg.mcnemar.p_value,
    }
    micro.update(_lat_cols("baseline_latency", agg.baseline_latency))
    micro.update(_lat_cols("translation_latency", agg.translation_latency))
    micro.update(_lat_cols("translated_classifier_latency", agg.translated_classifier_latency))
    micro.update(_lat_cols("path_b_total_latency", agg.path_b_total_latency))

    macro: dict = {
        "scope": "MACRO_AVERAGE",
        "language": "ALL",
        "language_name": f"Mean across {agg.n_languages} language(s)",
        "n": agg.n_samples,
        "baseline_evaluated_n": agg.macro_baseline.languages_included,
        "baseline_accuracy": agg.macro_baseline.accuracy,
        "baseline_precision": agg.macro_baseline.precision,
        "baseline_recall": agg.macro_baseline.recall,
        "baseline_f1": agg.macro_baseline.f1,
        "path_b_evaluated_n": agg.macro_path_b.languages_included,
        "path_b_accuracy": agg.macro_path_b.accuracy,
        "path_b_precision": agg.macro_path_b.precision,
        "path_b_recall": agg.macro_path_b.recall,
        "path_b_f1": agg.macro_path_b.f1,
        "paired_n": agg.macro_delta_languages_included,
        "delta_accuracy": agg.macro_delta_accuracy,
        "delta_precision": agg.macro_delta_precision,
        "delta_recall": agg.macro_delta_recall,
        "delta_f1": agg.macro_delta_f1,
    }
    return [micro, macro]


def save_summary_csv(path: Path, report: BenchmarkReport) -> Path:
    path = Path(path)
    path.parent.mkdir(parents=True, exist_ok=True)
    with open(path, "w", newline="", encoding="utf-8") as f:
        writer = csv.DictWriter(f, fieldnames=SUMMARY_CSV_FIELDS,
                                extrasaction="ignore", restval="")
        writer.writeheader()
        for m in report.per_language:
            writer.writerow(language_metrics_row(m))
        for row in aggregate_rows(report.aggregate):
            writer.writerow(row)
    return path


PER_SAMPLE_CSV_FIELDS = [
    "id", "language", "language_name", "label",
    "baseline_status", "baseline_phishing_prob", "baseline_pred",
    "baseline_latency_s", "baseline_error",
    "translation_status", "translation_latency_s", "translation_error",
    "translated_status", "translated_phishing_prob", "translated_pred",
    "translated_classifier_latency_s", "translated_error",
    "path_b_total_latency_s",
    "baseline_correct", "path_b_correct", "paired_evaluable",
    "disagreement",
    "source_text", "translated_text",
]


def _disagreement_label(r: SampleResult) -> str:
    if not r.paired_evaluable:
        return "not_paired"
    if r.baseline_correct and r.path_b_correct:
        return "both_correct"
    if r.baseline_correct and not r.path_b_correct:
        return "a_correct_b_wrong"
    if r.path_b_correct and not r.baseline_correct:
        return "b_correct_a_wrong"
    return "both_wrong"


def save_per_sample_csv(path: Path, report: BenchmarkReport,
                        samples_by_id: dict[int, Sample]) -> Path:
    """
    One row per sample, including the translated English text.

    Translation quality is judged by reading this file, never by looking at
    the classifier score.
    """
    path = Path(path)
    path.parent.mkdir(parents=True, exist_ok=True)
    with open(path, "w", newline="", encoding="utf-8") as f:
        writer = csv.DictWriter(f, fieldnames=PER_SAMPLE_CSV_FIELDS,
                                extrasaction="ignore", restval="")
        writer.writeheader()
        for r in sorted(report.per_sample, key=lambda x: (x.language, x.id)):
            row = asdict(r)
            row["disagreement"] = _disagreement_label(r)
            sample = samples_by_id.get(r.id)
            row["source_text"] = sample.text if sample else ""
            writer.writerow(row)
    return path


# ---------------------------------------------------------------------------
# Console output
# ---------------------------------------------------------------------------

_DIV = "-" * 118


def _fmt_pct(v: Optional[float]) -> str:
    return "    n/a" if v is None else f"{v * 100:6.2f}%"


def _fmt_delta(v: Optional[float]) -> str:
    return "     n/a" if v is None else f"{v * 100:+7.2f}pp"


def _fmt_lat(v: Optional[float]) -> str:
    return "     n/a" if v is None else f"{v:7.3f}s"


def print_dataset_issues(issues: Sequence[DatasetIssue], limit: int = 20) -> None:
    if not issues:
        print("  Dataset validation: no malformed rows.")
        return
    print(f"  Dataset validation: {len(issues)} MALFORMED ROW(S) EXCLUDED "
          f"from evaluation:")
    for issue in issues[:limit]:
        print(f"    row {issue.row_number} (id={issue.sample_id}): {issue.reason}")
    if len(issues) > limit:
        print(f"    ... and {len(issues) - limit} more (see the JSON report).")


def print_language_table(per_language: Sequence[LanguageMetrics]) -> None:
    print()
    print(_DIV)
    print("  Per-language results   A = raw Indic -> V2     B = Indic -> NLLB -> English -> V2")
    print("  (Deltas use the PAIRED subset only: samples where both paths produced a prediction.)")
    print(_DIV)
    header = (f"  {'Language':<11} {'N':>4} {'A-eval':>6} {'B-eval':>6} {'TrFail':>6} "
              f"{'ClsFail':>7} {'A-Acc':>7} {'B-Acc':>7} {'dAcc':>9} "
              f"{'A-F1':>7} {'B-F1':>7} {'dF1':>9} {'TrLat':>8}")
    print(header)
    print("  " + "-" * (len(header) - 2))
    for m in per_language:
        print(f"  {m.language_name:<11} {m.n:>4} {m.baseline_evaluated_n:>6} "
              f"{m.path_b_evaluated_n:>6} {m.translation_failures:>6} "
              f"{m.translated_classifier_failures:>7} "
              f"{_fmt_pct(m.baseline.accuracy):>7} {_fmt_pct(m.path_b.accuracy):>7} "
              f"{_fmt_delta(m.delta_accuracy):>9} "
              f"{_fmt_pct(m.baseline.f1):>7} {_fmt_pct(m.path_b.f1):>7} "
              f"{_fmt_delta(m.delta_f1):>9} "
              f"{_fmt_lat(m.translation_latency.mean_s):>8}")
    print(_DIV)


def print_aggregates(agg: Aggregate) -> None:
    print()
    print(_DIV)
    print("  Aggregates")
    print(_DIV)
    print(f"  Samples:                    {agg.n_samples} "
          f"(legitimate {agg.n_legitimate} / phishing {agg.n_phishing}) "
          f"across {agg.n_languages} language(s)")
    print(f"  Path A evaluated:           {agg.baseline_evaluated_n}"
          f"   (classifier failures: {agg.baseline_failures})")
    print(f"  Path B evaluated:           {agg.path_b_evaluated_n}"
          f"   (translation failures: {agg.translation_failures},"
          f" translated-classifier failures: {agg.translated_classifier_failures})")
    print(f"  Translation success rate:   "
          f"{_fmt_pct(agg.translation_success_rate)}"
          f"   ({agg.translation_success_n}/{agg.translation_attempted_n})")
    print(f"  Paired samples (both paths):{agg.micro_paired_n:>5}")
    print()
    print("  MICRO / POOLED  -- every valid prediction counts once; "
          "deltas over the paired subset")
    print(f"    {'Metric':<10} {'A (n=' + str(agg.micro_baseline.n) + ')':>14} "
          f"{'B (n=' + str(agg.micro_path_b.n) + ')':>14} "
          f"{'delta (paired n=' + str(agg.micro_paired_n) + ')':>28}")
    for name, a, b, d in [
        ("Accuracy", agg.micro_baseline.accuracy, agg.micro_path_b.accuracy, agg.micro_delta_accuracy),
        ("Precision", agg.micro_baseline.precision, agg.micro_path_b.precision, agg.micro_delta_precision),
        ("Recall", agg.micro_baseline.recall, agg.micro_path_b.recall, agg.micro_delta_recall),
        ("F1", agg.micro_baseline.f1, agg.micro_path_b.f1, agg.micro_delta_f1),
    ]:
        print(f"    {name:<10} {_fmt_pct(a):>14} {_fmt_pct(b):>14} {_fmt_delta(d):>28}")
    print()
    print(f"  MACRO AVERAGE   -- each language counts once "
          f"(A over {agg.macro_baseline.languages_included} lang, "
          f"B over {agg.macro_path_b.languages_included} lang, "
          f"delta over {agg.macro_delta_languages_included} lang)")
    print(f"    {'Metric':<10} {'A':>14} {'B':>14} {'delta':>28}")
    for name, a, b, d in [
        ("Accuracy", agg.macro_baseline.accuracy, agg.macro_path_b.accuracy, agg.macro_delta_accuracy),
        ("Precision", agg.macro_baseline.precision, agg.macro_path_b.precision, agg.macro_delta_precision),
        ("Recall", agg.macro_baseline.recall, agg.macro_path_b.recall, agg.macro_delta_recall),
        ("F1", agg.macro_baseline.f1, agg.macro_path_b.f1, agg.macro_delta_f1),
    ]:
        print(f"    {name:<10} {_fmt_pct(a):>14} {_fmt_pct(b):>14} {_fmt_delta(d):>28}")
    print(_DIV)


def print_paired_analysis(agg: Aggregate) -> None:
    c = agg.paired_counts
    print()
    print(_DIV)
    print("  Paired sample-level analysis (same email, both paths)")
    print(_DIV)
    print(f"    Paired samples:              {c.n_paired}")
    print(f"    Both correct:                {c.both_correct}")
    print(f"    A correct / B wrong:         {c.a_correct_b_wrong}")
    print(f"    A wrong   / B correct:       {c.b_correct_a_wrong}")
    print(f"    Both wrong:                  {c.both_wrong}")
    print()
    m = agg.mcnemar
    if m.valid:
        print(f"    McNemar ({m.method}): statistic={m.statistic}  p={m.p_value}")
        print(f"    {m.note}")
        print("    Interpret with care: this p-value applies to this synthetic "
              "dataset only.")
    else:
        print(f"    McNemar: not applicable -- {m.note}")
    print(_DIV)


def print_latency(agg: Aggregate) -> None:
    print()
    print(_DIV)
    print("  Latency (successful operations only)")
    print(_DIV)
    print(f"    {'Operation':<30} {'count':>7} {'mean':>10} {'median':>10} {'p95':>10}")
    for name, s in [
        ("Path A classifier", agg.baseline_latency),
        ("NLLB translation", agg.translation_latency),
        ("Path B classifier", agg.translated_classifier_latency),
        ("Path B total (trans + cls)", agg.path_b_total_latency),
    ]:
        print(f"    {name:<30} {s.count:>7} {_fmt_lat(s.mean_s):>10} "
              f"{_fmt_lat(s.median_s):>10} {_fmt_lat(s.p95_s):>10}")
    print(_DIV)


def print_disagreements(d: DisagreementSummary, show: int = 3) -> None:
    print()
    print(_DIV)
    print("  Disagreement cases (the diagnostic signal)")
    print(_DIV)
    print(f"    A correct / B wrong: {d.n_a_correct_b_wrong}"
          f"    A wrong / B correct: {d.n_b_correct_a_wrong}")
    for title, examples in [
        ("A correct / B wrong", d.examples_a_correct_b_wrong),
        ("A wrong / B correct", d.examples_b_correct_a_wrong),
    ]:
        if not examples:
            continue
        print(f"\n    -- {title} (showing {min(show, len(examples))}) --")
        for ex in examples[:show]:
            print(f"      id={ex.id} [{ex.language}] true={ex.label} "
                  f"A={ex.baseline_pred} B={ex.path_b_pred}")
            print(f"        src: {ex.source_text_excerpt[:150]}")
            print(f"        en : {ex.translated_text_excerpt[:150]}")
    print()
    print("    Full lists are in the JSON report and the per-sample CSV.")
    print("    Translation quality must be judged by reading the English text,")
    print("    not by looking at the classifier score.")
    print(_DIV)


def print_closing_note(agg: Aggregate) -> None:
    print()
    print(_DIV)
    print("  Notes on interpretation")
    print(_DIV)
    print("    * The dataset is synthetic and template-derived. These figures are a")
    print("      relative, directional signal on a narrow distribution -- not an")
    print("      accuracy claim for real Indic-language phishing traffic.")
    print("    * Micro and macro can legitimately disagree when failure counts differ")
    print("      across languages. Both are reported above; neither is 'the' number.")
    print("    * Failed translations and failed classifier calls are excluded from the")
    print("      metric denominators and counted as failures. They are never scored as")
    print("      'legitimate'.")
    print("    * NLLB remains a prototype. Nothing here changes production behaviour.")
    print(_DIV)


# ---------------------------------------------------------------------------
# CLI
# ---------------------------------------------------------------------------

def build_arg_parser() -> argparse.ArgumentParser:
    p = argparse.ArgumentParser(
        description="ValorProtects -- Indic NLLB evaluation harness (Path A vs Path B).",
        formatter_class=argparse.ArgumentDefaultsHelpFormatter,
    )
    p.add_argument("--dataset", default=str(DEFAULT_DATASET),
                   help="Path to indic_eval.csv")
    p.add_argument("--lang", action="append", default=None, metavar="CODE",
                   help="Restrict to this language code (repeatable)")
    p.add_argument("--max-per-lang", type=int, default=None,
                   help="Cap samples per language (smoke tests)")
    p.add_argument("--max-rows", type=int, default=None,
                   help="Global cap on evaluated samples (applied after sorting)")
    p.add_argument("--threshold", type=float, default=PHISHING_THRESHOLD,
                   help="Phishing probability threshold on the 0-100 scale")
    p.add_argument("--results-dir", default=str(DEFAULT_RESULTS_DIR),
                   help="Directory for the three output files")
    p.add_argument("--json-out", default=None, help="Override the JSON output path")
    p.add_argument("--csv-out", default=None, help="Override the summary CSV path")
    p.add_argument("--per-sample-out", default=None,
                   help="Override the per-sample CSV path")
    p.add_argument("--no-save", action="store_true",
                   help="Print results without writing any file")
    p.add_argument("--json-include-per-sample", action="store_true",
                   help="Embed per-sample records in the JSON as well as the CSV")
    p.add_argument("--examples", type=int, default=DEFAULT_EXAMPLE_LIMIT,
                   help="Disagreement examples stored per direction")
    p.add_argument("--dry-run", action="store_true",
                   help="Use deterministic stubs instead of V2 and NLLB "
                        "(pipeline check only; the scores are meaningless)")
    p.add_argument("--strict", action="store_true",
                   help="Exit non-zero if the dataset contains malformed rows")
    return p


def main(argv: Optional[Sequence[str]] = None) -> int:
    argv = list(sys.argv[1:] if argv is None else argv)
    args = build_arg_parser().parse_args(argv)

    print()
    print("=" * 78)
    print("  ValorProtects -- Indic NLLB evaluation harness")
    print("  Path A: Indic -> V2        Path B: Indic -> NLLB -> English -> V2")
    print("  ADVISORY: Path B output is prototype-only and never reaches production.")
    print("=" * 78)
    print()

    dataset_path = Path(args.dataset)
    try:
        dataset = load_dataset(
            dataset_path,
            languages=args.lang,
            max_per_language=args.max_per_lang,
            max_rows=args.max_rows,
        )
    except (FileNotFoundError, ValueError) as exc:
        print(f"  ERROR: {exc}")
        return 2

    print(f"  Dataset: {dataset.path}")
    print(f"  sha256:  {dataset.sha256}")
    print(f"  Rows read: {dataset.rows_read}   Samples evaluated: {len(dataset.samples)}")
    print_dataset_issues(dataset.issues)

    if args.strict and dataset.issues:
        print("\n  --strict: malformed rows present, aborting before evaluation.")
        return 3

    if not dataset.samples:
        print("\n  ERROR: no samples to evaluate (check --lang / --max-rows filters).")
        return 2

    if args.dry_run:
        print("\n  MODE: DRY RUN -- deterministic stubs; no V2 model and no NLLB "
              "weights are loaded.")
        print("  The resulting scores are plumbing checks only and must not be "
              "reported as results.")
        classifier: ClassifierFn = make_dry_run_classifier(args.threshold)
        translator: TranslatorFn = make_dry_run_translator()
    else:
        print("\n  Loading the production V2 classifier and the NLLB-200 prototype ...")
        try:
            classifier = make_real_classifier()
            translator = make_real_translator()
        except Exception as exc:  # noqa: BLE001
            print(f"\n  ERROR: could not initialise the models: "
                  f"{type(exc).__name__}: {exc}")
            print("  Run with --dry-run to exercise the harness without models.")
            return 4

    print(f"  Evaluating {len(dataset.samples)} samples ...\n")

    last_lang = {"value": None}

    def _progress(index: int, total: int, sample: Sample) -> None:
        if last_lang["value"] != sample.language:
            last_lang["value"] = sample.language
            print(f"    [{sample.language}] {sample.language_name} ...", flush=True)
        if index % 100 == 0 or index == total:
            print(f"      {index}/{total}", flush=True)

    started = time.perf_counter()
    results = evaluate_samples(
        dataset.samples,
        classifier=classifier,
        translator=translator,
        threshold=args.threshold,
        progress=_progress,
    )
    wall = time.perf_counter() - started

    report = build_report(
        dataset=dataset,
        results=results,
        threshold=args.threshold,
        dry_run=args.dry_run,
        argv=["python", "scripts/evaluate_indic_nllb.py", *argv],
        example_limit=args.examples,
    )
    report.run_metadata["wall_clock_seconds"] = round(wall, 3)

    print_language_table(report.per_language)
    print_aggregates(report.aggregate)
    print_paired_analysis(report.aggregate)
    print_latency(report.aggregate)
    print_disagreements(report.disagreements)
    print_closing_note(report.aggregate)

    if not args.no_save:
        results_dir = Path(args.results_dir)
        json_path = Path(args.json_out) if args.json_out else results_dir / JSON_FILENAME
        csv_path = Path(args.csv_out) if args.csv_out else results_dir / CSV_FILENAME
        sample_path = (Path(args.per_sample_out) if args.per_sample_out
                       else results_dir / PER_SAMPLE_FILENAME)
        samples_by_id = {s.id: s for s in dataset.samples}

        save_json(json_path, report, include_per_sample=args.json_include_per_sample)
        save_summary_csv(csv_path, report)
        save_per_sample_csv(sample_path, report, samples_by_id)
        print()
        print(f"  JSON       -> {json_path}")
        print(f"  Summary CSV-> {csv_path}")
        print(f"  Per-sample -> {sample_path}")

    print(f"\n  Done in {wall:.1f}s.\n")
    return 0


if __name__ == "__main__":
    sys.exit(main())
