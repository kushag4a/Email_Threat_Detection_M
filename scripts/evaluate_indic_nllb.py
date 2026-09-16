#!/usr/bin/env python
"""
ValorProtects -- Indic NLLB Evaluation Benchmark
=================================================

Compares two classification paths for each Indic-language email sample:

  Path A  Baseline
            raw Indic text --> V2 phishing classifier

  Path B  Translation
            Indic text --> NLLB-200 --> English --> V2 phishing classifier

Metrics calculated per language and in aggregate:
  accuracy, precision, recall, F1, delta (B - A)

Translation side-statistics:
  successful translations, failures, mean latency (seconds)

ADVISORY NOTE
-------------
All Path-B classification results are PROTOTYPE ONLY.  They are produced by
calling the production V2 classifier on NLLB-translated text for offline
evaluation purposes.  These results:
  - Do NOT affect any production risk score
  - Do NOT affect any stored scan result
  - Do NOT become independent risk evidence
  - Are never written to analysis_service, risk_engine, or any live pipeline

Usage
-----
    # Full benchmark (downloads model if not cached):
    python scripts/evaluate_indic_nllb.py --save-default

    # Single language:
    python scripts/evaluate_indic_nllb.py --lang hin_Deva

    # Limit rows per language (quick smoke-test):
    python scripts/evaluate_indic_nllb.py --max-rows 10

    # Save results explicitly:
    python scripts/evaluate_indic_nllb.py --json-out out.json --csv-out out.csv

    # Dry-run (no NLLB inference, for testing the pipeline):
    python scripts/evaluate_indic_nllb.py --dry-run
"""
from __future__ import annotations

import argparse
import csv
import json
import sys
import time
import warnings
from dataclasses import dataclass, asdict
from pathlib import Path
from typing import Optional

# ---------------------------------------------------------------------------
# Path setup
# ---------------------------------------------------------------------------
_SCRIPT_DIR = Path(__file__).resolve().parent
_PROJECT_ROOT = _SCRIPT_DIR.parent
sys.path.insert(0, str(_PROJECT_ROOT))

# Load .env BEFORE any project import so os.getenv() in config.py sees values.
from backend.app.multilingual.config import load_nllb_env
load_nllb_env()

from backend.app.multilingual.language_codes import SUPPORTED_LANGUAGES
from backend.app.multilingual.nllb_translator import translate, TranslationStatus
from backend.app.services.ml_classifier import classify_email

# ---------------------------------------------------------------------------
# Constants
# ---------------------------------------------------------------------------
DEFAULT_DATASET = _PROJECT_ROOT / "datasets" / "evaluation" / "indic" / "indic_eval.csv"
DEFAULT_RESULTS_DIR = _PROJECT_ROOT / "datasets" / "evaluation" / "indic" / "results"

# Phishing probability threshold for binary prediction (0-100 scale).
PHISHING_THRESHOLD = 50.0


# ---------------------------------------------------------------------------
# Data structures
# ---------------------------------------------------------------------------

@dataclass
class Sample:
    id: int
    language: str
    language_name: str
    text: str
    label: int
    source: str
    notes: str = ""


@dataclass
class TranslationRecord:
    sample_id: int
    language: str
    success: bool
    translated_text: Optional[str]
    latency_s: float
    error: Optional[str]


@dataclass
class PredictionRecord:
    sample_id: int
    language: str
    label: int
    baseline_phishing_prob: float
    baseline_pred: int
    translated_phishing_prob: Optional[float]
    translated_pred: Optional[int]
    translation_success: bool
    translation_latency_s: float


@dataclass
class LanguageMetrics:
    language: str
    language_name: str
    n_samples: int
    n_legit: int
    n_phishing: int
    n_translation_success: int
    n_translation_failure: int
    mean_translation_latency_s: float
    baseline_accuracy: float
    baseline_precision: float
    baseline_recall: float
    baseline_f1: float
    translated_accuracy: Optional[float]
    translated_precision: Optional[float]
    translated_recall: Optional[float]
    translated_f1: Optional[float]
    delta_accuracy: Optional[float]
    delta_precision: Optional[float]
    delta_recall: Optional[float]
    delta_f1: Optional[float]


@dataclass
class AggregateMetrics:
    n_languages: int
    n_samples_total: int
    n_legit_total: int
    n_phishing_total: int
    n_translation_success: int
    n_translation_failure: int
    translation_failure_rate: float
    mean_translation_latency_s: float
    macro_baseline_accuracy: float
    macro_baseline_precision: float
    macro_baseline_recall: float
    macro_baseline_f1: float
    macro_translated_accuracy: float
    macro_translated_precision: float
    macro_translated_recall: float
    macro_translated_f1: float
    macro_delta_accuracy: float
    macro_delta_precision: float
    macro_delta_recall: float
    macro_delta_f1: float


# ---------------------------------------------------------------------------
# Dataset loading
# ---------------------------------------------------------------------------

def load_dataset(
    path: Path,
    lang_filter: Optional[str] = None,
    max_rows: Optional[int] = None,
) -> list[Sample]:
    """Load CSV dataset and return Sample objects."""
    if not path.exists():
        raise FileNotFoundError(
            f"Dataset not found at {path}. "
            "Run `python datasets/evaluation/indic/generate_dataset.py` first."
        )
    samples: list[Sample] = []
    with open(path, newline="", encoding="utf-8") as f:
        reader = csv.DictReader(f)
        for row in reader:
            lang = row["language"]
            if lang_filter and lang != lang_filter:
                continue
            samples.append(Sample(
                id=int(row["id"]),
                language=lang,
                language_name=row.get("language_name", SUPPORTED_LANGUAGES.get(lang, lang)),
                text=row["text"],
                label=int(row["label"]),
                source=row.get("source", "synthetic"),
                notes=row.get("notes", ""),
            ))
            if max_rows and len(samples) >= max_rows:
                break
    return samples


# ---------------------------------------------------------------------------
# Classifier helpers
# ---------------------------------------------------------------------------

def _classify_text(text: str) -> float:
    """Call V2 classify_email(), return phishing_probability (0-100). Never raises."""
    try:
        result = classify_email(text)
        return float(result["phishing_probability"])
    except Exception as exc:  # noqa: BLE001
        warnings.warn(f"classify_email failed: {exc}", stacklevel=2)
        return 0.0


def _pred_from_prob(prob: float, threshold: float = PHISHING_THRESHOLD) -> int:
    """Convert phishing probability (0-100) to binary label (0 or 1)."""
    return 1 if prob >= threshold else 0


# ---------------------------------------------------------------------------
# Metrics
# ---------------------------------------------------------------------------

def compute_metrics(labels: list[int], preds: list[int]) -> tuple[float, float, float, float]:
    """
    Compute accuracy, precision, recall, F1 (binary, positive class = phishing = 1).
    Returns (accuracy, precision, recall, f1). All in [0.0, 1.0].
    Returns (0.0, 0.0, 0.0, 0.0) for empty input.
    """
    if not labels:
        return 0.0, 0.0, 0.0, 0.0
    tp = sum(1 for l, p in zip(labels, preds) if l == 1 and p == 1)
    tn = sum(1 for l, p in zip(labels, preds) if l == 0 and p == 0)
    fp = sum(1 for l, p in zip(labels, preds) if l == 0 and p == 1)
    fn = sum(1 for l, p in zip(labels, preds) if l == 1 and p == 0)
    total = tp + tn + fp + fn
    accuracy  = (tp + tn) / total if total else 0.0
    precision = tp / (tp + fp)    if (tp + fp) else 0.0
    recall    = tp / (tp + fn)    if (tp + fn) else 0.0
    f1 = (2 * precision * recall / (precision + recall)) if (precision + recall) else 0.0
    return round(accuracy, 4), round(precision, 4), round(recall, 4), round(f1, 4)


# ---------------------------------------------------------------------------
# Core evaluation loop
# ---------------------------------------------------------------------------

def evaluate_language(
    samples: list[Sample],
    dry_run: bool = False,
) -> tuple[list[PredictionRecord], list[TranslationRecord]]:
    """Evaluate all samples for one language. Returns (pred_records, trans_records)."""
    pred_records: list[PredictionRecord] = []
    trans_records: list[TranslationRecord] = []

    for sample in samples:
        # Path A: raw Indic text -> V2
        try:
            baseline_prob = _classify_text(sample.text)
        except Exception as exc:  # noqa: BLE001 -- evaluate_language must not raise
            warnings.warn(f"baseline classify failed for sample {sample.id}: {exc}", stacklevel=2)
            baseline_prob = 0.0
        baseline_pred = _pred_from_prob(baseline_prob)

        # Path B: translate -> V2
        if dry_run:
            import random
            success = random.random() > 0.1
            latency = round(random.uniform(0.05, 0.5), 3)
            translated_text = f"[dry-run sample {sample.id}]" if success else None
            error = None if success else "dry-run simulated failure"
        else:
            t0 = time.perf_counter()
            tr = translate(sample.text, sample.language)
            latency = round(time.perf_counter() - t0, 3)
            success = tr.status == TranslationStatus.TRANSLATED
            translated_text = tr.translated_text if success else None
            error = tr.error if not success else None

        trans_records.append(TranslationRecord(
            sample_id=sample.id,
            language=sample.language,
            success=success,
            translated_text=translated_text,
            latency_s=latency,
            error=error,
        ))

        if success and translated_text:
            try:
                translated_prob = _classify_text(translated_text)
                translated_pred = _pred_from_prob(translated_prob)
            except Exception as exc:  # noqa: BLE001
                warnings.warn(f"translated classify failed for sample {sample.id}: {exc}", stacklevel=2)
                translated_prob = None
                translated_pred = None
        else:
            translated_prob = None
            translated_pred = None

        pred_records.append(PredictionRecord(
            sample_id=sample.id,
            language=sample.language,
            label=sample.label,
            baseline_phishing_prob=baseline_prob,
            baseline_pred=baseline_pred,
            translated_phishing_prob=translated_prob,
            translated_pred=translated_pred,
            translation_success=success,
            translation_latency_s=latency,
        ))

    return pred_records, trans_records


def compute_language_metrics(
    language: str,
    samples: list[Sample],
    pred_records: list[PredictionRecord],
    trans_records: list[TranslationRecord],
) -> LanguageMetrics:
    """Compute all metrics for a single language."""
    lang_name = SUPPORTED_LANGUAGES.get(language, language)
    n_legit   = sum(1 for s in samples if s.label == 0)
    n_phishing= sum(1 for s in samples if s.label == 1)
    n_success = sum(1 for t in trans_records if t.success)
    n_fail    = sum(1 for t in trans_records if not t.success)
    latencies = [t.latency_s for t in trans_records if t.success]
    mean_lat  = round(sum(latencies) / len(latencies), 3) if latencies else 0.0

    # Path A: full sample set
    all_labels    = [p.label for p in pred_records]
    baseline_preds= [p.baseline_pred for p in pred_records]
    ba, bp, br, bf= compute_metrics(all_labels, baseline_preds)

    # Path B: only successfully translated samples
    trans_mask = [p for p in pred_records if p.translation_success and p.translated_pred is not None]
    if trans_mask:
        t_labels = [p.label for p in trans_mask]
        t_preds  = [p.translated_pred for p in trans_mask]
        ta, tp_, tr_, tf = compute_metrics(t_labels, t_preds)
        # Delta vs baseline on same subset
        b_sub = [p.baseline_pred for p in trans_mask]
        sub_ba, sub_bp, sub_br, sub_bf = compute_metrics(t_labels, b_sub)
        da, dp, dr, df = (round(ta-sub_ba,4), round(tp_-sub_bp,4),
                          round(tr_-sub_br,4), round(tf-sub_bf,4))
    else:
        ta = tp_ = tr_ = tf = None
        da = dp = dr = df = None

    return LanguageMetrics(
        language=language, language_name=lang_name,
        n_samples=len(samples), n_legit=n_legit, n_phishing=n_phishing,
        n_translation_success=n_success, n_translation_failure=n_fail,
        mean_translation_latency_s=mean_lat,
        baseline_accuracy=ba, baseline_precision=bp, baseline_recall=br, baseline_f1=bf,
        translated_accuracy=ta, translated_precision=tp_, translated_recall=tr_, translated_f1=tf,
        delta_accuracy=da, delta_precision=dp, delta_recall=dr, delta_f1=df,
    )


def compute_aggregate_metrics(
    lang_metrics: list[LanguageMetrics],
    all_trans_records: list[TranslationRecord],
) -> AggregateMetrics:
    """Macro-average across languages and aggregate translation stats."""
    n_total   = sum(m.n_samples for m in lang_metrics)
    n_legit   = sum(m.n_legit   for m in lang_metrics)
    n_phishing= sum(m.n_phishing for m in lang_metrics)
    n_success = sum(m.n_translation_success for m in lang_metrics)
    n_fail    = sum(m.n_translation_failure for m in lang_metrics)
    fail_rate = round(n_fail / (n_success + n_fail), 4) if (n_success + n_fail) else 0.0
    latencies = [t.latency_s for t in all_trans_records if t.success]
    mean_lat  = round(sum(latencies)/len(latencies), 3) if latencies else 0.0

    def _macro(values: list) -> float:
        valid = [v for v in values if v is not None]
        return round(sum(valid)/len(valid), 4) if valid else 0.0

    return AggregateMetrics(
        n_languages=len(lang_metrics),
        n_samples_total=n_total,
        n_legit_total=n_legit,
        n_phishing_total=n_phishing,
        n_translation_success=n_success,
        n_translation_failure=n_fail,
        translation_failure_rate=fail_rate,
        mean_translation_latency_s=mean_lat,
        macro_baseline_accuracy =_macro([m.baseline_accuracy  for m in lang_metrics]),
        macro_baseline_precision=_macro([m.baseline_precision for m in lang_metrics]),
        macro_baseline_recall   =_macro([m.baseline_recall    for m in lang_metrics]),
        macro_baseline_f1       =_macro([m.baseline_f1        for m in lang_metrics]),
        macro_translated_accuracy =_macro([m.translated_accuracy  for m in lang_metrics]),
        macro_translated_precision=_macro([m.translated_precision for m in lang_metrics]),
        macro_translated_recall   =_macro([m.translated_recall    for m in lang_metrics]),
        macro_translated_f1       =_macro([m.translated_f1        for m in lang_metrics]),
        macro_delta_accuracy =_macro([m.delta_accuracy  for m in lang_metrics]),
        macro_delta_precision=_macro([m.delta_precision for m in lang_metrics]),
        macro_delta_recall   =_macro([m.delta_recall    for m in lang_metrics]),
        macro_delta_f1       =_macro([m.delta_f1        for m in lang_metrics]),
    )


# ---------------------------------------------------------------------------
# Output formatting
# ---------------------------------------------------------------------------
_DIV = "-" * 110

def _pct(v: Optional[float]) -> str:
    return "  N/A  " if v is None else f"{v*100:6.1f}%"

def _delta(v: Optional[float]) -> str:
    if v is None: return "   N/A  "
    return f"{v*100:+.1f}pp"

def _lat(v: float) -> str:
    return f"{v:.3f}s"


def print_language_table(metrics: list[LanguageMetrics]) -> None:
    print(); print(_DIV)
    print("  Per-Language Comparison  (A=Baseline raw Indic->V2  B=Indic->NLLB->English->V2)")
    print(_DIV)
    hdr = (f"  {'Language':<14} {'N':>4} {'L':>4} {'P':>4}"
           f" {'Trans':>6} {'Fail':>4} {'AvgLat':>7}"
           f"  {'A-Acc':>7} {'B-Acc':>7} {'dAcc':>7}"
           f"  {'A-F1':>6} {'B-F1':>6} {'dF1':>7}")
    print(hdr); print("-" * len(hdr))
    for m in metrics:
        print(
            f"  {m.language_name:<14} {m.n_samples:>4} {m.n_legit:>4} {m.n_phishing:>4}"
            f" {m.n_translation_success:>6} {m.n_translation_failure:>4} {_lat(m.mean_translation_latency_s):>7}"
            f"  {_pct(m.baseline_accuracy):>7} {_pct(m.translated_accuracy):>7} {_delta(m.delta_accuracy):>7}"
            f"  {_pct(m.baseline_f1):>6} {_pct(m.translated_f1):>6} {_delta(m.delta_f1):>7}"
        )
    print(_DIV)


def print_aggregate_table(agg: AggregateMetrics) -> None:
    print(); print(_DIV)
    print("  Aggregate  (macro-average across all languages)")
    print(_DIV)
    print(f"  Samples total:                   {agg.n_samples_total}  (legit: {agg.n_legit_total}  phishing: {agg.n_phishing_total})")
    print(f"  Translation success/failure:     {agg.n_translation_success} / {agg.n_translation_failure}  (failure rate: {agg.translation_failure_rate*100:.1f}%)")
    print(f"  Mean translation latency:        {_lat(agg.mean_translation_latency_s)}")
    print()
    print(f"  {'Metric':<12}  {'Baseline (A)':>14}  {'Translated (B)':>14}  {'Delta (B-A)':>12}")
    print(f"  {'------':<12}  {'------------':>14}  {'--------------':>14}  {'-----------':>12}")
    for name, ba, ta, da in [
        ("Accuracy",  agg.macro_baseline_accuracy,  agg.macro_translated_accuracy,  agg.macro_delta_accuracy),
        ("Precision", agg.macro_baseline_precision, agg.macro_translated_precision, agg.macro_delta_precision),
        ("Recall",    agg.macro_baseline_recall,    agg.macro_translated_recall,    agg.macro_delta_recall),
        ("F1",        agg.macro_baseline_f1,        agg.macro_translated_f1,        agg.macro_delta_f1),
    ]:
        print(f"  {name:<12}  {_pct(ba):>14}  {_pct(ta):>14}  {_delta(da):>12}")
    print(_DIV)


def print_conclusion(agg: AggregateMetrics, lang_metrics: list[LanguageMetrics]) -> None:
    print(); print(_DIV)
    print("  Conclusion")
    print(_DIV)
    d = agg.macro_delta_f1
    if d > 0.02:   verdict = f"NLLB translation IMPROVES classification  (macro ΔF1 = {_delta(d)})"
    elif d > 0:    verdict = f"marginal improvement  (macro ΔF1 = {_delta(d)})"
    elif d < -0.02:verdict = f"NLLB translation DEGRADES classification  (macro ΔF1 = {_delta(d)})"
    elif d < 0:    verdict = f"marginal degradation  (macro ΔF1 = {_delta(d)})"
    else:          verdict = "no measurable change"
    print(f"  Overall: {verdict}")
    print()
    benefited= [m.language_name for m in lang_metrics if m.delta_f1 is not None and m.delta_f1 > 0.02]
    degraded = [m.language_name for m in lang_metrics if m.delta_f1 is not None and m.delta_f1 < -0.02]
    neutral  = [m.language_name for m in lang_metrics if m.delta_f1 is not None and abs(m.delta_f1) <= 0.02]
    failed   = [m.language_name for m in lang_metrics if m.delta_f1 is None]
    if benefited: print(f"  Languages that benefit:          {', '.join(benefited)}")
    if degraded:  print(f"  Languages that degrade:          {', '.join(degraded)}")
    if neutral:   print(f"  Languages with neutral impact:   {', '.join(neutral)}")
    if failed:    print(f"  Languages with 100%% failure:    {', '.join(failed)}")
    print()
    print(f"  Translation failure rate: {agg.translation_failure_rate*100:.1f}%")
    print(f"  Mean translation latency: {_lat(agg.mean_translation_latency_s)}")
    print()
    print("  ADVISORY: These results are prototype evaluation only.")
    print("  NLLB is NOT integrated into the production risk pipeline.")
    print(_DIV)


# ---------------------------------------------------------------------------
# Results serialisation
# ---------------------------------------------------------------------------

def save_json(
    path: Path,
    lang_metrics: list[LanguageMetrics],
    agg: AggregateMetrics,
    pred_records: list[PredictionRecord],
) -> None:
    payload = {
        "meta": {
            "generated_at": time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime()),
            "advisory": (
                "PROTOTYPE ONLY. Path B predictions are V2 classifier output on "
                "NLLB-translated text for offline evaluation. Not production results."
            ),
        },
        "aggregate": asdict(agg),
        "per_language": [asdict(m) for m in lang_metrics],
        "predictions": [asdict(p) for p in pred_records],
    }
    path.parent.mkdir(parents=True, exist_ok=True)
    with open(path, "w", encoding="utf-8") as f:
        json.dump(payload, f, indent=2, ensure_ascii=False)
    print(f"  JSON saved -> {path}")


def save_csv(path: Path, lang_metrics: list[LanguageMetrics]) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    fields = [
        "language","language_name","n_samples","n_legit","n_phishing",
        "n_translation_success","n_translation_failure","mean_translation_latency_s",
        "baseline_accuracy","baseline_precision","baseline_recall","baseline_f1",
        "translated_accuracy","translated_precision","translated_recall","translated_f1",
        "delta_accuracy","delta_precision","delta_recall","delta_f1",
    ]
    with open(path, "w", newline="", encoding="utf-8") as f:
        w = csv.DictWriter(f, fieldnames=fields, extrasaction="ignore")
        w.writeheader()
        for m in lang_metrics:
            w.writerow(asdict(m))
    print(f"  CSV saved  -> {path}")


# ---------------------------------------------------------------------------
# Entrypoint
# ---------------------------------------------------------------------------

def main() -> None:
    parser = argparse.ArgumentParser(description="ValorProtects Indic NLLB Evaluation Benchmark")
    parser.add_argument("--dataset",    default=str(DEFAULT_DATASET))
    parser.add_argument("--lang",       default=None)
    parser.add_argument("--max-rows",   type=int, default=None)
    parser.add_argument("--json-out",   default=None)
    parser.add_argument("--csv-out",    default=None)
    parser.add_argument("--save-default", action="store_true",
                        help="Save to datasets/evaluation/indic/results/ automatically")
    parser.add_argument("--dry-run",    action="store_true",
                        help="Skip real NLLB inference (pipeline/CI testing only)")
    args = parser.parse_args()

    print("\n" + "="*70)
    print("  ValorProtects -- Indic NLLB Evaluation Benchmark")
    print("  ADVISORY: Path-B results are prototype-only")
    print("="*70 + "\n")

    dataset_path = Path(args.dataset)
    print(f"  Dataset: {dataset_path}")
    if args.lang:  print(f"  Filter:  {args.lang}")
    if args.dry_run: print("  Mode:    DRY-RUN (no real NLLB inference)")
    print()

    samples = load_dataset(dataset_path, lang_filter=args.lang, max_rows=args.max_rows)
    if not samples:
        print("  No samples found.")
        sys.exit(1)

    lang_to_samples: dict[str, list[Sample]] = {}
    for s in samples:
        lang_to_samples.setdefault(s.language, []).append(s)
    print(f"  Loaded {len(samples)} samples across {len(lang_to_samples)} language(s).\n")

    all_lang_metrics: list[LanguageMetrics]   = []
    all_pred_records: list[PredictionRecord]  = []
    all_trans_records: list[TranslationRecord]= []

    for lang, lang_samples in sorted(lang_to_samples.items()):
        lang_name = SUPPORTED_LANGUAGES.get(lang, lang)
        print(f"  [{lang}] {lang_name}: {len(lang_samples)} samples ...", flush=True)
        pred_recs, trans_recs = evaluate_language(lang_samples, dry_run=args.dry_run)
        lm = compute_language_metrics(lang, lang_samples, pred_recs, trans_recs)
        all_lang_metrics.append(lm)
        all_pred_records.extend(pred_recs)
        all_trans_records.extend(trans_recs)
        print(
            f"    trans: {lm.n_translation_success} ok / {lm.n_translation_failure} fail  "
            f"lat={_lat(lm.mean_translation_latency_s)}  "
            f"BaseF1={_pct(lm.baseline_f1)}  TransF1={_pct(lm.translated_f1)}  dF1={_delta(lm.delta_f1)}"
        )

    agg = compute_aggregate_metrics(all_lang_metrics, all_trans_records)
    print_language_table(all_lang_metrics)
    print_aggregate_table(agg)
    print_conclusion(agg, all_lang_metrics)

    if args.save_default:
        ts = time.strftime("%Y%m%d_%H%M%S")
        save_json(DEFAULT_RESULTS_DIR / f"results_{ts}.json", all_lang_metrics, agg, all_pred_records)
        save_csv(DEFAULT_RESULTS_DIR  / f"results_{ts}.csv",  all_lang_metrics)
    if args.json_out:
        save_json(Path(args.json_out), all_lang_metrics, agg, all_pred_records)
    if args.csv_out:
        save_csv(Path(args.csv_out), all_lang_metrics)


if __name__ == "__main__":
    main()
