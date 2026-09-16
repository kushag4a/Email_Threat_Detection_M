"""
Focused tests for the Indic NLLB Evaluation Benchmark.

Scope
-----
- compute_metrics(): accuracy/precision/recall/F1 calculation
- compute_language_metrics(): per-language metric aggregation
- compute_aggregate_metrics(): macro-average across languages
- load_dataset(): CSV loading, filtering, empty/missing file handling
- evaluate_language(): translation-failure propagation, dry-run mode
- PredictionRecord / TranslationRecord construction

All tests are fully mocked -- no NLLB model is downloaded or loaded.
The production V2 classify_email() is patched where needed.
"""
from __future__ import annotations

import csv
import json
import os
import sys
import tempfile
from dataclasses import asdict
from pathlib import Path
from typing import Optional
from unittest.mock import MagicMock, patch

import pytest

# ── path setup ──────────────────────────────────────────────────────────────
sys.path.insert(0, str(Path(__file__).resolve().parents[1]))

from scripts.evaluate_indic_nllb import (
    Sample,
    TranslationRecord,
    PredictionRecord,
    LanguageMetrics,
    AggregateMetrics,
    compute_metrics,
    compute_language_metrics,
    compute_aggregate_metrics,
    load_dataset,
    evaluate_language,
    _classify_text,
    _pred_from_prob,
    PHISHING_THRESHOLD,
)


# ===========================================================================
# Helpers
# ===========================================================================

def _make_sample(id_: int, lang: str = "hin_Deva", label: int = 1,
                 text: str = "test") -> Sample:
    return Sample(
        id=id_, language=lang, language_name="Hindi",
        text=text, label=label, source="synthetic", notes="",
    )


def _make_pred(sample_id: int, label: int, baseline_pred: int,
               translated_pred: Optional[int] = None,
               translation_success: bool = True) -> PredictionRecord:
    return PredictionRecord(
        sample_id=sample_id,
        language="hin_Deva",
        label=label,
        baseline_phishing_prob=80.0 if baseline_pred == 1 else 20.0,
        baseline_pred=baseline_pred,
        translated_phishing_prob=(75.0 if translated_pred == 1 else 15.0)
                                  if translated_pred is not None else None,
        translated_pred=translated_pred,
        translation_success=translation_success,
        translation_latency_s=0.5,
    )


def _make_trans(sample_id: int, success: bool = True) -> TranslationRecord:
    return TranslationRecord(
        sample_id=sample_id, language="hin_Deva",
        success=success,
        translated_text="translated text" if success else None,
        latency_s=0.5 if success else 0.0,
        error=None if success else "failure reason",
    )


def _make_lang_metrics(lang: str = "hin_Deva", **kwargs) -> LanguageMetrics:
    defaults = dict(
        language=lang, language_name="Hindi",
        n_samples=50, n_legit=25, n_phishing=25,
        n_translation_success=48, n_translation_failure=2,
        mean_translation_latency_s=0.45,
        baseline_accuracy=0.72, baseline_precision=0.70, baseline_recall=0.74, baseline_f1=0.72,
        translated_accuracy=0.80, translated_precision=0.78, translated_recall=0.82, translated_f1=0.80,
        delta_accuracy=0.08, delta_precision=0.08, delta_recall=0.08, delta_f1=0.08,
    )
    defaults.update(kwargs)
    return LanguageMetrics(**defaults)


# ===========================================================================
# compute_metrics
# ===========================================================================

class TestComputeMetrics:
    """Unit tests for the metric calculation function."""

    def test_perfect_predictions(self):
        labels = [1, 1, 0, 0]
        preds  = [1, 1, 0, 0]
        acc, prec, rec, f1 = compute_metrics(labels, preds)
        assert acc == 1.0
        assert prec == 1.0
        assert rec == 1.0
        assert f1 == 1.0

    def test_all_wrong_predictions(self):
        labels = [1, 1, 0, 0]
        preds  = [0, 0, 1, 1]
        acc, prec, rec, f1 = compute_metrics(labels, preds)
        assert acc == 0.0
        assert prec == 0.0
        assert rec == 0.0
        assert f1 == 0.0

    def test_empty_input_returns_zeros(self):
        acc, prec, rec, f1 = compute_metrics([], [])
        assert acc == 0.0 and prec == 0.0 and rec == 0.0 and f1 == 0.0

    def test_all_positive_correct(self):
        """All samples are phishing and correctly predicted."""
        labels = [1, 1, 1]
        preds  = [1, 1, 1]
        acc, prec, rec, f1 = compute_metrics(labels, preds)
        assert acc == 1.0 and prec == 1.0 and rec == 1.0 and f1 == 1.0

    def test_all_negative_correct(self):
        """All samples are legit and correctly predicted."""
        labels = [0, 0, 0]
        preds  = [0, 0, 0]
        acc, prec, rec, f1 = compute_metrics(labels, preds)
        assert acc == 1.0
        # precision/recall for phishing class are 0 (no phishing samples)
        assert prec == 0.0 and rec == 0.0 and f1 == 0.0

    def test_no_predicted_positives(self):
        """Model predicts everything as legit -- recall=0, precision undefined (0)."""
        labels = [1, 0, 1, 0]
        preds  = [0, 0, 0, 0]
        acc, prec, rec, f1 = compute_metrics(labels, preds)
        assert acc == 0.5
        assert prec == 0.0
        assert rec == 0.0
        assert f1 == 0.0

    def test_known_values(self):
        """2 TP, 1 FP, 1 FN, 2 TN."""
        labels = [1, 1, 0, 0, 1, 0]
        preds  = [1, 1, 1, 0, 0, 0]
        # TP=2, FP=1, FN=1, TN=2
        acc, prec, rec, f1 = compute_metrics(labels, preds)
        assert acc == pytest.approx(4/6, rel=1e-3)
        assert prec == pytest.approx(2/3, rel=1e-3)
        assert rec == pytest.approx(2/3, rel=1e-3)
        assert f1 == pytest.approx(2/3, rel=1e-3)

    def test_returns_four_values(self):
        result = compute_metrics([1, 0], [1, 0])
        assert len(result) == 4


# ===========================================================================
# _pred_from_prob
# ===========================================================================

class TestPredFromProb:
    def test_above_threshold_is_phishing(self):
        assert _pred_from_prob(PHISHING_THRESHOLD + 1) == 1

    def test_at_threshold_is_phishing(self):
        assert _pred_from_prob(PHISHING_THRESHOLD) == 1

    def test_below_threshold_is_legit(self):
        assert _pred_from_prob(PHISHING_THRESHOLD - 1) == 0

    def test_zero_is_legit(self):
        assert _pred_from_prob(0.0) == 0

    def test_hundred_is_phishing(self):
        assert _pred_from_prob(100.0) == 1


# ===========================================================================
# compute_language_metrics
# ===========================================================================

class TestComputeLanguageMetrics:
    def _run(self, pred_records, trans_records):
        samples = [_make_sample(p.sample_id, label=p.label) for p in pred_records]
        return compute_language_metrics("hin_Deva", samples, pred_records, trans_records)

    def test_perfect_baseline_and_translated(self):
        # 4 samples: 2 phishing, 2 legit; all baseline and translated correct
        preds = [
            _make_pred(1, 1, 1, 1),
            _make_pred(2, 1, 1, 1),
            _make_pred(3, 0, 0, 0),
            _make_pred(4, 0, 0, 0),
        ]
        trans = [_make_trans(p.sample_id, True) for p in preds]
        m = self._run(preds, trans)
        assert m.baseline_accuracy == 1.0
        assert m.translated_accuracy == 1.0
        assert m.delta_accuracy == 0.0

    def test_translation_failures_excluded_from_path_b(self):
        """Samples with translation failure must not count in Path B metrics."""
        preds = [
            _make_pred(1, 1, 1, 1, True),
            _make_pred(2, 0, 0, 0, True),
            _make_pred(3, 1, 0, None, False),  # translation failed
        ]
        trans = [
            _make_trans(1, True),
            _make_trans(2, True),
            _make_trans(3, False),
        ]
        m = self._run(preds, trans)
        assert m.n_translation_success == 2
        assert m.n_translation_failure == 1
        # Path B: only 2 samples (ids 1 and 2), both correct
        assert m.translated_accuracy == 1.0

    def test_all_translations_fail_gives_none_metrics(self):
        """If all translations fail, Path B metrics should be None."""
        preds = [
            _make_pred(1, 1, 1, None, False),
            _make_pred(2, 0, 0, None, False),
        ]
        trans = [_make_trans(1, False), _make_trans(2, False)]
        m = self._run(preds, trans)
        assert m.translated_accuracy is None
        assert m.translated_f1 is None
        assert m.delta_accuracy is None
        assert m.delta_f1 is None

    def test_delta_is_b_minus_a_on_same_subset(self):
        """Delta is computed against baseline on the same subset as translation."""
        # Baseline wrong on sample 1, translated correct on sample 1
        preds = [
            _make_pred(1, 1, 0, 1, True),   # baseline wrong, translated right
            _make_pred(2, 0, 0, 0, True),   # both correct
        ]
        trans = [_make_trans(1, True), _make_trans(2, True)]
        m = self._run(preds, trans)
        # Translated: sample 1 TP, sample 2 TN -> acc=1.0
        # Baseline on same subset: sample 1 FN, sample 2 TN -> acc=0.5
        assert m.delta_accuracy == pytest.approx(0.5, abs=0.01)

    def test_mean_latency_only_from_successful_translations(self):
        preds = [
            _make_pred(1, 1, 1, 1, True),
            _make_pred(2, 0, 0, None, False),
        ]
        trans = [
            TranslationRecord(1, "hin_Deva", True, "text", latency_s=0.8, error=None),
            TranslationRecord(2, "hin_Deva", False, None, latency_s=0.0, error="fail"),
        ]
        m = self._run(preds, trans)
        assert m.mean_translation_latency_s == pytest.approx(0.8)

    def test_language_name_populated(self):
        preds = [_make_pred(1, 1, 1, 1)]
        trans = [_make_trans(1, True)]
        m = self._run(preds, trans)
        assert m.language_name == "Hindi"

    def test_n_legit_n_phishing_counts(self):
        samples = [
            _make_sample(1, label=0),
            _make_sample(2, label=0),
            _make_sample(3, label=1),
        ]
        preds = [_make_pred(s.id, s.label, s.label) for s in samples]
        trans = [_make_trans(s.id, True) for s in samples]
        m = compute_language_metrics("hin_Deva", samples, preds, trans)
        assert m.n_legit == 2
        assert m.n_phishing == 1


# ===========================================================================
# compute_aggregate_metrics
# ===========================================================================

class TestComputeAggregateMetrics:
    def _agg(self, lang_metrics, trans_records=None):
        if trans_records is None:
            trans_records = []
        return compute_aggregate_metrics(lang_metrics, trans_records)

    def test_single_language_passes_through(self):
        m = _make_lang_metrics()
        agg = self._agg([m])
        assert agg.n_languages == 1
        assert agg.n_samples_total == m.n_samples
        assert agg.macro_baseline_f1 == m.baseline_f1
        assert agg.macro_translated_f1 == m.translated_f1

    def test_macro_average_across_two_languages(self):
        m1 = _make_lang_metrics("hin_Deva", baseline_f1=0.6, translated_f1=0.8, delta_f1=0.2)
        m2 = _make_lang_metrics("tel_Telu", baseline_f1=0.8, translated_f1=0.6, delta_f1=-0.2)
        agg = self._agg([m1, m2])
        assert agg.macro_baseline_f1 == pytest.approx(0.7)
        assert agg.macro_translated_f1 == pytest.approx(0.7)
        assert agg.macro_delta_f1 == pytest.approx(0.0)

    def test_none_translated_metrics_excluded_from_macro(self):
        """Languages with 100% translation failure have None translated_f1 -- must be excluded."""
        m1 = _make_lang_metrics("hin_Deva", translated_f1=0.8, delta_f1=0.08)
        m2 = _make_lang_metrics("tel_Telu", translated_f1=None, delta_f1=None)
        agg = self._agg([m1, m2])
        # Only m1 has translated_f1 -- macro = 0.8
        assert agg.macro_translated_f1 == pytest.approx(0.8)

    def test_empty_language_list(self):
        agg = self._agg([])
        assert agg.n_languages == 0
        assert agg.n_samples_total == 0
        assert agg.macro_baseline_f1 == 0.0

    def test_failure_rate_calculation(self):
        m = _make_lang_metrics(n_translation_success=40, n_translation_failure=10)
        trans = (
            [TranslationRecord(i, "hin_Deva", True, "t", 0.5, None) for i in range(40)] +
            [TranslationRecord(i, "hin_Deva", False, None, 0.0, "fail") for i in range(40, 50)]
        )
        agg = self._agg([m], trans)
        assert agg.translation_failure_rate == pytest.approx(10/50)

    def test_mean_latency_from_successful_only(self):
        m = _make_lang_metrics()
        trans = [
            TranslationRecord(1, "x", True, "t", latency_s=1.0, error=None),
            TranslationRecord(2, "x", True, "t", latency_s=3.0, error=None),
            TranslationRecord(3, "x", False, None, latency_s=0.0, error="fail"),
        ]
        agg = self._agg([m], trans)
        assert agg.mean_translation_latency_s == pytest.approx(2.0)


# ===========================================================================
# load_dataset
# ===========================================================================

class TestLoadDataset:
    def _write_csv(self, rows: list[dict], tmp_path: Path) -> Path:
        path = tmp_path / "indic_eval.csv"
        if not rows:
            path.write_text("id,language,language_name,text,label,source,notes\n")
            return path
        with open(path, "w", newline="", encoding="utf-8") as f:
            writer = csv.DictWriter(f, fieldnames=rows[0].keys())
            writer.writeheader()
            writer.writerows(rows)
        return path

    def _row(self, id_: int, lang: str = "hin_Deva", label: int = 1,
             text: str = "sample") -> dict:
        return {"id": id_, "language": lang, "language_name": "Hindi",
                "text": text, "label": label, "source": "synthetic", "notes": ""}

    def test_loads_all_rows(self, tmp_path):
        rows = [self._row(i) for i in range(5)]
        path = self._write_csv(rows, tmp_path)
        samples = load_dataset(path)
        assert len(samples) == 5

    def test_lang_filter(self, tmp_path):
        rows = [self._row(1, "hin_Deva"), self._row(2, "tel_Telu")]
        path = self._write_csv(rows, tmp_path)
        samples = load_dataset(path, lang_filter="hin_Deva")
        assert len(samples) == 1
        assert samples[0].language == "hin_Deva"

    def test_max_rows_limit(self, tmp_path):
        rows = [self._row(i) for i in range(20)]
        path = self._write_csv(rows, tmp_path)
        samples = load_dataset(path, max_rows=5)
        assert len(samples) == 5

    def test_empty_csv_returns_empty_list(self, tmp_path):
        path = self._write_csv([], tmp_path)
        samples = load_dataset(path)
        assert samples == []

    def test_missing_file_raises_file_not_found(self, tmp_path):
        with pytest.raises(FileNotFoundError, match="Dataset not found"):
            load_dataset(tmp_path / "nonexistent.csv")

    def test_label_parsed_as_int(self, tmp_path):
        rows = [self._row(1, label=0), self._row(2, label=1)]
        path = self._write_csv(rows, tmp_path)
        samples = load_dataset(path)
        assert samples[0].label == 0
        assert samples[1].label == 1
        assert isinstance(samples[0].label, int)

    def test_unicode_text_preserved(self, tmp_path):
        text = "आपका खाता निलंबित है"
        rows = [self._row(1, text=text)]
        path = self._write_csv(rows, tmp_path)
        samples = load_dataset(path)
        assert samples[0].text == text


# ===========================================================================
# evaluate_language
# ===========================================================================

class TestEvaluateLanguage:
    """
    All tests use dry_run=True so no NLLB model is loaded.
    The V2 classifier is patched to return controlled probabilities.
    """

    def test_dry_run_returns_correct_record_counts(self):
        samples = [_make_sample(i) for i in range(5)]
        with patch("scripts.evaluate_indic_nllb._classify_text", return_value=80.0):
            preds, trans = evaluate_language(samples, dry_run=True)
        assert len(preds) == 5
        assert len(trans) == 5

    def test_translation_failure_gives_none_translated_pred(self):
        """When a translation fails, translated_pred must be None (not a guess)."""
        samples = [_make_sample(1)]
        # Force translation to always fail in dry_run by patching random
        import random
        with patch("scripts.evaluate_indic_nllb._classify_text", return_value=30.0), \
             patch("random.random", return_value=0.0):  # always < 0.1 -> always fail
            preds, trans = evaluate_language(samples, dry_run=True)
        assert trans[0].success is False
        assert preds[0].translated_pred is None
        assert preds[0].translated_phishing_prob is None

    def test_successful_translation_gives_translated_pred(self):
        """Successful translation must produce a non-None translated_pred."""
        samples = [_make_sample(1)]
        with patch("scripts.evaluate_indic_nllb._classify_text", return_value=80.0), \
             patch("random.random", return_value=0.5):  # 0.5 > 0.1 -> success
            preds, trans = evaluate_language(samples, dry_run=True)
        assert trans[0].success is True
        assert preds[0].translated_pred is not None
        assert preds[0].translated_phishing_prob is not None

    def test_baseline_prediction_always_present(self):
        """Path A (baseline) must run for every sample, even if translation fails."""
        samples = [_make_sample(i) for i in range(3)]
        with patch("scripts.evaluate_indic_nllb._classify_text", return_value=20.0), \
             patch("random.random", return_value=0.0):  # all translations fail
            preds, _ = evaluate_language(samples, dry_run=True)
        assert all(p.baseline_pred == 0 for p in preds)  # 20.0 < threshold -> legit

    def test_classify_failure_does_not_propagate(self):
        """_classify_text() catches all exceptions; evaluate_language must not raise."""
        samples = [_make_sample(1)]
        with patch("scripts.evaluate_indic_nllb._classify_text",
                   side_effect=RuntimeError("classifier crashed")):
            # Should not raise
            try:
                preds, trans = evaluate_language(samples, dry_run=True)
            except RuntimeError:
                pytest.fail("evaluate_language must not propagate classify_email exceptions")

    def test_latency_recorded_for_each_sample(self):
        samples = [_make_sample(i) for i in range(4)]
        with patch("scripts.evaluate_indic_nllb._classify_text", return_value=50.0):
            _, trans = evaluate_language(samples, dry_run=True)
        assert all(isinstance(t.latency_s, float) for t in trans)


# ===========================================================================
# Language grouping (integration-style, no model needed)
# ===========================================================================

class TestLanguageGrouping:
    def test_samples_grouped_by_language(self):
        """evaluate_language receives only same-language samples in a real run."""
        all_samples = [
            _make_sample(1, lang="hin_Deva"),
            _make_sample(2, lang="tel_Telu"),
            _make_sample(3, lang="hin_Deva"),
        ]
        groups: dict[str, list] = {}
        for s in all_samples:
            groups.setdefault(s.language, []).append(s)
        assert len(groups["hin_Deva"]) == 2
        assert len(groups["tel_Telu"]) == 1

    def test_aggregate_sums_across_all_languages(self):
        m1 = _make_lang_metrics("hin_Deva", n_samples=50)
        m2 = _make_lang_metrics("tel_Telu", n_samples=48)
        agg = compute_aggregate_metrics([m1, m2], [])
        assert agg.n_samples_total == 98

    def test_missing_language_not_in_aggregate(self):
        """Only languages present in lang_metrics appear in aggregate."""
        m = _make_lang_metrics("hin_Deva")
        agg = compute_aggregate_metrics([m], [])
        assert agg.n_languages == 1
