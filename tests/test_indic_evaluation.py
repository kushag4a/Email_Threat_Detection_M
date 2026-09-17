"""
Model-free tests for the Indic NLLB evaluation harness.

Nothing here downloads NLLB, loads the V2 pickles, or touches the network.
The classifier and translator are plain injected callables, so the harness
logic is tested in isolation from both models.

Written with unittest.TestCase so the suite runs under pytest
(`pytest tests/test_indic_evaluation.py`) and under the stdlib runner
(`python -m unittest tests.test_indic_evaluation -v`) alike.

Coverage
--------
* metric maths: perfect, all-negative, all-positive, empty, undefined cells
* failure handling: failed translation, failed baseline call, failed
  translated-text call -- none may be scored as "legitimate"
* grouping by language
* micro (pooled) aggregation
* macro (per-language mean) aggregation
* A/B paired outcome counts and McNemar validity
* delta calculation over the paired subset
* deterministic ordering of samples, results and serialised output
* dataset loading, including malformed-row reporting
"""
from __future__ import annotations

import csv
import json
import sys
import tempfile
import unittest
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))

from scripts.evaluate_indic_nllb import (  # noqa: E402
    Aggregate,
    ClassifyOutcome,
    DatasetIssue,
    LanguageMetrics,
    OpStatus,
    PairedCounts,
    Sample,
    SampleResult,
    TransStatus,
    TranslateOutcome,
    build_report,
    compute_aggregate,
    compute_language_metrics,
    compute_metrics,
    compute_paired_counts,
    evaluate_samples,
    language_metrics_row,
    latency_stats,
    load_dataset,
    make_dry_run_classifier,
    make_dry_run_translator,
    mcnemar_test,
    pred_from_prob,
    report_to_dict,
    safe_classify,
    safe_translate,
    save_per_sample_csv,
    save_summary_csv,
    summarise_disagreements,
)

PHISH = 90.0
LEGIT = 10.0


# ===========================================================================
# Fixtures / fakes
# ===========================================================================

def make_sample(id_: int, label: int = 1, language: str = "hin_Deva",
                text: str | None = None) -> Sample:
    return Sample(
        id=id_,
        language=language,
        language_name="Hindi" if language == "hin_Deva" else language,
        text=text if text is not None else f"sample-{id_}",
        label=label,
        source="synthetic",
    )


def ok_classifier(mapping: dict[str, float] | None = None,
                  default: float = LEGIT):
    """Classifier returning a score looked up by exact text, else *default*."""
    mapping = mapping or {}

    def _classify(text: str) -> ClassifyOutcome:
        return ClassifyOutcome(
            status=OpStatus.OK,
            phishing_probability=mapping.get(text, default),
            latency_s=0.01,
        )

    return _classify


def failing_classifier(fail_on=lambda text: True, otherwise: float = LEGIT):
    """Classifier that fails for texts matching *fail_on*."""

    def _classify(text: str) -> ClassifyOutcome:
        if fail_on(text):
            return ClassifyOutcome(
                status=OpStatus.FAILED,
                phishing_probability=None,
                latency_s=0.002,
                error="RuntimeError: classifier exploded",
            )
        return ClassifyOutcome(OpStatus.OK, otherwise, 0.01)

    return _classify


def ok_translator(prefix: str = "EN:"):
    def _translate(text: str, src_lang: str) -> TranslateOutcome:
        return TranslateOutcome(
            status=TransStatus.TRANSLATED,
            translated_text=f"{prefix}{text}",
            latency_s=0.2,
        )

    return _translate


def failing_translator(fail_ids: set[str] | None = None):
    """Translator that fails for texts in *fail_ids* (or all of them)."""

    def _translate(text: str, src_lang: str) -> TranslateOutcome:
        if fail_ids is None or text in fail_ids:
            return TranslateOutcome(
                status=TransStatus.TRANSLATION_FAILED,
                translated_text=None,
                latency_s=None,
                error="CUDA out of memory",
            )
        return TranslateOutcome(TransStatus.TRANSLATED, f"EN:{text}", 0.2)

    return _translate


def raising_classifier(raise_on=lambda text: True, otherwise: float = LEGIT,
                       exc: BaseException | None = None):
    """Classifier that RAISES (rather than returning FAILED) for some texts."""

    def _classify(text: str) -> ClassifyOutcome:
        if raise_on(text):
            raise exc or RuntimeError(f"classifier blew up on {text!r}")
        return ClassifyOutcome(OpStatus.OK, otherwise, 0.01)

    return _classify


def raising_translator(raise_on=lambda text: True,
                       exc: BaseException | None = None):
    """Translator that RAISES for some texts."""

    def _translate(text: str, src_lang: str) -> TranslateOutcome:
        if raise_on(text):
            raise exc or RuntimeError(f"translator blew up on {text!r}")
        return TranslateOutcome(TransStatus.TRANSLATED, f"EN:{text}", 0.2)

    return _translate


def make_result(id_: int, label: int, baseline_pred: int | None,
                path_b_pred: int | None, language: str = "hin_Deva",
                translation_ok: bool = True) -> SampleResult:
    """Hand-built SampleResult for metric-level tests."""
    trans_status = (TransStatus.TRANSLATED.value if translation_ok
                    else TransStatus.TRANSLATION_FAILED.value)
    if path_b_pred is not None:
        t_status = OpStatus.OK.value
    elif translation_ok:
        t_status = OpStatus.FAILED.value
    else:
        t_status = OpStatus.SKIPPED.value
    return SampleResult(
        id=id_,
        language=language,
        language_name="Hindi" if language == "hin_Deva" else language,
        label=label,
        baseline_status=(OpStatus.OK.value if baseline_pred is not None
                         else OpStatus.FAILED.value),
        baseline_phishing_prob=None if baseline_pred is None else (
            PHISH if baseline_pred == 1 else LEGIT),
        baseline_pred=baseline_pred,
        baseline_latency_s=0.01 if baseline_pred is not None else None,
        baseline_error=None if baseline_pred is not None else "boom",
        translation_status=trans_status,
        translated_text="EN:text" if translation_ok else None,
        translation_latency_s=0.2 if translation_ok else None,
        translation_error=None if translation_ok else "translate boom",
        translated_status=t_status,
        translated_phishing_prob=None if path_b_pred is None else (
            PHISH if path_b_pred == 1 else LEGIT),
        translated_pred=path_b_pred,
        translated_classifier_latency_s=0.02 if path_b_pred is not None else None,
        translated_error=None,
        path_b_total_latency_s=0.22 if path_b_pred is not None else None,
        baseline_correct=None if baseline_pred is None else baseline_pred == label,
        path_b_correct=None if path_b_pred is None else path_b_pred == label,
        paired_evaluable=baseline_pred is not None and path_b_pred is not None,
    )


# ===========================================================================
# compute_metrics
# ===========================================================================

class TestComputeMetrics(unittest.TestCase):

    def test_perfect_metrics(self):
        m = compute_metrics([1, 1, 0, 0], [1, 1, 0, 0])
        self.assertEqual(m.n, 4)
        self.assertEqual(m.accuracy, 1.0)
        self.assertEqual(m.precision, 1.0)
        self.assertEqual(m.recall, 1.0)
        self.assertEqual(m.f1, 1.0)
        self.assertEqual((m.tp, m.tn, m.fp, m.fn), (2, 2, 0, 0))

    def test_all_negative_edge_case(self):
        """No positives at all: precision/recall/F1 are undefined, not zero."""
        m = compute_metrics([0, 0, 0], [0, 0, 0])
        self.assertEqual(m.accuracy, 1.0)
        self.assertIsNone(m.precision)
        self.assertIsNone(m.recall)
        self.assertIsNone(m.f1)
        self.assertEqual(m.n_actual_positive, 0)

    def test_all_positive_edge_case(self):
        m = compute_metrics([1, 1, 1], [1, 1, 1])
        self.assertEqual(m.accuracy, 1.0)
        self.assertEqual(m.precision, 1.0)
        self.assertEqual(m.recall, 1.0)
        self.assertEqual(m.f1, 1.0)
        self.assertEqual(m.n_actual_negative, 0)

    def test_empty_input(self):
        m = compute_metrics([], [])
        self.assertEqual(m.n, 0)
        self.assertIsNone(m.accuracy)
        self.assertIsNone(m.precision)
        self.assertIsNone(m.recall)
        self.assertIsNone(m.f1)

    def test_all_wrong(self):
        m = compute_metrics([1, 1, 0, 0], [0, 0, 1, 1])
        self.assertEqual(m.accuracy, 0.0)
        self.assertEqual(m.precision, 0.0)
        self.assertEqual(m.recall, 0.0)
        self.assertIsNone(m.f1, "F1 is undefined when precision and recall are both 0")

    def test_known_confusion_values(self):
        # TP=2, FP=1, FN=1, TN=2
        m = compute_metrics([1, 1, 0, 0, 1, 0], [1, 1, 1, 0, 0, 0])
        self.assertEqual((m.tp, m.fp, m.fn, m.tn), (2, 1, 1, 2))
        self.assertAlmostEqual(m.accuracy, 4 / 6, places=5)
        self.assertAlmostEqual(m.precision, 2 / 3, places=5)
        self.assertAlmostEqual(m.recall, 2 / 3, places=5)
        self.assertAlmostEqual(m.f1, 2 / 3, places=5)

    def test_nothing_predicted_positive_leaves_precision_undefined(self):
        m = compute_metrics([1, 0, 1, 0], [0, 0, 0, 0])
        self.assertEqual(m.accuracy, 0.5)
        self.assertIsNone(m.precision)
        self.assertEqual(m.recall, 0.0)
        self.assertIsNone(m.f1)

    def test_length_mismatch_raises(self):
        with self.assertRaises(ValueError):
            compute_metrics([1, 0], [1])


class TestPredFromProb(unittest.TestCase):

    def test_threshold_is_inclusive(self):
        self.assertEqual(pred_from_prob(50.0), 1)
        self.assertEqual(pred_from_prob(49.999), 0)

    def test_none_stays_none(self):
        """A missing score must never become a 'legitimate' prediction."""
        self.assertIsNone(pred_from_prob(None))

    def test_custom_threshold(self):
        self.assertEqual(pred_from_prob(30.0, threshold=25.0), 1)
        self.assertEqual(pred_from_prob(30.0, threshold=35.0), 0)


# ===========================================================================
# evaluate_samples: failure handling
# ===========================================================================

class TestEvaluateSamples(unittest.TestCase):

    def test_happy_path_records_both_predictions(self):
        samples = [make_sample(1, label=1), make_sample(2, label=0)]
        results = evaluate_samples(
            samples,
            classifier=ok_classifier({"sample-1": PHISH, "EN:sample-1": PHISH,
                                      "sample-2": LEGIT, "EN:sample-2": LEGIT}),
            translator=ok_translator(),
        )
        self.assertEqual([r.baseline_pred for r in results], [1, 0])
        self.assertEqual([r.translated_pred for r in results], [1, 0])
        self.assertTrue(all(r.paired_evaluable for r in results))
        self.assertTrue(all(r.baseline_correct and r.path_b_correct for r in results))

    def test_one_failed_translation(self):
        samples = [make_sample(1, label=1), make_sample(2, label=1)]
        results = evaluate_samples(
            samples,
            classifier=ok_classifier(default=PHISH),
            translator=failing_translator({"sample-1"}),
        )
        failed, ok = results[0], results[1]

        self.assertEqual(failed.translation_status,
                         TransStatus.TRANSLATION_FAILED.value)
        self.assertIsNone(failed.translated_pred)
        self.assertIsNone(failed.path_b_correct,
                          "a failed translation must not produce a verdict")
        self.assertEqual(failed.translated_status, OpStatus.SKIPPED.value)
        self.assertFalse(failed.paired_evaluable)
        self.assertIsNone(failed.path_b_total_latency_s)
        # Path A still ran for the failed-translation sample.
        self.assertEqual(failed.baseline_pred, 1)
        self.assertTrue(ok.paired_evaluable)

    def test_failed_translation_is_not_scored_as_legitimate(self):
        """The regression this harness exists to prevent."""
        samples = [make_sample(1, label=1)]
        results = evaluate_samples(
            samples,
            classifier=ok_classifier(default=PHISH),
            translator=failing_translator(),
        )
        m = compute_language_metrics("hin_Deva", results)
        self.assertEqual(m.path_b_evaluated_n, 0)
        self.assertEqual(m.translation_failures, 1)
        self.assertEqual(m.path_b.tn, 0, "must not be counted as a true negative")
        self.assertEqual(m.path_b.fn, 0, "must not be counted as a false negative")
        self.assertIsNone(m.path_b.accuracy)

    def test_one_failed_baseline_classification(self):
        samples = [make_sample(1, label=1)]
        results = evaluate_samples(
            samples,
            # fail on the raw text only; the translated text still classifies
            classifier=failing_classifier(fail_on=lambda t: not t.startswith("EN:"),
                                          otherwise=PHISH),
            translator=ok_translator(),
        )
        r = results[0]
        self.assertEqual(r.baseline_status, OpStatus.FAILED.value)
        self.assertIsNone(r.baseline_pred)
        self.assertIsNone(r.baseline_correct)
        self.assertIsNotNone(r.baseline_error)
        self.assertEqual(r.translated_pred, 1, "Path B is unaffected by a Path A failure")
        self.assertFalse(r.paired_evaluable)

        m = compute_language_metrics("hin_Deva", results)
        self.assertEqual(m.baseline_failures, 1)
        self.assertEqual(m.baseline_evaluated_n, 0)
        self.assertEqual(m.path_b_evaluated_n, 1)
        self.assertEqual(m.paired_n, 0)

    def test_one_failed_translated_classification(self):
        samples = [make_sample(1, label=1)]
        results = evaluate_samples(
            samples,
            # translation succeeds, but classifying the English text fails
            classifier=failing_classifier(fail_on=lambda t: t.startswith("EN:"),
                                          otherwise=PHISH),
            translator=ok_translator(),
        )
        r = results[0]
        self.assertEqual(r.translation_status, TransStatus.TRANSLATED.value)
        self.assertEqual(r.translated_status, OpStatus.FAILED.value)
        self.assertIsNone(r.translated_pred)
        self.assertIsNone(r.path_b_total_latency_s)
        self.assertEqual(r.baseline_pred, 1)

        m = compute_language_metrics("hin_Deva", results)
        self.assertEqual(m.translation_failures, 0)
        self.assertEqual(m.translated_classifier_failures, 1)
        self.assertEqual(m.path_b_evaluated_n, 0)
        self.assertEqual(m.translation_success_rate, 1.0)

    def test_evaluation_continues_past_a_failure(self):
        samples = [make_sample(i, label=1) for i in range(1, 6)]
        results = evaluate_samples(
            samples,
            classifier=ok_classifier(default=PHISH),
            translator=failing_translator({"sample-3"}),
        )
        self.assertEqual(len(results), 5)
        self.assertEqual(sum(1 for r in results if r.translated_pred is None), 1)

    def test_progress_callback_invoked_per_sample(self):
        seen: list[int] = []
        samples = [make_sample(i) for i in range(1, 4)]
        evaluate_samples(samples, ok_classifier(), ok_translator(),
                         progress=lambda i, total, s: seen.append(i))
        self.assertEqual(seen, [1, 2, 3])


# ===========================================================================
# Injected-callable boundary: nothing may terminate the benchmark
# ===========================================================================

class TestRaisingCallablesAreContained(unittest.TestCase):
    """
    The built-in adapters catch their own exceptions, but evaluate_samples()
    accepts arbitrary injected callables. A raising callable must become an
    explicit FAILED status on one sample, never an aborted run and never a
    prediction of 0.
    """

    def _samples(self, n: int = 5, label: int = 1) -> list[Sample]:
        return [make_sample(i, label=label) for i in range(1, n + 1)]

    # -- 1. baseline classifier raises ------------------------------------

    def test_raising_baseline_classifier_continues(self):
        samples = self._samples()
        results = evaluate_samples(
            samples,
            # raise on raw text, succeed on translated text
            classifier=raising_classifier(raise_on=lambda t: not t.startswith("EN:"),
                                          otherwise=PHISH),
            translator=ok_translator(),
        )
        self.assertEqual(len(results), 5, "every sample must still be reported")
        for r in results:
            self.assertEqual(r.baseline_status, OpStatus.FAILED.value)
            self.assertIsNone(r.baseline_pred)
            self.assertIsNone(r.baseline_correct)
            self.assertIn("RuntimeError", r.baseline_error)
            self.assertEqual(r.translated_pred, 1, "Path B is unaffected")

    # -- 2. translator raises ---------------------------------------------

    def test_raising_translator_continues(self):
        samples = self._samples()
        results = evaluate_samples(
            samples,
            classifier=ok_classifier(default=PHISH),
            translator=raising_translator(),
        )
        self.assertEqual(len(results), 5)
        for r in results:
            self.assertEqual(r.translation_status,
                             TransStatus.TRANSLATION_FAILED.value)
            self.assertIsNone(r.translated_text)
            self.assertIn("RuntimeError", r.translation_error)
            self.assertEqual(r.translated_status, OpStatus.SKIPPED.value)
            self.assertIsNone(r.translated_pred)
            self.assertIsNone(r.path_b_correct)
            self.assertEqual(r.baseline_pred, 1, "Path A is unaffected")

    # -- 3. translated-text classifier raises ------------------------------

    def test_raising_translated_classifier_continues(self):
        samples = self._samples()
        results = evaluate_samples(
            samples,
            # succeed on raw text, raise on the English text
            classifier=raising_classifier(raise_on=lambda t: t.startswith("EN:"),
                                          otherwise=PHISH),
            translator=ok_translator(),
        )
        self.assertEqual(len(results), 5)
        for r in results:
            self.assertEqual(r.translation_status, TransStatus.TRANSLATED.value)
            self.assertEqual(r.translated_status, OpStatus.FAILED.value)
            self.assertIsNone(r.translated_pred)
            self.assertIsNone(r.path_b_correct)
            self.assertIn("RuntimeError", r.translated_error)
            self.assertIsNone(r.path_b_total_latency_s)
            self.assertEqual(r.baseline_pred, 1)

    # -- 4. all three excluded from the denominators -----------------------

    def test_all_three_raise_types_excluded_from_denominators(self):
        """
        One sample per failure mode, plus one clean sample. Only the clean
        sample may appear in any metric denominator.
        """
        samples = [
            make_sample(1, label=1, text="clean"),
            make_sample(2, label=1, text="base-boom"),
            make_sample(3, label=1, text="trans-boom"),
            make_sample(4, label=1, text="tcls-boom"),
        ]

        def classifier(text: str) -> ClassifyOutcome:
            if text == "base-boom":
                raise RuntimeError("path A classifier raised")
            if text == "EN:tcls-boom":
                raise ValueError("path B classifier raised")
            return ClassifyOutcome(OpStatus.OK, PHISH, 0.01)

        def translator(text: str, src_lang: str) -> TranslateOutcome:
            if text == "trans-boom":
                raise OSError("translator raised")
            return TranslateOutcome(TransStatus.TRANSLATED, f"EN:{text}", 0.2)

        results = evaluate_samples(samples, classifier, translator)
        self.assertEqual(len(results), 4)

        m = compute_language_metrics("hin_Deva", results)
        self.assertEqual(m.n, 4)
        # Path A saw everything except the sample whose baseline call raised.
        self.assertEqual(m.baseline_evaluated_n, 3)
        self.assertEqual(m.baseline_failures, 1)
        self.assertEqual(m.baseline.n, 3)
        # Path B lost one to translation and one to the translated classifier.
        self.assertEqual(m.path_b_evaluated_n, 2)
        self.assertEqual(m.translation_failures, 1)
        self.assertEqual(m.translated_classifier_failures, 1)
        self.assertEqual(m.path_b.n, 2)
        # Only the clean sample is usable by both paths.
        self.assertEqual(m.paired_n, 1)
        self.assertEqual(m.paired_counts.n_paired, 1)
        # Latency never counts a failed operation.
        self.assertEqual(m.baseline_latency.count, 3)
        self.assertEqual(m.translation_latency.count, 3)
        self.assertEqual(m.translated_classifier_latency.count, 2)
        self.assertEqual(m.path_b_total_latency.count, 2)

    # -- 5. no failure becomes prediction 0 --------------------------------

    def test_no_raised_failure_becomes_prediction_zero(self):
        """
        Every sample is phishing (label 1). If a failure were silently scored
        as 0, it would land in the false-negative cell. No cell may move.
        """
        samples = self._samples(n=6, label=1)

        def classifier(text: str) -> ClassifyOutcome:
            raise RuntimeError("everything is on fire")

        def translator(text: str, src_lang: str) -> TranslateOutcome:
            raise RuntimeError("also on fire")

        results = evaluate_samples(samples, classifier, translator)
        self.assertEqual(len(results), 6)

        self.assertTrue(all(r.baseline_pred is None for r in results))
        self.assertTrue(all(r.translated_pred is None for r in results))
        self.assertNotIn(0, [r.baseline_pred for r in results])
        self.assertNotIn(0, [r.translated_pred for r in results])

        m = compute_language_metrics("hin_Deva", results)
        for cell in (m.baseline.tp, m.baseline.tn, m.baseline.fp, m.baseline.fn,
                     m.path_b.tp, m.path_b.tn, m.path_b.fp, m.path_b.fn):
            self.assertEqual(cell, 0, "a failure must not populate any confusion cell")
        self.assertEqual(m.baseline.n, 0)
        self.assertEqual(m.path_b.n, 0)
        self.assertIsNone(m.baseline.accuracy, "undefined, not 0.0")
        self.assertIsNone(m.path_b.accuracy)
        self.assertIsNone(m.delta_accuracy)
        self.assertEqual(m.translation_success_rate, 0.0)

        agg = compute_aggregate([m], results)
        self.assertEqual(agg.micro_baseline.n, 0)
        self.assertEqual(agg.micro_path_b.n, 0)
        self.assertFalse(agg.mcnemar.valid)

    # -- boundary hardening extras ----------------------------------------

    def test_intermittent_failures_do_not_stop_the_run(self):
        """A failure in the middle must not truncate the remaining samples."""
        samples = [make_sample(i, label=1) for i in range(1, 11)]

        def classifier(text: str) -> ClassifyOutcome:
            if text == "sample-5":
                raise RuntimeError("transient")
            return ClassifyOutcome(OpStatus.OK, PHISH, 0.01)

        def translator(text: str, src_lang: str) -> TranslateOutcome:
            if text == "sample-7":
                raise RuntimeError("transient")
            return TranslateOutcome(TransStatus.TRANSLATED, f"EN:{text}", 0.2)

        results = evaluate_samples(samples, classifier, translator)
        self.assertEqual([r.id for r in results], list(range(1, 11)))
        self.assertEqual(sum(1 for r in results if r.baseline_pred is None), 1)
        self.assertEqual(sum(1 for r in results if r.translated_pred is None), 1)
        self.assertEqual(sum(1 for r in results if r.paired_evaluable), 8)

    def test_non_baseexception_from_callable_is_contained(self):
        """Even a KeyboardInterrupt-style BaseException must not abort a run."""
        samples = self._samples(n=2)
        results = evaluate_samples(
            samples,
            classifier=raising_classifier(exc=SystemExit("hard exit")),
            translator=ok_translator(),
        )
        self.assertEqual(len(results), 2)
        self.assertTrue(all(r.baseline_status == OpStatus.FAILED.value
                            for r in results))
        self.assertIn("SystemExit", results[0].baseline_error)

    def test_callable_returning_wrong_type_is_contained(self):
        samples = self._samples(n=2)
        results = evaluate_samples(
            samples,
            classifier=lambda text: None,          # type: ignore[arg-type,return-value]
            translator=lambda text, lang: "nope",  # type: ignore[arg-type,return-value]
        )
        self.assertEqual(len(results), 2)
        for r in results:
            self.assertEqual(r.baseline_status, OpStatus.FAILED.value)
            self.assertIn("expected ClassifyOutcome", r.baseline_error)
            self.assertEqual(r.translation_status,
                             TransStatus.TRANSLATION_FAILED.value)
            self.assertIn("expected TranslateOutcome", r.translation_error)

    def test_keyboard_interrupt_is_not_contained(self):
        """Ctrl-C during a long GPU run must still stop it."""
        samples = self._samples(n=3)
        with self.assertRaises(KeyboardInterrupt):
            evaluate_samples(
                samples,
                classifier=raising_classifier(exc=KeyboardInterrupt()),
                translator=ok_translator(),
            )

    def test_raising_progress_callback_does_not_stop_the_run(self):
        samples = self._samples(n=3)

        def bad_progress(index, total, sample):
            raise RuntimeError("broken reporter")

        results = evaluate_samples(samples, ok_classifier(), ok_translator(),
                                   progress=bad_progress)
        self.assertEqual(len(results), 3)

    def test_safe_wrappers_pass_through_normal_outcomes(self):
        """The wrappers must not alter a well-behaved callable's result."""
        outcome = safe_classify(ok_classifier(default=PHISH), "x")
        self.assertEqual(outcome.status, OpStatus.OK)
        self.assertEqual(outcome.phishing_probability, PHISH)
        self.assertIsNone(outcome.error)

        t = safe_translate(ok_translator(), "x", "hin_Deva")
        self.assertEqual(t.status, TransStatus.TRANSLATED)
        self.assertEqual(t.translated_text, "EN:x")
        self.assertTrue(t.ok)

    def test_safe_wrappers_record_latency_on_failure(self):
        """A failed call still has a measured duration, not None."""
        outcome = safe_classify(raising_classifier(), "x")
        self.assertEqual(outcome.status, OpStatus.FAILED)
        self.assertIsNotNone(outcome.latency_s)
        self.assertGreaterEqual(outcome.latency_s, 0.0)
        self.assertIsNone(outcome.phishing_probability)


# ===========================================================================
# Latency
# ===========================================================================

class TestLatency(unittest.TestCase):

    def test_stats_ignore_none_entries(self):
        s = latency_stats([1.0, 3.0, None, 2.0])
        self.assertEqual(s.count, 3)
        self.assertAlmostEqual(s.mean_s, 2.0)
        self.assertAlmostEqual(s.median_s, 2.0)

    def test_empty_is_undefined_not_zero(self):
        s = latency_stats([None, None])
        self.assertEqual(s.count, 0)
        self.assertIsNone(s.mean_s)
        self.assertIsNone(s.p95_s)

    def test_p95_interpolates(self):
        s = latency_stats([float(i) for i in range(1, 101)])
        self.assertEqual(s.count, 100)
        self.assertAlmostEqual(s.p95_s, 95.05, places=2)

    def test_failed_translation_excluded_from_latency(self):
        results = [
            make_result(1, 1, 1, 1),
            make_result(2, 1, 1, None, translation_ok=False),
        ]
        m = compute_language_metrics("hin_Deva", results)
        self.assertEqual(m.translation_latency.count, 1)
        self.assertEqual(m.path_b_total_latency.count, 1)
        self.assertEqual(m.baseline_latency.count, 2)


# ===========================================================================
# Grouping by language
# ===========================================================================

class TestLanguageGrouping(unittest.TestCase):

    def test_metrics_only_use_rows_of_that_language(self):
        results = [
            make_result(1, 1, 1, 1, language="hin_Deva"),
            make_result(2, 0, 0, 0, language="hin_Deva"),
            make_result(3, 1, 0, 0, language="tel_Telu"),
        ]
        hin = compute_language_metrics("hin_Deva", results)
        tel = compute_language_metrics("tel_Telu", results)
        self.assertEqual(hin.n, 2)
        self.assertEqual(tel.n, 1)
        self.assertEqual(hin.baseline.accuracy, 1.0)
        self.assertEqual(tel.baseline.accuracy, 0.0)

    def test_class_counts_per_language(self):
        results = [
            make_result(1, 1, 1, 1),
            make_result(2, 0, 0, 0),
            make_result(3, 0, 0, 0),
        ]
        m = compute_language_metrics("hin_Deva", results)
        self.assertEqual((m.n_legitimate, m.n_phishing), (2, 1))

    def test_unknown_language_yields_empty_block(self):
        m = compute_language_metrics("ben_Beng", [make_result(1, 1, 1, 1)])
        self.assertEqual(m.n, 0)
        self.assertIsNone(m.baseline.accuracy)
        self.assertEqual(m.language_name, "Bengali")


# ===========================================================================
# Aggregation: micro and macro
# ===========================================================================

class TestAggregation(unittest.TestCase):

    def _agg(self, results: list[SampleResult]) -> Aggregate:
        languages = sorted({r.language for r in results})
        per_lang = [compute_language_metrics(l, results) for l in languages]
        return compute_aggregate(per_lang, results)

    def test_micro_pools_every_valid_prediction(self):
        # hin: 4 samples, all baseline-correct. tel: 1 sample, baseline-wrong.
        results = (
            [make_result(i, 1, 1, 1, language="hin_Deva") for i in range(1, 5)]
            + [make_result(9, 1, 0, 0, language="tel_Telu")]
        )
        agg = self._agg(results)
        self.assertEqual(agg.micro_baseline.n, 5)
        self.assertAlmostEqual(agg.micro_baseline.accuracy, 4 / 5)

    def test_macro_weights_languages_equally(self):
        results = (
            [make_result(i, 1, 1, 1, language="hin_Deva") for i in range(1, 5)]
            + [make_result(9, 1, 0, 0, language="tel_Telu")]
        )
        agg = self._agg(results)
        # hin accuracy 1.0, tel accuracy 0.0 -> macro 0.5, micro 0.8
        self.assertAlmostEqual(agg.macro_baseline.accuracy, 0.5)
        self.assertEqual(agg.macro_baseline.languages_included, 2)
        self.assertNotAlmostEqual(agg.macro_baseline.accuracy,
                                  agg.micro_baseline.accuracy)

    def test_macro_records_how_many_languages_contributed(self):
        """A language with 100% translation failure has no Path B metric."""
        results = (
            [make_result(1, 1, 1, 1, language="hin_Deva")]
            + [make_result(2, 1, 1, None, language="tel_Telu", translation_ok=False)]
        )
        agg = self._agg(results)
        self.assertEqual(agg.macro_baseline.languages_included, 2)
        self.assertEqual(agg.macro_path_b.languages_included, 1)
        self.assertEqual(agg.translation_failures, 1)

    def test_failure_counts_roll_up(self):
        results = [
            make_result(1, 1, 1, 1),
            make_result(2, 1, None, 1),                       # baseline failure
            make_result(3, 1, 1, None, translation_ok=False),  # translation failure
            make_result(4, 1, 1, None, translation_ok=True),   # translated cls failure
        ]
        agg = self._agg(results)
        self.assertEqual(agg.baseline_failures, 1)
        self.assertEqual(agg.translation_failures, 1)
        self.assertEqual(agg.translated_classifier_failures, 1)
        self.assertEqual(agg.baseline_evaluated_n, 3)
        self.assertEqual(agg.path_b_evaluated_n, 2)

    def test_translation_success_rate(self):
        results = [make_result(i, 1, 1, 1) for i in range(1, 4)] + [
            make_result(4, 1, 1, None, translation_ok=False)
        ]
        agg = self._agg(results)
        self.assertAlmostEqual(agg.translation_success_rate, 0.75)

    def test_empty_aggregate_is_undefined_not_zero(self):
        agg = compute_aggregate([], [])
        self.assertEqual(agg.n_languages, 0)
        self.assertIsNone(agg.micro_baseline.accuracy)
        self.assertIsNone(agg.macro_baseline.f1)
        self.assertIsNone(agg.translation_success_rate)
        self.assertFalse(agg.mcnemar.valid)


# ===========================================================================
# Paired counts, deltas, McNemar
# ===========================================================================

class TestPairedAnalysis(unittest.TestCase):

    def test_paired_outcome_counts(self):
        results = [
            make_result(1, 1, 1, 1),      # both correct
            make_result(2, 1, 1, 0),      # A correct, B wrong
            make_result(3, 1, 0, 1),      # A wrong, B correct
            make_result(4, 1, 0, 0),      # both wrong
        ]
        c = compute_paired_counts(results)
        self.assertEqual(c.n_paired, 4)
        self.assertEqual(c.both_correct, 1)
        self.assertEqual(c.a_correct_b_wrong, 1)
        self.assertEqual(c.b_correct_a_wrong, 1)
        self.assertEqual(c.both_wrong, 1)

    def test_unpaired_samples_excluded_from_counts(self):
        results = [
            make_result(1, 1, 1, 1),
            make_result(2, 1, 1, None, translation_ok=False),
            make_result(3, 1, None, 1),
        ]
        c = compute_paired_counts(results)
        self.assertEqual(c.n_paired, 1)
        self.assertEqual(c.both_correct, 1)

    def test_delta_computed_on_paired_subset(self):
        # 4 paired samples: A gets 2/4, B gets 3/4 -> delta accuracy = +0.25
        results = [
            make_result(1, 1, 1, 1),
            make_result(2, 1, 1, 1),
            make_result(3, 1, 0, 1),
            make_result(4, 1, 0, 0),
        ]
        m = compute_language_metrics("hin_Deva", results)
        self.assertEqual(m.paired_n, 4)
        self.assertAlmostEqual(m.paired_baseline.accuracy, 0.5)
        self.assertAlmostEqual(m.paired_path_b.accuracy, 0.75)
        self.assertAlmostEqual(m.delta_accuracy, 0.25)

    def test_delta_is_none_when_one_side_undefined(self):
        results = [make_result(1, 1, 1, None, translation_ok=False)]
        m = compute_language_metrics("hin_Deva", results)
        self.assertEqual(m.paired_n, 0)
        self.assertIsNone(m.delta_accuracy)
        self.assertIsNone(m.delta_f1)

    def test_delta_ignores_samples_only_one_path_saw(self):
        """
        Path A also scored an extra sample that Path B never saw. The delta
        must not compare a 3-sample A against a 2-sample B.
        """
        results = [
            make_result(1, 1, 1, 1),
            make_result(2, 1, 1, 1),
            make_result(3, 1, 0, None, translation_ok=False),
        ]
        m = compute_language_metrics("hin_Deva", results)
        self.assertAlmostEqual(m.baseline.accuracy, 2 / 3, places=5)  # full Path A denominator
        self.assertAlmostEqual(m.paired_baseline.accuracy, 1.0)  # paired denominator
        self.assertAlmostEqual(m.delta_accuracy, 0.0)

    def test_mcnemar_not_valid_without_discordant_pairs(self):
        counts = PairedCounts(n_paired=10, both_correct=8, a_correct_b_wrong=0,
                              b_correct_a_wrong=0, both_wrong=2)
        r = mcnemar_test(counts)
        self.assertFalse(r.valid)
        self.assertIsNone(r.p_value)

    def test_mcnemar_not_valid_without_paired_samples(self):
        r = mcnemar_test(PairedCounts(0, 0, 0, 0, 0))
        self.assertFalse(r.valid)
        self.assertIsNone(r.p_value)

    def test_mcnemar_exact_for_few_discordant_pairs(self):
        counts = PairedCounts(n_paired=40, both_correct=30, a_correct_b_wrong=2,
                              b_correct_a_wrong=6, both_wrong=2)
        r = mcnemar_test(counts)
        self.assertTrue(r.valid)
        self.assertEqual(r.method, "exact_binomial")
        # two-sided exact binomial, b=2, c=6, n=8 -> p = 2 * 37/256
        self.assertAlmostEqual(r.p_value, 2 * (1 + 8 + 28) / 256, places=5)

    def test_mcnemar_symmetric_case_gives_p_one(self):
        counts = PairedCounts(n_paired=20, both_correct=10, a_correct_b_wrong=5,
                              b_correct_a_wrong=5, both_wrong=0)
        r = mcnemar_test(counts)
        self.assertAlmostEqual(r.p_value, 1.0)

    def test_mcnemar_chi_square_for_many_discordant_pairs(self):
        counts = PairedCounts(n_paired=200, both_correct=100,
                              a_correct_b_wrong=10, b_correct_a_wrong=40,
                              both_wrong=50)
        r = mcnemar_test(counts)
        self.assertTrue(r.valid)
        self.assertEqual(r.method, "chi_square_continuity_corrected")
        self.assertAlmostEqual(r.statistic, (abs(10 - 40) - 1) ** 2 / 50, places=6)
        self.assertLess(r.p_value, 0.001)


# ===========================================================================
# Disagreement diagnostics
# ===========================================================================

class TestDisagreements(unittest.TestCase):

    def test_buckets_and_counts(self):
        results = [
            make_result(1, 1, 1, 0),   # A correct, B wrong
            make_result(2, 1, 0, 1),   # A wrong, B correct
            make_result(3, 1, 1, 1),   # both correct
        ]
        d = summarise_disagreements(results, {})
        self.assertEqual(d.n_a_correct_b_wrong, 1)
        self.assertEqual(d.n_b_correct_a_wrong, 1)
        self.assertEqual(d.per_language["hin_Deva"]["a_correct_b_wrong"], 1)
        self.assertEqual([e.id for e in d.examples_a_correct_b_wrong], [1])
        self.assertEqual([e.id for e in d.examples_b_correct_a_wrong], [2])

    def test_examples_carry_source_and_translated_text(self):
        results = [make_result(1, 1, 1, 0)]
        samples = {1: make_sample(1, text="मूल पाठ")}
        d = summarise_disagreements(results, samples)
        ex = d.examples_a_correct_b_wrong[0]
        self.assertEqual(ex.source_text_excerpt, "मूल पाठ")
        self.assertEqual(ex.translated_text_excerpt, "EN:text")

    def test_example_limit_is_respected(self):
        results = [make_result(i, 1, 1, 0) for i in range(1, 11)]
        d = summarise_disagreements(results, {}, limit=3)
        self.assertEqual(d.n_a_correct_b_wrong, 10)
        self.assertEqual(len(d.examples_a_correct_b_wrong), 3)

    def test_example_selection_is_deterministic(self):
        results = [make_result(i, 1, 1, 0) for i in range(10, 0, -1)]
        d = summarise_disagreements(results, {}, limit=3)
        self.assertEqual([e.id for e in d.examples_a_correct_b_wrong], [1, 2, 3])


# ===========================================================================
# Dataset loading
# ===========================================================================

class TestLoadDataset(unittest.TestCase):

    def setUp(self):
        self._tmp = tempfile.TemporaryDirectory()
        self.tmp = Path(self._tmp.name)

    def tearDown(self):
        self._tmp.cleanup()

    def _write(self, rows, fields=("id", "language", "text", "label", "source")):
        path = self.tmp / "indic_eval.csv"
        with open(path, "w", newline="", encoding="utf-8") as f:
            w = csv.DictWriter(f, fieldnames=list(fields))
            w.writeheader()
            for r in rows:
                w.writerow(r)
        return path

    def _row(self, id_, language="hin_Deva", text="सन्देश", label="1"):
        return {"id": id_, "language": language, "text": text,
                "label": label, "source": "synthetic"}

    def test_loads_valid_rows(self):
        path = self._write([self._row(i) for i in range(1, 4)])
        loaded = load_dataset(path)
        self.assertEqual(len(loaded.samples), 3)
        self.assertEqual(loaded.issues, [])
        self.assertEqual(loaded.rows_read, 3)
        self.assertEqual(len(loaded.sha256), 64)

    def test_missing_file_raises(self):
        with self.assertRaises(FileNotFoundError):
            load_dataset(self.tmp / "nope.csv")

    def test_missing_required_column_raises(self):
        path = self.tmp / "bad.csv"
        path.write_text("id,language,text\n1,hin_Deva,hi\n", encoding="utf-8")
        with self.assertRaises(ValueError):
            load_dataset(path)

    def test_malformed_rows_are_reported_not_silently_dropped(self):
        rows = [
            self._row(1),
            self._row("abc"),                      # bad id
            self._row(3, label="2"),               # bad label
            self._row(4, text="   "),              # empty text
            self._row(5, language="fra_Latn"),     # unsupported language
            self._row(1),                          # duplicate id
        ]
        loaded = self._write(rows)
        result = load_dataset(loaded)
        self.assertEqual(len(result.samples), 1)
        self.assertEqual(len(result.issues), 5)
        reasons = " | ".join(i.reason for i in result.issues)
        for fragment in ("not an integer", "label must be", "empty text",
                         "unknown language", "duplicate id"):
            self.assertIn(fragment, reasons)
        self.assertTrue(all(isinstance(i, DatasetIssue) for i in result.issues))

    def test_language_filter(self):
        path = self._write([self._row(1, "hin_Deva"), self._row(2, "tel_Telu")])
        loaded = load_dataset(path, languages=["tel_Telu"])
        self.assertEqual([s.language for s in loaded.samples], ["tel_Telu"])

    def test_max_per_language_cap(self):
        rows = ([self._row(i, "hin_Deva") for i in range(1, 6)]
                + [self._row(i, "tel_Telu") for i in range(6, 11)])
        loaded = load_dataset(self._write(rows), max_per_language=2)
        self.assertEqual(len(loaded.samples), 4)

    def test_max_rows_cap(self):
        loaded = load_dataset(self._write([self._row(i) for i in range(1, 11)]),
                              max_rows=3)
        self.assertEqual(len(loaded.samples), 3)

    def test_unicode_text_preserved(self):
        text = "आपका खाता निलंबित कर दिया गया है"
        loaded = load_dataset(self._write([self._row(1, text=text)]))
        self.assertEqual(loaded.samples[0].text, text)

    def test_deterministic_sample_ordering(self):
        """File order must not affect evaluation order."""
        rows = [self._row(7, "tel_Telu"), self._row(2, "hin_Deva"),
                self._row(5, "tel_Telu"), self._row(1, "hin_Deva")]
        loaded = load_dataset(self._write(rows))
        self.assertEqual([(s.language, s.id) for s in loaded.samples],
                         [("hin_Deva", 1), ("hin_Deva", 2),
                          ("tel_Telu", 5), ("tel_Telu", 7)])


# ===========================================================================
# Determinism and serialisation
# ===========================================================================

class TestDeterminismAndOutput(unittest.TestCase):

    def setUp(self):
        self._tmp = tempfile.TemporaryDirectory()
        self.tmp = Path(self._tmp.name)
        path = self.tmp / "indic_eval.csv"
        with open(path, "w", newline="", encoding="utf-8") as f:
            w = csv.DictWriter(f, fieldnames=["id", "language", "text", "label", "source"])
            w.writeheader()
            for i, lang in enumerate(["tel_Telu", "hin_Deva"] * 4, start=1):
                w.writerow({"id": i, "language": lang, "text": f"पाठ {i}",
                            "label": str(i % 2), "source": "synthetic"})
        self.dataset_path = path

    def tearDown(self):
        self._tmp.cleanup()

    def _run(self):
        loaded = load_dataset(self.dataset_path)
        results = evaluate_samples(
            loaded.samples,
            classifier=make_dry_run_classifier(),
            translator=make_dry_run_translator(),
        )
        return loaded, results

    def test_dry_run_stubs_are_deterministic(self):
        _, first = self._run()
        _, second = self._run()
        self.assertEqual([r.baseline_phishing_prob for r in first],
                         [r.baseline_phishing_prob for r in second])
        self.assertEqual([r.translation_status for r in first],
                         [r.translation_status for r in second])

    def test_result_ordering_matches_sample_ordering(self):
        loaded, results = self._run()
        self.assertEqual([(r.language, r.id) for r in results],
                         [(s.language, s.id) for s in loaded.samples])
        self.assertEqual(results, sorted(results, key=lambda r: (r.language, r.id)))

    def test_report_json_is_byte_identical_across_runs(self):
        loaded, results = self._run()
        report = build_report(loaded, results, 50.0, True, ["dry"], example_limit=5)
        # Timestamp/command are the only non-deterministic parts; drop them.
        def _stable(rep):
            d = report_to_dict(rep, include_per_sample=True)
            d["run_metadata"].pop("generated_at_utc")
            d["run_metadata"].pop("platform")
            return json.dumps(d, ensure_ascii=False, sort_keys=True)

        loaded2, results2 = self._run()
        report2 = build_report(loaded2, results2, 50.0, True, ["dry"], example_limit=5)
        self.assertEqual(_stable(report), _stable(report2))

    def test_per_language_blocks_are_sorted_by_code(self):
        loaded, results = self._run()
        report = build_report(loaded, results, 50.0, True, ["dry"])
        codes = [m.language for m in report.per_language]
        self.assertEqual(codes, sorted(codes))

    def test_summary_csv_has_language_micro_and_macro_rows(self):
        loaded, results = self._run()
        report = build_report(loaded, results, 50.0, True, ["dry"])
        out = save_summary_csv(self.tmp / "summary.csv", report)
        with open(out, encoding="utf-8") as f:
            rows = list(csv.DictReader(f))
        scopes = [r["scope"] for r in rows]
        self.assertEqual(scopes[-2:], ["MICRO_POOLED", "MACRO_AVERAGE"])
        self.assertEqual(scopes.count("language"), len(report.per_language))

    def test_per_sample_csv_contains_source_and_translated_text(self):
        loaded, results = self._run()
        report = build_report(loaded, results, 50.0, True, ["dry"])
        samples_by_id = {s.id: s for s in loaded.samples}
        out = save_per_sample_csv(self.tmp / "per_sample.csv", report, samples_by_id)
        with open(out, encoding="utf-8") as f:
            rows = list(csv.DictReader(f))
        self.assertEqual(len(rows), len(results))
        self.assertIn("translated_text", rows[0])
        self.assertTrue(all(r["source_text"] for r in rows))
        self.assertTrue(all(r["disagreement"] for r in rows))
        self.assertEqual([int(r["id"]) for r in rows],
                         [r.id for r in sorted(results, key=lambda x: (x.language, x.id))])

    def test_run_metadata_records_reproducibility_fields(self):
        loaded, results = self._run()
        report = build_report(loaded, results, 50.0, True, ["dry"])
        meta = report.run_metadata
        self.assertEqual(meta["dataset"]["sha256"], loaded.sha256)
        self.assertEqual(meta["classifier"]["phishing_threshold_0_100"], 50.0)
        self.assertIn("languages", meta)
        self.assertIn("generated_at_utc", meta)
        self.assertTrue(meta["nllb"]["dry_run"])
        self.assertIn("advisory", meta)

    def test_language_metrics_row_exposes_explicit_denominators(self):
        results = [make_result(1, 1, 1, 1), make_result(2, 0, 0, None,
                                                        translation_ok=False)]
        row = language_metrics_row(compute_language_metrics("hin_Deva", results))
        self.assertEqual(row["baseline_evaluated_n"], 2)
        self.assertEqual(row["path_b_evaluated_n"], 1)
        self.assertEqual(row["paired_n"], 1)
        self.assertEqual(row["translation_failures"], 1)


if __name__ == "__main__":
    unittest.main(verbosity=2)
