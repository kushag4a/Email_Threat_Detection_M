#!/usr/bin/env python3
"""
Lightweight validation for datasets/evaluation/indic/indic_eval.csv.
Not a benchmark evaluator -- just structural/content sanity checks.

Usage:
    python scripts/validate_indic_eval_dataset.py
"""
from __future__ import annotations

import csv
import sys
from collections import Counter
from pathlib import Path

_SCRIPT_DIR = Path(__file__).resolve().parent
_PROJECT_ROOT = _SCRIPT_DIR.parent
DATASET = _PROJECT_ROOT / "datasets" / "evaluation" / "indic" / "indic_eval.csv"

REQUIRED_COLUMNS = ["id", "language", "text", "label", "source"]
VALID_LANGUAGE_CODES = {
    "hin_Deva", "tel_Telu", "tam_Taml", "kan_Knda", "mal_Mlym",
    "mar_Deva", "ben_Beng", "guj_Gujr", "ory_Orya", "pan_Guru", "urd_Arab",
}


def main() -> int:
    errors: list[str] = []

    if not DATASET.exists():
        print(f"FAIL: dataset not found at {DATASET}")
        return 1

    with open(DATASET, newline="", encoding="utf-8") as f:
        reader = csv.DictReader(f)
        fieldnames = reader.fieldnames or []
        rows = list(reader)

    missing_cols = [c for c in REQUIRED_COLUMNS if c not in fieldnames]
    if missing_cols:
        errors.append(f"missing required columns: {missing_cols}")

    ids = [r["id"] for r in rows]
    dup_ids = [i for i, c in Counter(ids).items() if c > 1]
    if dup_ids:
        errors.append(f"duplicate ids: {dup_ids[:10]}")

    empty_text_ids = [r["id"] for r in rows if not r.get("text", "").strip()]
    if empty_text_ids:
        errors.append(f"empty text rows: {empty_text_ids[:10]}")

    bad_labels = sorted({r["label"] for r in rows} - {"0", "1"})
    if bad_labels:
        errors.append(f"invalid label values: {bad_labels}")

    langs_found = {r["language"] for r in rows}
    unexpected_langs = langs_found - VALID_LANGUAGE_CODES
    missing_langs = VALID_LANGUAGE_CODES - langs_found
    if unexpected_langs:
        errors.append(f"unexpected language codes: {sorted(unexpected_langs)}")
    if missing_langs:
        errors.append(f"missing required language codes: {sorted(missing_langs)}")

    non_synthetic = sorted({r["source"] for r in rows} - {"synthetic"})
    if non_synthetic:
        errors.append(f"non-synthetic source values found: {non_synthetic}")

    # Per-language / per-class counts (informational, always printed)
    per_lang = Counter(r["language"] for r in rows)
    per_lang_label = Counter((r["language"], r["label"]) for r in rows)

    print(f"Dataset: {DATASET}")
    print(f"Total rows: {len(rows)}")
    print(f"{'Language':<10} {'Total':>6} {'Legit(0)':>9} {'Phish(1)':>9}")
    for lang in sorted(VALID_LANGUAGE_CODES):
        total = per_lang.get(lang, 0)
        legit = per_lang_label.get((lang, "0"), 0)
        phish = per_lang_label.get((lang, "1"), 0)
        print(f"{lang:<10} {total:>6} {legit:>9} {phish:>9}")

    print()
    if errors:
        print("VALIDATION FAILED:")
        for e in errors:
            print(f"  - {e}")
        return 1

    print("VALIDATION PASSED: all checks OK.")
    return 0


if __name__ == "__main__":
    sys.exit(main())
