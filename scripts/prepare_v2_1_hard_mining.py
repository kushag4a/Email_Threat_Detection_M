#!/usr/bin/env python3
"""
Mine high-value hard examples for ValorProtects V2.1.

Reads:
  datasets/processed/train.parquet
  datasets/processed/validation.parquet

Loads:
  backend/app/models/v2/phishing_vectorizer.pkl
  backend/app/models/v2/phishing_model.pkl

Optionally compares V1:
  backend/app/models/v1_current/phishing_vectorizer.pkl
  backend/app/models/v1_current/phishing_model.pkl

Writes:
  datasets/v2_1/hard_positive/train_hard_positives.csv
  datasets/v2_1/hard_negative/train_hard_negatives.csv
  datasets/v2_1/hard_positive/validation_hard_positive_review.csv
  datasets/v2_1/hard_negative/validation_hard_negative_review.csv
  datasets/v2_1/review/uncertain_train.csv
  datasets/v2_1/review/uncertain_validation.csv
  datasets/v2_1/mining_summary.json

Important:
- Original train/validation/test files are NEVER modified.
- "Hard positive" means a known phishing row that V2 currently predicts too benign.
- "Hard negative" means a known benign row that V2 currently predicts too phishing.
- "Uncertain" means V2 probability is close to 0.5 and should be human-reviewed.
- Validation outputs are REVIEW candidates, not training data.
"""

from __future__ import annotations

import argparse
import json
import math
import pickle
from pathlib import Path
from typing import Iterable

import numpy as np
import pandas as pd


LABEL_POSITIVE = 1

DEFAULT_V2_DIR = Path("backend/app/models/v2")
DEFAULT_V1_DIR = Path("backend/app/models/v1_current")
TRAIN_PATH = Path("datasets/processed/train.parquet")
VALIDATION_PATH = Path("datasets/processed/validation.parquet")
OUT_ROOT = Path("datasets/v2_1")


def load_pickle(path: Path):
    """Load sklearn artifacts saved with joblib or pickle."""
    try:
        import joblib
        return joblib.load(path)
    except Exception as joblib_error:
        try:
            with path.open("rb") as f:
                return pickle.load(f)
        except Exception as pickle_error:
            raise RuntimeError(
                f"Could not load model artifact: {path}\n"
                f"joblib error: {joblib_error}\n"
                f"pickle error: {pickle_error}"
            ) from pickle_error


def probability_for_model(vectorizer, model, texts: list[str]) -> np.ndarray:
    x = vectorizer.transform(texts)

    if hasattr(model, "predict_proba"):
        probs = model.predict_proba(x)[:, 1]
    elif hasattr(model, "decision_function"):
        scores = model.decision_function(x)
        # Logistic mapping gives a useful ranking when predict_proba is unavailable.
        probs = 1.0 / (1.0 + np.exp(-np.clip(scores, -50, 50)))
    else:
        raise TypeError("Model has neither predict_proba nor decision_function().")

    return np.asarray(probs, dtype=np.float64)


def mine_file(
    path: Path,
    v2_vectorizer,
    v2_model,
    v1_vectorizer=None,
    v1_model=None,
    chunk_size: int = 5000,
) -> dict[str, pd.DataFrame]:
    df = pd.read_parquet(path)

    required = {"id", "text", "label", "source", "source_group", "language", "text_hash"}
    missing = required - set(df.columns)
    if missing:
        raise ValueError(f"{path}: missing required columns: {sorted(missing)}")

    # Normalize only for inference; original text/metadata are preserved.
    texts = df["text"].fillna("").astype(str).tolist()

    v2_prob = np.empty(len(df), dtype=np.float64)
    v1_prob = np.full(len(df), np.nan, dtype=np.float64) if v1_model is not None else None

    for start in range(0, len(df), chunk_size):
        end = min(start + chunk_size, len(df))
        batch = texts[start:end]

        v2_prob[start:end] = probability_for_model(v2_vectorizer, v2_model, batch)

        if v1_model is not None:
            v1_prob[start:end] = probability_for_model(v1_vectorizer, v1_model, batch)

    result = df.copy()
    result["v2_phishing_probability"] = v2_prob
    result["v2_prediction"] = (v2_prob >= 0.50).astype(int)
    result["v2_error"] = (result["v2_prediction"] != result["label"].astype(int))

    if v1_prob is not None:
        result["v1_phishing_probability"] = v1_prob
        result["v1_prediction"] = (v1_prob >= 0.50).astype(int)
        result["v1_v2_probability_gap"] = np.abs(v1_prob - v2_prob)
        result["v1_v2_prediction_disagreement"] = (
            result["v1_prediction"] != result["v2_prediction"]
        )
    else:
        result["v1_phishing_probability"] = np.nan
        result["v1_prediction"] = np.nan
        result["v1_v2_probability_gap"] = np.nan
        result["v1_v2_prediction_disagreement"] = False

    # "Hardness":
    # label=1 -> low predicted probability is hard
    # label=0 -> high predicted probability is hard
    result["hardness"] = np.where(
        result["label"].astype(int) == LABEL_POSITIVE,
        1.0 - result["v2_phishing_probability"],
        result["v2_phishing_probability"],
    )
    result["distance_from_boundary"] = np.abs(
        result["v2_phishing_probability"] - 0.50
    )

    # Human-readable mining reason.
    reasons = np.where(
        (result["label"] == 1) & (result["v2_phishing_probability"] < 0.50),
        "false_negative_v2",
        np.where(
            (result["label"] == 0) & (result["v2_phishing_probability"] >= 0.50),
            "false_positive_v2",
            "other",
        ),
    )
    result["mining_reason"] = reasons

    return {
        "all": result,
        "hard_positive": result[
            (result["label"].astype(int) == 1)
            & (result["v2_phishing_probability"] <= 0.35)
        ].copy(),
        "hard_negative": result[
            (result["label"].astype(int) == 0)
            & (result["v2_phishing_probability"] >= 0.65)
        ].copy(),
        "uncertain": result[
            result["distance_from_boundary"] <= 0.10
        ].copy(),
        "disagreement": result[
            result["v1_v2_prediction_disagreement"]
        ].copy(),
    }


def dedupe_keep_best(df: pd.DataFrame, n: int) -> pd.DataFrame:
    if df.empty:
        return df

    # text_hash is already in the processed schema, so use it as the dedupe key.
    df = df.drop_duplicates(subset=["text_hash"], keep="first").copy()

    # Prefer large hardness, then V1/V2 disagreement.
    df["priority"] = (
        df["hardness"].astype(float)
        + 0.25 * df["v1_v2_probability_gap"].fillna(0.0).astype(float)
    )
    df = df.sort_values(
        ["priority", "hardness"],
        ascending=[False, False],
        kind="stable",
    )
    return df.head(n).drop(columns=["priority"])


def save_csv(df: pd.DataFrame, path: Path):
    path.parent.mkdir(parents=True, exist_ok=True)
    columns = [
        "id",
        "text",
        "label",
        "source",
        "source_group",
        "language",
        "text_hash",
        "v2_phishing_probability",
        "v2_prediction",
        "v2_error",
        "v1_phishing_probability",
        "v1_prediction",
        "v1_v2_probability_gap",
        "v1_v2_prediction_disagreement",
        "hardness",
        "distance_from_boundary",
        "mining_reason",
    ]
    existing = [c for c in columns if c in df.columns]
    df[existing].to_csv(path, index=False, encoding="utf-8-sig")


def basic_metrics(df: pd.DataFrame) -> dict:
    labels = df["label"].astype(int).to_numpy()
    preds = df["v2_prediction"].astype(int).to_numpy()
    tp = int(((labels == 1) & (preds == 1)).sum())
    tn = int(((labels == 0) & (preds == 0)).sum())
    fp = int(((labels == 0) & (preds == 1)).sum())
    fn = int(((labels == 1) & (preds == 0)).sum())
    total = len(df)

    precision = tp / (tp + fp) if (tp + fp) else 0.0
    recall = tp / (tp + fn) if (tp + fn) else 0.0
    accuracy = (tp + tn) / total if total else 0.0

    return {
        "rows": total,
        "accuracy": round(accuracy, 6),
        "precision": round(precision, 6),
        "recall": round(recall, 6),
        "false_positives": fp,
        "false_negatives": fn,
    }


def main():
    parser = argparse.ArgumentParser()
    parser.add_argument("--max-per-file", type=int, default=5000)
    parser.add_argument("--chunk-size", type=int, default=5000)
    parser.add_argument("--skip-v1", action="store_true")
    args = parser.parse_args()

    v2_vectorizer_path = DEFAULT_V2_DIR / "phishing_vectorizer.pkl"
    v2_model_path = DEFAULT_V2_DIR / "phishing_model.pkl"

    if not v2_vectorizer_path.exists() or not v2_model_path.exists():
        raise FileNotFoundError(
            "V2 model artifacts not found. Expected:\n"
            f"  {v2_vectorizer_path}\n"
            f"  {v2_model_path}"
        )

    v2_vectorizer = load_pickle(v2_vectorizer_path)
    v2_model = load_pickle(v2_model_path)

    v1_vectorizer = v1_model = None
    v1_available = False

    v1_vectorizer_path = DEFAULT_V1_DIR / "phishing_vectorizer.pkl"
    v1_model_path = DEFAULT_V1_DIR / "phishing_model.pkl"

    if not args.skip_v1 and v1_vectorizer_path.exists() and v1_model_path.exists():
        v1_vectorizer = load_pickle(v1_vectorizer_path)
        v1_model = load_pickle(v1_model_path)
        v1_available = True

    OUT_ROOT.mkdir(parents=True, exist_ok=True)
    (OUT_ROOT / "review").mkdir(parents=True, exist_ok=True)
    (OUT_ROOT / "hard_positive").mkdir(parents=True, exist_ok=True)
    (OUT_ROOT / "hard_negative").mkdir(parents=True, exist_ok=True)

    summary = {
        "configuration": {
            "v2_model_dir": str(DEFAULT_V2_DIR),
            "v1_model_available": v1_available,
            "hard_positive_threshold": 0.35,
            "hard_negative_threshold": 0.65,
            "uncertain_boundary": 0.10,
            "max_per_file": args.max_per_file,
            "chunk_size": args.chunk_size,
        },
        "files": {},
    }

    combined_hard_pos = []
    combined_hard_neg = []

    for split_name, path in [
        ("train", TRAIN_PATH),
        ("validation", VALIDATION_PATH),
    ]:
        print(f"\nMining {split_name}: {path}")
        mined = mine_file(
            path,
            v2_vectorizer,
            v2_model,
            v1_vectorizer,
            v1_model,
            args.chunk_size,
        )
        all_df = mined["all"]

        metrics = basic_metrics(all_df)
        print("  metrics:", json.dumps(metrics))

        hp = dedupe_keep_best(mined["hard_positive"], args.max_per_file)
        hn = dedupe_keep_best(mined["hard_negative"], args.max_per_file)
        uq = mined["uncertain"].drop_duplicates("text_hash").copy()

        print(f"  hard positives: {len(hp):,}")
        print(f"  hard negatives: {len(hn):,}")
        print(f"  uncertain:      {len(uq):,}")
        print(f"  V1/V2 disagree: {len(mined['disagreement']):,}")

        summary["files"][split_name] = {
            "metrics": metrics,
            "hard_positive_candidates": int(len(hp)),
            "hard_negative_candidates": int(len(hn)),
            "uncertain_candidates": int(len(uq)),
            "v1_v2_disagreements": int(len(mined["disagreement"])),
        }

        combined_hard_pos.append(hp)
        combined_hard_neg.append(hn)

        if split_name == "train":
            save_csv(
                hp,
                OUT_ROOT / "hard_positive" / "train_hard_positives.csv",
            )
            save_csv(
                hn,
                OUT_ROOT / "hard_negative" / "train_hard_negatives.csv",
            )
            # Keep a manageable review queue: most uncertain first.
            save_csv(
                uq.sort_values(
                    ["distance_from_boundary", "v1_v2_probability_gap"],
                    ascending=[True, False],
                ).head(args.max_per_file),
                OUT_ROOT / "review" / "uncertain_train.csv",
            )
        else:
            # Validation must not be silently mixed into training.
            save_csv(
                hp,
                OUT_ROOT / "hard_positive" / "validation_hard_positive_review.csv",
            )
            save_csv(
                hn,
                OUT_ROOT / "hard_negative" / "validation_hard_negative_review.csv",
            )
            save_csv(
                uq.sort_values(
                    ["distance_from_boundary", "v1_v2_probability_gap"],
                    ascending=[True, False],
                ).head(args.max_per_file),
                OUT_ROOT / "review" / "uncertain_validation.csv",
            )

    # Build deduplicated candidate pools across train+validation.
    if combined_hard_pos:
        all_hp = pd.concat(combined_hard_pos, ignore_index=True)
        all_hp = dedupe_keep_best(all_hp, args.max_per_file * 2)
        save_csv(
            all_hp,
            OUT_ROOT / "hard_positive" / "all_split_hard_positive_candidates.csv",
        )

    if combined_hard_neg:
        all_hn = pd.concat(combined_hard_neg, ignore_index=True)
        all_hn = dedupe_keep_best(all_hn, args.max_per_file * 2)
        save_csv(
            all_hn,
            OUT_ROOT / "hard_negative" / "all_split_hard_negative_candidates.csv",
        )

    summary_path = OUT_ROOT / "mining_summary.json"
    summary_path.write_text(json.dumps(summary, indent=2), encoding="utf-8")

    print("\nDONE")
    print(f"Summary: {summary_path}")
    print("\nNext:")
    print("1. Train V2.1 using TRAIN hard examples only after human/automatic review.")
    print("2. Keep validation candidates separate.")
    print("3. Never use datasets/processed/test.parquet for training.")


if __name__ == "__main__":
    main()

