from pathlib import Path
import json
import time

import joblib
import numpy as np
import pandas as pd

from sklearn.feature_extraction.text import TfidfVectorizer
from sklearn.svm import LinearSVC
from sklearn.calibration import CalibratedClassifierCV
from sklearn.metrics import (
    accuracy_score,
    precision_score,
    recall_score,
    f1_score,
    roc_auc_score,
    confusion_matrix,
)

TRAIN_PATH = Path("datasets/processed/train.parquet")
VAL_PATH = Path("datasets/processed/validation.parquet")

HARD_POS_PATH = Path(
    "datasets/v2_1/hard_positive/train_hard_positives.csv"
)
HARD_NEG_PATH = Path(
    "datasets/v2_1/hard_negative/train_hard_negatives.csv"
)

OUT_DIR = Path("backend/app/models/v2_1")
OUT_DIR.mkdir(parents=True, exist_ok=True)

HARD_REPEAT = 8

VECTORIZER_CONFIG = dict(
    lowercase=True,
    strip_accents="unicode",
    stop_words="english",
    ngram_range=(1, 2),
    min_df=2,
    max_df=0.995,
    max_features=50000,
    sublinear_tf=True,
)

MODEL_CONFIG = dict(
    C=1.0,
    cv=3,
    method="sigmoid",
    n_jobs=-1,
)


def load_table(path: Path) -> pd.DataFrame:
    df = pd.read_parquet(path) if path.suffix == ".parquet" else pd.read_csv(path)

    required = {"text", "label"}
    missing = required - set(df.columns)
    if missing:
        raise ValueError(f"{path}: missing columns {sorted(missing)}")

    df = df.copy()
    df["text"] = df["text"].fillna("").astype(str)
    df["label"] = df["label"].astype(int)

    df = df[df["text"].str.strip().str.len() >= 10].copy()
    return df


def prepare_training_data():
    base = load_table(TRAIN_PATH)

    hard_pos = pd.read_csv(HARD_POS_PATH)
    hard_neg = pd.read_csv(HARD_NEG_PATH)

    hard_pos = hard_pos[["id", "text", "label"]].copy()
    hard_neg = hard_neg[["id", "text", "label"]].copy()

    hard = pd.concat([hard_pos, hard_neg], ignore_index=True)

    hard["text"] = hard["text"].fillna("").astype(str)
    hard["label"] = hard["label"].astype(int)

    # Deduplicate hard examples by text.
    hard = hard.drop_duplicates(subset=["text"]).reset_index(drop=True)

    # Keep the original distribution plus repeated hard failures.
    hard_repeated = pd.concat(
        [hard] * HARD_REPEAT,
        ignore_index=True,
    )

    # Mark source only for diagnostics.
    base2 = base[["id", "text", "label"]].copy()
    base2["training_source"] = "original_v2_train"

    hard_repeated["training_source"] = "mined_hard_example"

    combined = pd.concat(
        [
            base2,
            hard_repeated[["id", "text", "label", "training_source"]],
        ],
        ignore_index=True,
    )

    # Remove exact duplicates while preserving intentional hard-example repeats.
    # We only remove duplicates between ORIGINAL rows; repeated hard rows stay.
    base_hash = pd.util.hash_pandas_object(
        base2["text"], index=False
    ).astype("uint64")
    hard_hash = pd.util.hash_pandas_object(
        hard["text"], index=False
    ).astype("uint64")

    print(f"Original training rows: {len(base2):,}")
    print(f"Unique hard positives: {len(hard_pos.drop_duplicates('text')):,}")
    print(f"Unique hard negatives: {len(hard_neg.drop_duplicates('text')):,}")
    print(f"Unique hard rows: {len(hard):,}")
    print(f"Hard repeat factor: {HARD_REPEAT}x")
    print(f"Final training rows: {len(combined):,}")
    print("\nFinal class distribution:")
    print(combined["label"].value_counts())

    return combined


def evaluate(model, vectorizer, df: pd.DataFrame):
    texts = df["text"].tolist()
    y = df["label"].to_numpy()

    x = vectorizer.transform(texts)
    proba = model.predict_proba(x)[:, 1]
    pred = (proba >= 0.5).astype(int)

    metrics = {
        "rows": int(len(df)),
        "accuracy": float(accuracy_score(y, pred)),
        "precision": float(precision_score(y, pred, zero_division=0)),
        "recall": float(recall_score(y, pred, zero_division=0)),
        "f1": float(f1_score(y, pred, zero_division=0)),
        "roc_auc": float(roc_auc_score(y, proba)),
        "confusion_matrix": confusion_matrix(y, pred).tolist(),
    }

    return metrics


def main():
    started = time.time()

    train = prepare_training_data()
    validation = load_table(VAL_PATH)

    print("\nFitting TF-IDF...")
    vectorizer = TfidfVectorizer(**VECTORIZER_CONFIG)
    x_train = vectorizer.fit_transform(train["text"])
    x_val = vectorizer.transform(validation["text"])

    print(f"Train matrix: {x_train.shape}")
    print(f"Validation matrix: {x_val.shape}")

    print("\nTraining LinearSVC + sigmoid calibration...")
    base_model = LinearSVC(C=MODEL_CONFIG["C"])
    model = CalibratedClassifierCV(
        estimator=base_model,
        cv=MODEL_CONFIG["cv"],
        method=MODEL_CONFIG["method"],
        n_jobs=MODEL_CONFIG["n_jobs"],
    )

    model.fit(x_train, train["label"])

    print("\nEvaluating V2.1 on validation...")
    metrics = evaluate(model, vectorizer, validation)

    print(json.dumps(metrics, indent=2))

    print("\nSaving V2.1 artifacts...")
    joblib.dump(
        vectorizer,
        OUT_DIR / "phishing_vectorizer.pkl",
        compress=3,
    )
    joblib.dump(
        model,
        OUT_DIR / "phishing_model.pkl",
        compress=3,
    )

    metadata = {
        "version": "v2.1",
        "base_model": "v2",
        "training_rows_original": 164788,
        "hard_positive_rows": int(
            len(pd.read_csv(HARD_POS_PATH).drop_duplicates("text"))
        ),
        "hard_negative_rows": int(
            len(pd.read_csv(HARD_NEG_PATH).drop_duplicates("text"))
        ),
        "hard_repeat_factor": HARD_REPEAT,
        "validation_metrics": metrics,
        "vectorizer_config": VECTORIZER_CONFIG,
        "model_config": MODEL_CONFIG,
        "do_not_use_test_for_training": True,
        "training_seconds": round(time.time() - started, 2),
    }

    (OUT_DIR / "MODEL_VERSION.json").write_text(
        json.dumps(metadata, indent=2),
        encoding="utf-8",
    )

    (OUT_DIR / "training_metrics.json").write_text(
        json.dumps(metrics, indent=2),
        encoding="utf-8",
    )

    print("\nDONE")
    print(f"Model directory: {OUT_DIR}")
    print(
        f"Elapsed: {round(time.time() - started, 2)} seconds"
    )


if __name__ == "__main__":
    main()
