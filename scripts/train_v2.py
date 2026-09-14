from __future__ import annotations

import json
import time
from pathlib import Path

import joblib
import pandas as pd
from sklearn.calibration import CalibratedClassifierCV
from sklearn.feature_extraction.text import TfidfVectorizer
from sklearn.metrics import (
    accuracy_score,
    classification_report,
    confusion_matrix,
    precision_recall_fscore_support,
    roc_auc_score,
)
from sklearn.svm import LinearSVC


# ============================================================
# PATHS
# ============================================================

ROOT = Path(__file__).resolve().parents[1]

DATA_DIR = ROOT / "datasets" / "processed"
MODEL_DIR = ROOT / "backend" / "app" / "models" / "v2"

TRAIN_PATH = DATA_DIR / "train.parquet"
VALIDATION_PATH = DATA_DIR / "validation.parquet"
TEST_PATH = DATA_DIR / "test.parquet"

MODEL_DIR.mkdir(parents=True, exist_ok=True)


# ============================================================
# SETTINGS
# ============================================================

RANDOM_STATE = 42

MAX_FEATURES = 50_000
NGRAM_RANGE = (1, 2)

# These settings intentionally keep the same general
# TF-IDF + calibrated LinearSVC architecture as V1,
# but give V2 a larger vocabulary and better normalization.
#
# V1 stays untouched.
# ============================================================


def load_split(path: Path, name: str) -> pd.DataFrame:
    if not path.exists():
        raise FileNotFoundError(
            f"{name} dataset not found:\n{path}"
        )

    df = pd.read_parquet(path)

    required = {"text", "label"}

    missing = required - set(df.columns)

    if missing:
        raise ValueError(
            f"{name} is missing columns: {sorted(missing)}"
        )

    df = df.copy()

    df["text"] = (
        df["text"]
        .fillna("")
        .astype(str)
    )

    df["label"] = (
        pd.to_numeric(
            df["label"],
            errors="coerce",
        )
    )

    df = df[
        df["label"].isin([0, 1])
    ].copy()

    df["label"] = df["label"].astype(int)

    return df.reset_index(drop=True)


def print_split_stats(
    name: str,
    df: pd.DataFrame,
) -> None:

    benign = int(
        (df["label"] == 0).sum()
    )

    phishing = int(
        (df["label"] == 1).sum()
    )

    print(f"\n{name}")
    print("-" * 60)
    print(f"Total   : {len(df):,}")
    print(f"Benign  : {benign:,}")
    print(f"Phishing: {phishing:,}")


def main() -> None:

    print("=" * 70)
    print("ValorProtects — V2 Phishing Model Training")
    print("=" * 70)

    start = time.perf_counter()

    # --------------------------------------------------------
    # Load data
    # --------------------------------------------------------

    print("\nLoading datasets...")

    train_df = load_split(
        TRAIN_PATH,
        "Training",
    )

    validation_df = load_split(
        VALIDATION_PATH,
        "Validation",
    )

    test_df = load_split(
        TEST_PATH,
        "Test",
    )

    print_split_stats(
        "TRAIN",
        train_df,
    )

    print_split_stats(
        "VALIDATION",
        validation_df,
    )

    print_split_stats(
        "TEST",
        test_df,
    )

    X_train = train_df["text"]
    y_train = train_df["label"]

    X_validation = validation_df["text"]
    y_validation = validation_df["label"]

    X_test = test_df["text"]
    y_test = test_df["label"]

    # --------------------------------------------------------
    # TF-IDF
    # --------------------------------------------------------

    print("\nCreating TF-IDF vectorizer...")

    vectorizer = TfidfVectorizer(
        max_features=MAX_FEATURES,
        ngram_range=NGRAM_RANGE,
        lowercase=True,
        stop_words="english",
        sublinear_tf=True,
        min_df=2,
        max_df=0.995,
        strip_accents="unicode",
    )

    print("Fitting TF-IDF on TRAIN only...")

    X_train_vec = vectorizer.fit_transform(
        X_train
    )

    print(
        f"Training matrix: "
        f"{X_train_vec.shape[0]:,} x "
        f"{X_train_vec.shape[1]:,}"
    )

    print("Transforming validation/test...")

    X_validation_vec = vectorizer.transform(
        X_validation
    )

    X_test_vec = vectorizer.transform(
        X_test
    )

    print(
        f"Vocabulary size: "
        f"{len(vectorizer.vocabulary_):,}"
    )

    # --------------------------------------------------------
    # Base model
    # --------------------------------------------------------

    print("\nTraining LinearSVC...")

    base_model = LinearSVC(
        C=1.0,
        max_iter=5000,
        random_state=RANDOM_STATE,
    )

    # Calibrated probabilities are important because ValorProtects
    # consumes a phishing probability as one of several signals.
    model = CalibratedClassifierCV(
        estimator=base_model,
        method="sigmoid",
        cv=3,
        n_jobs=-1,
    )

    model.fit(
        X_train_vec,
        y_train,
    )

    print("Training complete.")

    # --------------------------------------------------------
    # Validation evaluation
    # --------------------------------------------------------

    print("\n" + "=" * 70)
    print("VALIDATION EVALUATION")
    print("=" * 70)

    validation_pred = model.predict(
        X_validation_vec
    )

    validation_prob = model.predict_proba(
        X_validation_vec
    )[:, 1]

    val_accuracy = accuracy_score(
        y_validation,
        validation_pred,
    )

    val_precision, val_recall, val_f1, _ = (
        precision_recall_fscore_support(
            y_validation,
            validation_pred,
            average="binary",
            zero_division=0,
        )
    )

    val_roc_auc = roc_auc_score(
        y_validation,
        validation_prob,
    )

    print(
        f"Accuracy : {val_accuracy:.4f}"
    )

    print(
        f"Precision: {val_precision:.4f}"
    )

    print(
        f"Recall   : {val_recall:.4f}"
    )

    print(
        f"F1       : {val_f1:.4f}"
    )

    print(
        f"ROC-AUC  : {val_roc_auc:.4f}"
    )

    # --------------------------------------------------------
    # Final test evaluation
    # --------------------------------------------------------

    print("\n" + "=" * 70)
    print("FINAL TEST EVALUATION")
    print("=" * 70)

    test_pred = model.predict(
        X_test_vec
    )

    test_prob = model.predict_proba(
        X_test_vec
    )[:, 1]

    accuracy = accuracy_score(
        y_test,
        test_pred,
    )

    precision, recall, f1, _ = (
        precision_recall_fscore_support(
            y_test,
            test_pred,
            average="binary",
            zero_division=0,
        )
    )

    roc_auc = roc_auc_score(
        y_test,
        test_prob,
    )

    print(
        f"\nAccuracy : {accuracy:.4f}"
    )

    print(
        f"Precision: {precision:.4f}"
    )

    print(
        f"Recall   : {recall:.4f}"
    )

    print(
        f"F1       : {f1:.4f}"
    )

    print(
        f"ROC-AUC  : {roc_auc:.4f}"
    )

    print("\nClassification report:")
    print(
        classification_report(
            y_test,
            test_pred,
            target_names=[
                "BENIGN",
                "PHISHING",
            ],
            digits=4,
            zero_division=0,
        )
    )

    print("Confusion matrix:")
    print(
        confusion_matrix(
            y_test,
            test_pred,
        )
    )

    # --------------------------------------------------------
    # Save artifacts
    # --------------------------------------------------------

    print("\nSaving V2 artifacts...")

    vectorizer_path = (
        MODEL_DIR
        / "phishing_vectorizer.pkl"
    )

    model_path = (
        MODEL_DIR
        / "phishing_model.pkl"
    )

    metrics_path = (
        MODEL_DIR
        / "training_metrics.json"
    )

    manifest_path = (
        MODEL_DIR
        / "MODEL_VERSION.json"
    )

    joblib.dump(
        vectorizer,
        vectorizer_path,
        compress=3,
    )

    joblib.dump(
        model,
        model_path,
        compress=3,
    )

    metrics = {
        "validation": {
            "accuracy": float(val_accuracy),
            "precision": float(val_precision),
            "recall": float(val_recall),
            "f1": float(val_f1),
            "roc_auc": float(val_roc_auc),
            "rows": int(len(validation_df)),
        },
        "test": {
            "accuracy": float(accuracy),
            "precision": float(precision),
            "recall": float(recall),
            "f1": float(f1),
            "roc_auc": float(roc_auc),
            "rows": int(len(test_df)),
        },
    }

    metrics_path.write_text(
        json.dumps(
            metrics,
            indent=2,
        ),
        encoding="utf-8",
    )

    manifest = {
        "version": "v2",
        "model_type": (
            "CalibratedClassifierCV("
            "LinearSVC)"
        ),
        "vectorizer": (
            "TfidfVectorizer"
        ),
        "training_sources": [
            "puyang2025/seven-phishing-email-datasets",
            "zefang-liu/phishing-email-dataset",
            "Navyasri17/phishing_emails-data",
        ],
        "training_rows": int(len(train_df)),
        "validation_rows": int(
            len(validation_df)
        ),
        "test_rows": int(len(test_df)),
        "vocabulary_size": int(
            len(vectorizer.vocabulary_)
        ),
        "max_features": MAX_FEATURES,
        "ngram_range": list(
            NGRAM_RANGE
        ),
        "random_state": RANDOM_STATE,
        "language": "English",
        "label_mapping": {
            "0": "BENIGN",
            "1": "PHISHING",
        },
    }

    manifest_path.write_text(
        json.dumps(
            manifest,
            indent=2,
        ),
        encoding="utf-8",
    )

    elapsed = (
        time.perf_counter() - start
    )

    print("\n" + "=" * 70)
    print("V2 TRAINING COMPLETE")
    print("=" * 70)

    print(
        f"\nTime: {elapsed / 60:.2f} minutes"
    )

    print("\nCreated:")
    print(vectorizer_path)
    print(model_path)
    print(metrics_path)
    print(manifest_path)

    print("\nV1 was NOT modified.")


if __name__ == "__main__":
    main()