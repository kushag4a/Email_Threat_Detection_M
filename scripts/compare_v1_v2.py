from __future__ import annotations

from pathlib import Path

import joblib
import pandas as pd

from sklearn.metrics import (
    accuracy_score,
    precision_recall_fscore_support,
    roc_auc_score,
    confusion_matrix,
)


ROOT = Path(__file__).resolve().parents[1]

DATA = ROOT / "datasets" / "processed" / "test.parquet"

V1_DIR = ROOT / "backend" / "app" / "models" / "v1_current"
V2_DIR = ROOT / "backend" / "app" / "models" / "v2"


def evaluate(version: str, model_dir: Path, df: pd.DataFrame):
    print(f"\n{'=' * 70}")
    print(f"{version}")
    print(f"{'=' * 70}")

    vectorizer = joblib.load(
        model_dir / "phishing_vectorizer.pkl"
    )

    model = joblib.load(
        model_dir / "phishing_model.pkl"
    )

    X = vectorizer.transform(
        df["text"].astype(str)
    )

    y = df["label"].astype(int)

    pred = model.predict(X)
    prob = model.predict_proba(X)[:, 1]

    accuracy = accuracy_score(y, pred)

    precision, recall, f1, _ = (
        precision_recall_fscore_support(
            y,
            pred,
            average="binary",
            zero_division=0,
        )
    )

    auc = roc_auc_score(y, prob)

    cm = confusion_matrix(y, pred)

    print(f"Accuracy : {accuracy:.4f}")
    print(f"Precision: {precision:.4f}")
    print(f"Recall   : {recall:.4f}")
    print(f"F1       : {f1:.4f}")
    print(f"ROC-AUC  : {auc:.4f}")

    print("\nConfusion matrix:")
    print(cm)

    return {
        "accuracy": accuracy,
        "precision": precision,
        "recall": recall,
        "f1": f1,
        "roc_auc": auc,
    }


def main():
    if not DATA.exists():
        raise FileNotFoundError(DATA)

    df = pd.read_parquet(DATA)

    print(
        f"Using identical test set: {len(df):,} emails"
    )

    v1 = evaluate(
        "V1 CURRENT MODEL",
        V1_DIR,
        df,
    )

    v2 = evaluate(
        "V2 NEW MODEL",
        V2_DIR,
        df,
    )

    print("\n" + "=" * 70)
    print("V1 vs V2")
    print("=" * 70)

    for metric in [
        "accuracy",
        "precision",
        "recall",
        "f1",
        "roc_auc",
    ]:
        delta = v2[metric] - v1[metric]

        print(
            f"{metric.upper():10s}: "
            f"V1={v1[metric]:.4f}  "
            f"V2={v2[metric]:.4f}  "
            f"Delta={delta:+.4f}"
        )


if __name__ == "__main__":
    main()