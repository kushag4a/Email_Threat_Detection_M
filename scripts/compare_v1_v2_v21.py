from pathlib import Path
import json
import joblib
import pandas as pd
from sklearn.metrics import accuracy_score, precision_score, recall_score, f1_score, roc_auc_score, confusion_matrix

TEST = Path("datasets/processed/test.parquet")

MODELS = {
    "V1": Path("backend/app/models/v1_current"),
    "V2": Path("backend/app/models/v2"),
    "V2.1": Path("backend/app/models/v2_1"),
}

df = pd.read_parquet(TEST)
texts = df["text"].fillna("").astype(str)
y = df["label"].astype(int)

results = {}

for name, directory in MODELS.items():
    print(f"\n=== {name} ===")

    vectorizer = joblib.load(directory / "phishing_vectorizer.pkl")
    model = joblib.load(directory / "phishing_model.pkl")

    x = vectorizer.transform(texts)
    probabilities = model.predict_proba(x)[:, 1]
    predictions = (probabilities >= 0.50).astype(int)

    metrics = {
        "accuracy": float(accuracy_score(y, predictions)),
        "precision": float(precision_score(y, predictions, zero_division=0)),
        "recall": float(recall_score(y, predictions, zero_division=0)),
        "f1": float(f1_score(y, predictions, zero_division=0)),
        "roc_auc": float(roc_auc_score(y, probabilities)),
        "confusion_matrix": confusion_matrix(y, predictions).tolist(),
    }

    results[name] = metrics
    print(json.dumps(metrics, indent=2))

Path("datasets/v2_1/test_model_comparison.json").write_text(
    json.dumps(results, indent=2),
    encoding="utf-8",
)

print("\nSaved:")
print("datasets/v2_1/test_model_comparison.json")
