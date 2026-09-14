from pathlib import Path
import sys
import joblib

PROJECT_ROOT = Path(__file__).resolve().parents[1]

MODEL_DIR = PROJECT_ROOT / "backend" / "app" / "models"
V1_DIR = MODEL_DIR / "v1_current"
V2_DIR = MODEL_DIR / "v2"
FIXTURE_DIR = PROJECT_ROOT / "tests" / "fixtures" / "phishing_eml_suite"


def load_model(model_dir: Path):
    model = joblib.load(model_dir / "phishing_model.pkl")
    vectorizer = joblib.load(model_dir / "phishing_vectorizer.pkl")
    return model, vectorizer


def extract_email_text(eml_path: Path) -> str:
    # Simple fixture reader for comparing model behavior.
    # The production parser remains separate and unchanged.
    raw = eml_path.read_text(encoding="utf-8", errors="replace")

    parts = raw.split("\n\n", 1)
    body = parts[1] if len(parts) == 2 else raw

    return raw + "\n" + body


def predict(model, vectorizer, text: str):
    X = vectorizer.transform([text])

    prediction = int(model.predict(X)[0])

    probability = None
    if hasattr(model, "predict_proba"):
        probability = float(model.predict_proba(X)[0][1])

    return prediction, probability


def label_prediction(prediction: int) -> str:
    return "PHISHING" if prediction == 1 else "BENIGN"


def main():
    if not FIXTURE_DIR.exists():
        print(f"Fixture directory not found: {FIXTURE_DIR}")
        sys.exit(1)

    fixtures = sorted(FIXTURE_DIR.glob("*.eml"))

    if not fixtures:
        print("No .eml fixtures found.")
        sys.exit(1)

    print(f"Fixtures found: {len(fixtures)}")
    print()

    v1_model, v1_vectorizer = load_model(V1_DIR)
    v2_model, v2_vectorizer = load_model(V2_DIR)

    results = []

    for fixture in fixtures:
        text = extract_email_text(fixture)

        v1_pred, v1_prob = predict(v1_model, v1_vectorizer, text)
        v2_pred, v2_prob = predict(v2_model, v2_vectorizer, text)

        results.append(
            {
                "fixture": fixture.name,
                "v1_label": label_prediction(v1_pred),
                "v1_probability": v1_prob,
                "v2_label": label_prediction(v2_pred),
                "v2_probability": v2_prob,
            }
        )

    print("=" * 100)
    print("V1 vs V2 — PHISHING FIXTURE COMPARISON")
    print("=" * 100)

    for r in results:
        v1_prob = (
            f"{r['v1_probability'] * 100:.2f}%"
            if r["v1_probability"] is not None
            else "N/A"
        )
        v2_prob = (
            f"{r['v2_probability'] * 100:.2f}%"
            if r["v2_probability"] is not None
            else "N/A"
        )

        print(f"\n{r['fixture']}")
        print(f"  V1: {r['v1_label']:8}  probability={v1_prob}")
        print(f"  V2: {r['v2_label']:8}  probability={v2_prob}")

    print("\n" + "=" * 100)


if __name__ == "__main__":
    main()