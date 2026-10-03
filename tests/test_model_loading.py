"""
Regression tests for production ML model wiring.

The production phishing classifier must load V2 from models/v2/.
The separate multithreat classifier remains the V1 snapshot in
models/v1_current/ because no newer multithreat model was promoted.
"""

import hashlib
import json
from pathlib import Path

from backend.app.services import ml_classifier


MODELS_DIR = Path(__file__).resolve().parents[1] / "backend" / "app" / "models"
V1_DIR = MODELS_DIR / "v1_current"
V2_DIR = MODELS_DIR / "v2"


def _sha256(path: Path) -> str:
    return hashlib.sha256(path.read_bytes()).hexdigest()


class TestProductionPhishingModelIsV2:
    """Ensure the live phishing model is the approved V2 artifact."""

    def test_phishing_model_dir_points_at_v2(self):
        assert ml_classifier.PHISHING_MODEL_DIR.resolve() == V2_DIR.resolve()

    def test_phishing_model_artifacts_exist_in_production_directory(self):
        assert (V2_DIR / "phishing_model.pkl").exists()
        assert (V2_DIR / "phishing_vectorizer.pkl").exists()
        assert (V2_DIR / "MODEL_VERSION.json").exists()

    def test_loaded_phishing_model_hash_matches_v2_artifact_on_disk(self):
        loaded_artifact_hash = _sha256(V2_DIR / "phishing_model.pkl")
        production_artifact_hash = _sha256(
            ml_classifier.PHISHING_MODEL_DIR / "phishing_model.pkl"
        )

        assert loaded_artifact_hash == production_artifact_hash

    def test_loaded_phishing_vectorizer_hash_matches_v2_artifact_on_disk(self):
        loaded_artifact_hash = _sha256(V2_DIR / "phishing_vectorizer.pkl")
        production_artifact_hash = _sha256(
            ml_classifier.PHISHING_MODEL_DIR / "phishing_vectorizer.pkl"
        )

        assert loaded_artifact_hash == production_artifact_hash

    def test_production_phishing_model_is_not_v1(self):
        v2_hash = _sha256(V2_DIR / "phishing_model.pkl")
        v1_hash = _sha256(V1_DIR / "phishing_model.pkl")

        assert v2_hash != v1_hash

    def test_v2_model_version_metadata_declares_v2(self):
        metadata = json.loads(
            (V2_DIR / "MODEL_VERSION.json").read_text(encoding="utf-8")
        )

        assert metadata.get("version") == "v2"

    def test_in_memory_phishing_model_is_v2(self):
        import joblib

        expected_model = joblib.load(V2_DIR / "phishing_model.pkl")

        assert type(ml_classifier._phishing_model) is type(expected_model)
        assert (
            ml_classifier._phishing_model.classes_.tolist()
            == expected_model.classes_.tolist()
        )


class TestMultithreatModelLocation:
    """Ensure the separate multithreat model uses v1_current."""

    def test_multithreat_artifacts_are_in_v1_current(self):
        assert (V1_DIR / "multithreat_model.pkl").exists()
        assert (V1_DIR / "multithreat_vectorizer.pkl").exists()

    def test_multithreat_model_dir_points_at_v1_current(self):
        assert (
            ml_classifier.MULTITHREAT_MODEL_DIR.resolve()
            == V1_DIR.resolve()
        )

    def test_no_multithreat_artifacts_exist_in_v2(self):
        assert not (V2_DIR / "multithreat_model.pkl").exists()
        assert not (V2_DIR / "multithreat_vectorizer.pkl").exists()


class TestLegacyPhishingSnapshot:
    """Ensure the old V1 snapshot remains available as a reference only."""

    def test_v1_current_phishing_snapshot_exists(self):
        assert (V1_DIR / "phishing_model.pkl").exists()
        assert (V1_DIR / "phishing_vectorizer.pkl").exists()

    def test_production_phishing_directory_is_not_v1_current(self):
        assert ml_classifier.PHISHING_MODEL_DIR.resolve() != V1_DIR.resolve()