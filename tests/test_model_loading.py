"""
Regression tests for production ML model wiring.

Context (2026 risk-hardening review): ml_classifier.py was found to be
loading its phishing (binary) model from the flat
backend/app/models/ directory, which contained the V1 artifacts.

The approved production model is V2:
    backend/app/models/v2/

V2.1 was evaluated separately and was explicitly NOT promoted to
production. Its experimental artifacts have been removed from the
repository.

These tests pin the production model directory so a future change
cannot silently point production back at a stale or wrong model
directory without failing CI.

No model files are modified or retrained by these tests.
"""
import hashlib
import json
from pathlib import Path

from backend.app.services import ml_classifier


MODELS_DIR = Path(__file__).resolve().parents[1] / "backend" / "app" / "models"


def _sha256(path: Path) -> str:
    return hashlib.sha256(path.read_bytes()).hexdigest()


class TestProductionPhishingModelIsV2:
    def test_phishing_model_dir_points_at_v2(self):
        assert (
            ml_classifier.PHISHING_MODEL_DIR.resolve()
            == (MODELS_DIR / "v2").resolve()
        )

    def test_loaded_phishing_model_hash_matches_v2_artifact_on_disk(self):
        loaded_hash = _sha256(
            ml_classifier.PHISHING_MODEL_DIR / "phishing_model.pkl"
        )
        v2_hash = _sha256(MODELS_DIR / "v2" / "phishing_model.pkl")

        assert loaded_hash == v2_hash

    def test_loaded_phishing_vectorizer_hash_matches_v2_artifact_on_disk(self):
        loaded_hash = _sha256(
            ml_classifier.PHISHING_MODEL_DIR / "phishing_vectorizer.pkl"
        )
        v2_hash = _sha256(MODELS_DIR / "v2" / "phishing_vectorizer.pkl")

        assert loaded_hash == v2_hash

    def test_loaded_phishing_model_is_not_v1(self):
        """
        Guards specifically against regressing back to the original bug:
        production silently serving the V1 snapshot.
        """
        loaded_hash = _sha256(
            ml_classifier.PHISHING_MODEL_DIR / "phishing_model.pkl"
        )
        v1_hash = _sha256(
            MODELS_DIR / "v1_current" / "phishing_model.pkl"
        )

        assert loaded_hash != v1_hash

    def test_phishing_model_artifacts_exist_in_production_directory(self):
        assert (
            ml_classifier.PHISHING_MODEL_DIR / "phishing_model.pkl"
        ).exists()
        assert (
            ml_classifier.PHISHING_MODEL_DIR / "phishing_vectorizer.pkl"
        ).exists()
        assert (
            ml_classifier.PHISHING_MODEL_DIR / "MODEL_VERSION.json"
        ).exists()

    def test_v2_model_version_metadata_declares_v2(self):
        meta = json.loads(
            (MODELS_DIR / "v2" / "MODEL_VERSION.json").read_text(
                encoding="utf-8"
            )
        )

        assert meta.get("version") == "v2"

    def test_in_memory_phishing_model_objects_are_the_v2_artifacts(self):
        """
        Sanity check that the module-level singletons actually came from
        PHISHING_MODEL_DIR rather than another stale model copy.
        """
        import joblib

        expected_model = joblib.load(
            MODELS_DIR / "v2" / "phishing_model.pkl"
        )

        assert type(ml_classifier._phishing_model) is type(expected_model)
        assert (
            ml_classifier._phishing_model.classes_.tolist()
            == expected_model.classes_.tolist()
        )


class TestMultithreatModelUntouchedByV2Decision:
    """
    The multithreat model is unrelated to the V2/V2.1 binary phishing
    model decision.

    No V2 multithreat artifact exists, so the existing flat model
    remains the one used by the application.
    """

    def test_multithreat_artifacts_are_loaded_from_flat_models_dir(self):
        assert (MODELS_DIR / "multithreat_model.pkl").exists()
        assert (MODELS_DIR / "multithreat_vectorizer.pkl").exists()

    def test_no_v2_multithreat_artifact_exists(self):
        assert not (
            MODELS_DIR / "v2" / "multithreat_model.pkl"
        ).exists()
        assert not (
            MODELS_DIR / "v2" / "multithreat_vectorizer.pkl"
        ).exists()

    def test_flat_multithreat_artifacts_still_present(self):
        assert (MODELS_DIR / "multithreat_model.pkl").exists()
        assert (MODELS_DIR / "multithreat_vectorizer.pkl").exists()


class TestLegacyModelArtifacts:
    """
    Historical V1 artifacts are still present as reference/rollback
    material, but production must not load them for phishing detection.
    """

    def test_v1_current_snapshot_still_present(self):
        assert (
            MODELS_DIR / "v1_current" / "phishing_model.pkl"
        ).exists()
        assert (
            MODELS_DIR / "v1_current" / "phishing_vectorizer.pkl"
        ).exists()

    def test_flat_legacy_copy_still_present_but_unused(self):
        """
        The flat backend/app/models/phishing_model.pkl and vectorizer are
        legacy V1 copies. They remain inert and are no longer read by
        ml_classifier.py.
        """
        assert (MODELS_DIR / "phishing_model.pkl").exists()
        assert (MODELS_DIR / "phishing_vectorizer.pkl").exists()

        assert (
            ml_classifier.PHISHING_MODEL_DIR.resolve()
            != MODELS_DIR.resolve()
        )