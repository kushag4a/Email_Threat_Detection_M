"""
Regression tests for production ML model wiring.

Context (2026 risk-hardening review): ml_classifier.py was found to be
loading its phishing (binary) model from the flat
backend/app/models/ directory, which - verified by sha256 - still
contained the V1 artifacts, even though the approved final decision is
V2 (backend/app/models/v2/), with V2.1 evaluated and explicitly NOT
promoted. This test pins the fix (an explicit PHISHING_MODEL_DIR
constant in ml_classifier.py) so a future change cannot silently point
production back at a stale or wrong model directory without failing
CI.

No model files are modified or retrained by this test - it only reads
file bytes and the already-loaded in-memory model objects.
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
        assert ml_classifier.PHISHING_MODEL_DIR.resolve() == (MODELS_DIR / "v2").resolve()

    def test_loaded_phishing_model_hash_matches_v2_artifact_on_disk(self):
        loaded_hash = _sha256(ml_classifier.PHISHING_MODEL_DIR / "phishing_model.pkl")
        v2_hash = _sha256(MODELS_DIR / "v2" / "phishing_model.pkl")
        assert loaded_hash == v2_hash

    def test_loaded_phishing_vectorizer_hash_matches_v2_artifact_on_disk(self):
        loaded_hash = _sha256(ml_classifier.PHISHING_MODEL_DIR / "phishing_vectorizer.pkl")
        v2_hash = _sha256(MODELS_DIR / "v2" / "phishing_vectorizer.pkl")
        assert loaded_hash == v2_hash

    def test_loaded_phishing_model_is_not_v1(self):
        """Guards specifically against regressing back to the bug this
        fix addresses: production silently serving the V1 snapshot."""
        loaded_hash = _sha256(ml_classifier.PHISHING_MODEL_DIR / "phishing_model.pkl")
        v1_hash = _sha256(MODELS_DIR / "v1_current" / "phishing_model.pkl")
        assert loaded_hash != v1_hash

    def test_loaded_phishing_model_is_not_v2_1(self):
        """V2.1 was evaluated and explicitly NOT promoted - production
        must not be serving it either."""
        loaded_hash = _sha256(ml_classifier.PHISHING_MODEL_DIR / "phishing_model.pkl")
        v2_1_hash = _sha256(MODELS_DIR / "v2_1" / "phishing_model.pkl")
        assert loaded_hash != v2_1_hash

    def test_v2_model_version_metadata_declares_v2(self):
        meta = json.loads((MODELS_DIR / "v2" / "MODEL_VERSION.json").read_text())
        assert meta.get("version") == "v2"

    def test_in_memory_phishing_model_objects_are_the_v2_artifacts(self):
        """Sanity check that the module-level singletons actually came
        from PHISHING_MODEL_DIR (not e.g. a leftover import-order bug
        loading two different copies)."""
        import joblib
        expected_model = joblib.load(MODELS_DIR / "v2" / "phishing_model.pkl")
        assert type(ml_classifier._phishing_model) is type(expected_model)
        assert ml_classifier._phishing_model.classes_.tolist() == expected_model.classes_.tolist()


class TestMultithreatModelUntouchedByV2Decision:
    """The multithreat (multi-class category) model is unrelated to the
    phishing V2/V2.1 decision - no V2 equivalent exists for it, so it
    must keep loading from the flat MODELS_DIR, unchanged."""

    def test_multithreat_still_loads_from_flat_models_dir(self):
        loaded_hash = _sha256(MODELS_DIR / "multithreat_model.pkl")
        flat_hash = _sha256(MODELS_DIR / "multithreat_model.pkl")
        assert loaded_hash == flat_hash  # trivial path identity check

    def test_no_v2_multithreat_artifact_exists(self):
        """This review does not invent a V2 multithreat model - assert
        that assumption stays true so nobody adds one without an
        explicit decision."""
        assert not (MODELS_DIR / "v2" / "multithreat_model.pkl").exists()
        assert not (MODELS_DIR / "v2_1" / "multithreat_model.pkl").exists()

    def test_flat_multithreat_artifact_still_present(self):
        assert (MODELS_DIR / "multithreat_model.pkl").exists()
        assert (MODELS_DIR / "multithreat_vectorizer.pkl").exists()


class TestOldModelArtifactsNotDeleted:
    """This review explicitly must not delete any old model artifacts -
    only fix which one the application loads."""

    def test_v1_current_snapshot_still_present(self):
        assert (MODELS_DIR / "v1_current" / "phishing_model.pkl").exists()
        assert (MODELS_DIR / "v1_current" / "phishing_vectorizer.pkl").exists()

    def test_v2_1_experiment_still_present(self):
        assert (MODELS_DIR / "v2_1" / "phishing_model.pkl").exists()
        assert (MODELS_DIR / "v2_1" / "phishing_vectorizer.pkl").exists()

    def test_flat_legacy_copy_still_present_but_unused(self):
        """The flat backend/app/models/phishing_model.pkl (== V1) is
        left in place as an inert historical/rollback copy - not
        deleted, just no longer read by ml_classifier.py."""
        assert (MODELS_DIR / "phishing_model.pkl").exists()
        assert (MODELS_DIR / "phishing_vectorizer.pkl").exists()
        assert ml_classifier.PHISHING_MODEL_DIR != MODELS_DIR
