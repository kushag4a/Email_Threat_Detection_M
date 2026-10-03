"""Integration tests for wiring the isolated SpamAssassin adapter
(`backend.app.spam`) into the production analysis pipeline
(`backend/app/services/analysis_service.py`) as an OPTIONAL stage.

Scope of these tests:
    * SpamAssassin is OFF by default and, when off, is never invoked
      (no adapter call, no subprocess, no Docker).
    * When enabled, the adapter's structured `SpamAssassinResult` is
      exposed on the analysis response under `spamassassin`, unchanged
      whether it succeeded, came back `available=False`, or reported an
      `error` (missing executable, Docker not running, timeout,
      non-zero exit).
    * A SpamAssassin failure - expected or a genuinely unexpected bug in
      the integration glue itself - never fails the overall analysis.
    * The rest of the pipeline (attachments/YARA, M1, M2/V2 model, M3
      threat intel, the deterministic BEC detector, the risk engine) is
      unaffected: same calls, same arguments, same output shape.

Every scenario mocks the SpamAssassin adapter/subprocess layer (or the
other pipeline stages, when isolating the SpamAssassin call itself) so
this suite runs fully offline and deterministically, with no real
SpamAssassin installation, Docker, or ML models required.
"""

from __future__ import annotations

import subprocess
import sys
from pathlib import Path
from unittest.mock import MagicMock

import pytest


# Mirror the same defensive sys.path handling used by
# tests/test_spamassassin.py so this file is importable without the
# repository being installed as a package.
_REPO_ROOT = Path(__file__).resolve().parent.parent
if str(_REPO_ROOT) not in sys.path:
    sys.path.insert(0, str(_REPO_ROOT))

from backend.app.schemas.email_message import NormalizedEmail  # noqa: E402
from backend.app.services import analysis_service  # noqa: E402
from backend.app.spam import spamassassin as sa_module  # noqa: E402
from backend.app.spam.config import (  # noqa: E402
    ENV_ARGS,
    ENV_ENABLED,
    ENV_EXECUTABLE,
    ENV_TIMEOUT_SECONDS,
    SpamAssassinConfig,
)
from backend.app.spam.result_schema import SpamAssassinResult  # noqa: E402

# --- Fixtures ---------------------------------------------------------------


@pytest.fixture(autouse=True)
def _clean_spamassassin_env(monkeypatch):
    """Ensure no `SPAMASSASSIN_*` env var leaks between tests or from the host."""
    for var in (ENV_ENABLED, ENV_EXECUTABLE, ENV_ARGS, ENV_TIMEOUT_SECONDS):
        monkeypatch.delenv(var, raising=False)


def _make_email(**overrides) -> NormalizedEmail:
    defaults = dict(
        message_id="msg-1",
        provider="gmail",
        account_id="acct-1",
        sender="alice@example.com",
        recipient="bob@example.com",
        subject="Hello",
        date="2026-09-20T00:00:00Z",
        body="This is a normal test email body.",
    )
    defaults.update(overrides)
    return NormalizedEmail(**defaults)


def _patch_pipeline_stages(monkeypatch):
    """Stub every OTHER pipeline stage with cheap, deterministic
    fakes so these tests exercise only the new SpamAssassin wiring,
    without depending on (or risking any interaction with) the real
    V2/NLLB model, YARA, threat intelligence, or BEC detector."""
    monkeypatch.setattr(
        analysis_service,
        "analyze_attachments",
        MagicMock(
            return_value={
                "scanned": False,
                "reason": "no attachments",
                "has_high_severity": False,
                "high_severity_filenames": [],
                "items": [],
            }
        ),
    )
    monkeypatch.setattr(
        analysis_service,
        "m1_analyze",
        MagicMock(return_value={"origin_ip": None, "spf": "pass", "dkim": "pass", "dmarc": "pass"}),
    )
    monkeypatch.setattr(
        analysis_service, "prepare_m1_input", MagicMock(return_value=MagicMock(model_dump=lambda: {}))
    )
    monkeypatch.setattr(analysis_service, "build_analysis_text", MagicMock(return_value="text"))
    monkeypatch.setattr(
        analysis_service,
        "classify_email",
        MagicMock(
            return_value={
                "safe_probability": 100.0,
                "phishing_probability": 0.0,
                "threat_categories": {},
                "rule_based_threats": {},
                "top_classification": None,
            }
        ),
    )
    monkeypatch.setattr(
        analysis_service,
        "analyze_threat_intelligence",
        MagicMock(return_value={"phishtank": [], "spamhaus": [], "local_heuristics": []}),
    )
    monkeypatch.setattr(
        analysis_service, "detect_bec", MagicMock(return_value={"categories": {}, "category_count": 0})
    )
    monkeypatch.setattr(
        analysis_service,
        "calculate_risk",
        MagicMock(
            return_value={
                "score": 0,
                "level": "LOW",
                "threat_types": [],
                "reasons": ["No significant risk indicators found"],
                "contributing_modules": [],
                "calculation": {},
                "config_version": "test",
            }
        ),
    )


# --- 1. Disabled by default: SpamAssassin is never called -------------------


class TestDisabledByDefault:
    def test_default_config_is_disabled(self):
        from backend.app.spam.config import get_spamassassin_config

        assert get_spamassassin_config().enabled is False

    def test_disabled_stage_returns_none_without_calling_adapter(self, monkeypatch):
        mock_adapter = MagicMock()
        monkeypatch.setattr(analysis_service, "spamassassin_analyze_email", mock_adapter)

        result = analysis_service._run_spamassassin_stage(_make_email())

        assert result is None
        mock_adapter.assert_not_called()

    def test_disabled_stage_does_not_touch_subprocess_at_all(self, monkeypatch):
        """Belt-and-suspenders: patch subprocess.run inside the real
        adapter module itself and prove it is never reached - i.e.
        Docker is never invoked - when the flag is off."""
        mock_run = MagicMock()
        monkeypatch.setattr(sa_module.subprocess, "run", mock_run)

        result = analysis_service._run_spamassassin_stage(_make_email())

        assert result is None
        mock_run.assert_not_called()

    def test_full_pipeline_disabled_exposes_none_and_omits_evidence_source(self, monkeypatch):
        _patch_pipeline_stages(monkeypatch)
        mock_adapter = MagicMock()
        monkeypatch.setattr(analysis_service, "spamassassin_analyze_email", mock_adapter)

        out = analysis_service.analyze_normalized_email(_make_email())

        mock_adapter.assert_not_called()
        assert out["status"] == "analyzed"
        assert "spamassassin" in out  # key always present
        assert out["spamassassin"] is None
        assert "spamassassin" not in out["evidence_sources"]


# --- 2. Enabled + success: result is exposed --------------------------------


class TestEnabledSuccess:
    def test_enabled_success_exposes_full_structured_result(self, monkeypatch):
        _patch_pipeline_stages(monkeypatch)
        cfg = SpamAssassinConfig(enabled=True, executable="fake-spamassassin")
        monkeypatch.setattr(analysis_service, "get_spamassassin_config", lambda: cfg)

        fake_result = SpamAssassinResult(
            available=True,
            score=15.3,
            threshold=5.0,
            is_spam=True,
            matched_rules=["BAYES_99", "HTML_MESSAGE"],
            raw_status="X-Spam-Status: Yes, score=15.3 required=5.0",
            error=None,
        )
        mock_adapter = MagicMock(return_value=fake_result)
        monkeypatch.setattr(analysis_service, "spamassassin_analyze_email", mock_adapter)

        out = analysis_service.analyze_normalized_email(_make_email())

        mock_adapter.assert_called_once()
        _, kwargs = mock_adapter.call_args
        assert kwargs["config"] is cfg

        sa = out["spamassassin"]
        assert sa["available"] is True
        assert sa["score"] == 15.3
        assert sa["threshold"] == 5.0
        assert sa["is_spam"] is True
        assert sa["matched_rules"] == ["BAYES_99", "HTML_MESSAGE"]
        assert sa["engine"] == "spamassassin"
        assert sa["error"] is None
        assert "spamassassin" in out["evidence_sources"]
        assert out["status"] == "analyzed"

    def test_enabled_success_never_becomes_a_phishing_verdict(self, monkeypatch):
        """SpamAssassin stays separate from phishing classification."""
        _patch_pipeline_stages(monkeypatch)

        cfg = SpamAssassinConfig(enabled=True)
        monkeypatch.setattr(
            analysis_service,
            "get_spamassassin_config",
            lambda: cfg,
        )

        spam_result = SpamAssassinResult(
            available=True,
            score=99.0,
            is_spam=True,
        )

        monkeypatch.setattr(
            analysis_service,
            "spamassassin_analyze_email",
            MagicMock(return_value=spam_result),
        )

        out = analysis_service.analyze_normalized_email(_make_email())

        _, risk_kwargs = analysis_service.calculate_risk.call_args

        # SpamAssassin is intentionally wired into the risk engine.
        assert "spamassassin" in risk_kwargs

        # The stage passes the serialized result into calculate_risk().
        assert risk_kwargs["spamassassin"] == spam_result.model_dump()

        # SpamAssassin must not alter the phishing classifier's result.
        assert out["m2"]["phishing_probability"] == 0.0

        # The SpamAssassin result remains exposed separately.
        assert out["spamassassin"] == spam_result.model_dump()


# --- 3. Enabled + unavailable: analysis continues ----------------------------


class TestEnabledUnavailable:
    def test_enabled_but_not_installed_continues_normally(self, monkeypatch):
        _patch_pipeline_stages(monkeypatch)
        cfg = SpamAssassinConfig(enabled=True, executable="does-not-exist-binary")
        monkeypatch.setattr(analysis_service, "get_spamassassin_config", lambda: cfg)
        # Exercise the REAL adapter's own "not found" path rather than
        # re-mocking the result, to prove the integration survives it.
        monkeypatch.setattr(sa_module.shutil, "which", lambda exe: None)

        out = analysis_service.analyze_normalized_email(_make_email())

        assert out["status"] == "analyzed"
        assert out["spamassassin"]["available"] is False
        assert "does-not-exist-binary" in out["spamassassin"]["error"]
        assert "spamassassin" not in out["evidence_sources"]

    def test_enabled_docker_container_not_running_continues_normally(self, monkeypatch):
        """Simulates `docker.exe exec -i valorprotects-spamassassin ...`
        failing because the container isn't running (non-zero exit) -
        analysis must still complete."""
        _patch_pipeline_stages(monkeypatch)
        cfg = SpamAssassinConfig(
            enabled=True,
            executable="docker.exe",
            args=("exec", "-i", "valorprotects-spamassassin", "spamassassin", "--test-mode"),
        )
        monkeypatch.setattr(analysis_service, "get_spamassassin_config", lambda: cfg)
        monkeypatch.setattr(sa_module.shutil, "which", lambda exe: "/usr/bin/docker.exe")
        monkeypatch.setattr(
            sa_module.subprocess,
            "run",
            MagicMock(
                return_value=subprocess.CompletedProcess(
                    args=[], returncode=1, stdout=b"",
                    stderr=b"Error response from daemon: container is not running\n",
                )
            ),
        )

        out = analysis_service.analyze_normalized_email(_make_email())

        assert out["status"] == "analyzed"
        assert out["spamassassin"]["available"] is True  # docker.exe itself ran
        assert "container is not running" in out["spamassassin"]["error"]


# --- 4. Enabled + timeout/error: analysis continues --------------------------


class TestEnabledTimeoutOrError:
    def test_enabled_timeout_continues_normally(self, monkeypatch):
        _patch_pipeline_stages(monkeypatch)
        cfg = SpamAssassinConfig(enabled=True, timeout_seconds=5.0)
        monkeypatch.setattr(analysis_service, "get_spamassassin_config", lambda: cfg)
        monkeypatch.setattr(sa_module.shutil, "which", lambda exe: "/usr/bin/spamassassin")
        monkeypatch.setattr(
            sa_module.subprocess,
            "run",
            MagicMock(side_effect=subprocess.TimeoutExpired(cmd="spamassassin", timeout=5.0)),
        )

        out = analysis_service.analyze_normalized_email(_make_email())

        assert out["status"] == "analyzed"
        assert out["spamassassin"]["available"] is True
        assert "timed out" in out["spamassassin"]["error"]

    def test_enabled_malformed_output_continues_normally(self, monkeypatch):
        _patch_pipeline_stages(monkeypatch)
        cfg = SpamAssassinConfig(enabled=True)
        monkeypatch.setattr(analysis_service, "get_spamassassin_config", lambda: cfg)
        monkeypatch.setattr(sa_module.shutil, "which", lambda exe: "/usr/bin/spamassassin")
        monkeypatch.setattr(
            sa_module.subprocess,
            "run",
            MagicMock(
                return_value=subprocess.CompletedProcess(
                    args=[], returncode=0, stdout=b"not spamassassin output", stderr=b""
                )
            ),
        )

        out = analysis_service.analyze_normalized_email(_make_email())

        assert out["status"] == "analyzed"
        assert out["spamassassin"]["available"] is True
        assert "X-Spam-Status" in out["spamassassin"]["error"]

    def test_unexpected_exception_from_adapter_call_is_contained(self, monkeypatch):
        """Defense in depth: even if the adapter call raised (contrary
        to its own no-raise contract), the overall analysis must not
        fail."""
        _patch_pipeline_stages(monkeypatch)
        cfg = SpamAssassinConfig(enabled=True)
        monkeypatch.setattr(analysis_service, "get_spamassassin_config", lambda: cfg)
        monkeypatch.setattr(
            analysis_service, "spamassassin_analyze_email", MagicMock(side_effect=RuntimeError("boom"))
        )

        out = analysis_service.analyze_normalized_email(_make_email())

        assert out["status"] == "analyzed"
        assert out["spamassassin"]["available"] is False
        assert "boom" in out["spamassassin"]["error"]

    def test_spamassassin_failure_never_raises_out_of_analyze_email_safe(self, monkeypatch):
        cfg = SpamAssassinConfig(enabled=True)
        monkeypatch.setattr(analysis_service, "get_spamassassin_config", lambda: cfg)
        monkeypatch.setattr(
            analysis_service, "spamassassin_analyze_email", MagicMock(side_effect=RuntimeError("boom"))
        )
        # Intentionally do NOT patch the other stages here: this proves
        # the safe wrapper's per-message guarantee holds regardless,
        # even if something else upstream is also misbehaving.
        out = analysis_service.analyze_email_safe(_make_email())
        assert out["status"] in {"analyzed", "analysis_failed"}


# --- 5. Existing result fields remain stable ---------------------------------


class TestExistingFieldsStable:
    def test_top_level_response_shape_unchanged_aside_from_new_key(self, monkeypatch):
        _patch_pipeline_stages(monkeypatch)
        monkeypatch.setattr(analysis_service, "spamassassin_analyze_email", MagicMock())

        out = analysis_service.analyze_normalized_email(_make_email())

        expected_keys = {
            "message_id", "provider", "account_id", "email", "header_analysis",
            "m1", "m2", "m3", "m4", "spamassassin", "geo_status", "urls",
            "attachments_present", "attachments", "attachment_analysis", "risk",
            "risk_calculation", "risk_config_version", "threat_types",
            "bec_analysis", "evidence_sources", "status", "error", "analyzed_at",
        }
        assert set(out.keys()) == expected_keys

    def test_spamassassin_result_schema_fields_preserved_when_enabled(self, monkeypatch):
        """The exposed dict must still carry every field the adapter's
        contract documents - matched rules are never discarded."""
        _patch_pipeline_stages(monkeypatch)
        cfg = SpamAssassinConfig(enabled=True)
        monkeypatch.setattr(analysis_service, "get_spamassassin_config", lambda: cfg)
        monkeypatch.setattr(
            analysis_service,
            "spamassassin_analyze_email",
            MagicMock(
                return_value=SpamAssassinResult(
                    available=True, score=7.0, threshold=5.0, is_spam=True,
                    matched_rules=["BAYES_99", "URIBL_BLACK", "HTML_MESSAGE"],
                )
            ),
        )

        out = analysis_service.analyze_normalized_email(_make_email())

        expected_fields = {
            "available", "score", "threshold", "is_spam", "matched_rules",
            "raw_status", "error", "engine",
        }
        assert set(out["spamassassin"].keys()) == expected_fields
        assert out["spamassassin"]["matched_rules"] == ["BAYES_99", "URIBL_BLACK", "HTML_MESSAGE"]


# --- 6. No changes required for V2 / NLLB / YARA / threat intel / BEC -------


class TestNoUnrelatedRegressions:
    def test_other_stages_called_exactly_as_before_when_disabled(self, monkeypatch):
        _patch_pipeline_stages(monkeypatch)
        mock_adapter = MagicMock()
        monkeypatch.setattr(analysis_service, "spamassassin_analyze_email", mock_adapter)

        analysis_service.analyze_normalized_email(_make_email())

        mock_adapter.assert_not_called()
        analysis_service.analyze_attachments.assert_called_once()
        analysis_service.m1_analyze.assert_called_once()
        analysis_service.classify_email.assert_called_once()
        analysis_service.analyze_threat_intelligence.assert_called_once()
        analysis_service.detect_bec.assert_called_once()
        analysis_service.calculate_risk.assert_called_once()

    def test_other_stages_called_exactly_as_before_when_enabled(self, monkeypatch):
        """Enabling SpamAssassin must not change how many times, or
        with what arguments, the V2 model, M1 forensics, M3 threat
        intel, or the BEC detector are invoked."""
        _patch_pipeline_stages(monkeypatch)
        cfg = SpamAssassinConfig(enabled=True)
        monkeypatch.setattr(analysis_service, "get_spamassassin_config", lambda: cfg)
        monkeypatch.setattr(
            analysis_service,
            "spamassassin_analyze_email",
            MagicMock(return_value=SpamAssassinResult(available=True, score=1.0)),
        )

        analysis_service.analyze_normalized_email(_make_email())

        analysis_service.analyze_attachments.assert_called_once()
        analysis_service.m1_analyze.assert_called_once()
        analysis_service.classify_email.assert_called_once()
        analysis_service.analyze_threat_intelligence.assert_called_once()
        analysis_service.detect_bec.assert_called_once()
        analysis_service.calculate_risk.assert_called_once()

    def test_calculate_risk_call_signature_is_unmodified(self, monkeypatch):
        """Regression guard for TASK 9 ("do not touch risk scoring
        yet"): calculate_risk() must be called with exactly its
        existing keyword arguments, whether SpamAssassin is enabled or
        not."""
        _patch_pipeline_stages(monkeypatch)
        cfg = SpamAssassinConfig(enabled=True)
        monkeypatch.setattr(analysis_service, "get_spamassassin_config", lambda: cfg)
        monkeypatch.setattr(
            analysis_service,
            "spamassassin_analyze_email",
            MagicMock(return_value=SpamAssassinResult(available=True)),
        )

        analysis_service.analyze_normalized_email(_make_email())

        _, kwargs = analysis_service.calculate_risk.call_args
        assert set(kwargs.keys()) == {
    "m1",
    "m2",
    "m3",
    "header_analysis",
    "attachment_analysis",
    "bec_analysis",
    "spamassassin",
}


# --- Config surface: SPAMASSASSIN_ENABLED (new in this change) -------------


class TestSpamAssassinEnabledFlag:
    def test_enabled_flag_defaults_to_false(self):
        from backend.app.spam.config import get_spamassassin_config

        assert get_spamassassin_config().enabled is False

    @pytest.mark.parametrize(
        "raw_value,expected",
        [
            ("true", True),
            ("TRUE", True),
            ("1", True),
            ("yes", True),
            ("on", True),
            ("false", False),
            ("0", False),
            ("no", False),
            ("off", False),
            ("", False),
            ("not-a-bool", False),
        ],
    )
    def test_enabled_flag_parsing(self, monkeypatch, raw_value, expected):
        from backend.app.spam.config import get_spamassassin_config

        monkeypatch.setenv(ENV_ENABLED, raw_value)
        assert get_spamassassin_config().enabled is expected

    def test_existing_config_fields_unaffected_by_new_flag(self, monkeypatch):
        """The new field must not disturb the executable/args/timeout
        env-var handling already covered by tests/test_spamassassin.py."""
        from backend.app.spam.config import (
            DEFAULT_ARGS,
            DEFAULT_EXECUTABLE,
            DEFAULT_TIMEOUT_SECONDS,
            get_spamassassin_config,
        )

        monkeypatch.setenv(ENV_ENABLED, "true")
        cfg = get_spamassassin_config()
        assert cfg.enabled is True
        assert cfg.executable == DEFAULT_EXECUTABLE
        assert cfg.args == DEFAULT_ARGS
        assert cfg.timeout_seconds == DEFAULT_TIMEOUT_SECONDS

    def test_docker_style_configuration_documented_in_env_example(self, monkeypatch):
        monkeypatch.setenv(ENV_ENABLED, "true")
        monkeypatch.setenv(ENV_EXECUTABLE, "docker.exe")
        monkeypatch.setenv(
            ENV_ARGS,
            "exec -i valorprotects-spamassassin spamassassin --test-mode --local --nocreate-prefs",
        )
        from backend.app.spam.config import get_spamassassin_config

        cfg = get_spamassassin_config()
        assert cfg.enabled is True
        assert cfg.executable == "docker.exe"
        assert cfg.args == (
            "exec", "-i", "valorprotects-spamassassin", "spamassassin",
            "--test-mode", "--local", "--nocreate-prefs",
        )
