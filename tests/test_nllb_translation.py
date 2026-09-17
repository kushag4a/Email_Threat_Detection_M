"""
Tests for the NLLB multilingual translation prototype.

ALL tests in this file are fully mocked: the 600M NLLB model is NEVER
downloaded or loaded during a normal pytest run.  Only the four public
states of TranslationStatus and the utility functions are exercised.

Mocking strategy
----------------
* For tests that reach the inference path (TRANSLATED / TRANSLATION_FAILED):
    1. `_reset_singleton()` clears the module globals before each test.
    2. `_ensure_loaded` is patched to a no-op so the model is never loaded.
    3. `_run_inference` is patched to return a controlled string (or raise).
  This means torch and transformers are never imported by these tests.

* For English bypass and unsupported-language tests: no patching is needed
  at all because translate() returns before calling _ensure_loaded().

* For URL/email preservation: tested directly against the utility layer
  (mask_technical_tokens + restore_technical_tokens) without going through
  the translator singleton.

Test matrix
-----------
test_english_bypass                 ENGLISH_BYPASS state, no model load
test_unsupported_language_french    UNSUPPORTED_LANGUAGE (fra_Latn)
test_unsupported_language_german    UNSUPPORTED_LANGUAGE (deu_Latn)
test_hindi_translation              TRANSLATED, success=True
test_telugu_translation             TRANSLATED, correct lang tag / name
test_tamil_translation              TRANSLATED, correct lang tag / name
test_translation_failure            TRANSLATION_FAILED when _run_inference raises
test_long_input_truncation          Long text -> does not crash, returns valid result
test_url_preserved_in_mask_restore  URL survives mask -> (identity) restore cycle
test_email_preserved_in_mask_restore Email address survives mask -> restore
"""
from __future__ import annotations

import pytest
from unittest.mock import MagicMock, patch

import backend.app.multilingual.nllb_translator as _translator_mod
from backend.app.multilingual.nllb_translator import (
    TranslationStatus,
    _reset_singleton,
    translate,
)
from backend.app.multilingual.language_codes import ENGLISH_TAG
from backend.app.multilingual.utils import mask_technical_tokens, restore_technical_tokens


# ---------------------------------------------------------------------------
# Fixtures
# ---------------------------------------------------------------------------

@pytest.fixture(autouse=True)
def reset_singleton_state():
    """
    Reset the module-level singleton globals before and after every test.
    This ensures no test leaks model state into the next one.
    """
    _reset_singleton()
    yield
    _reset_singleton()


# ---------------------------------------------------------------------------
# Helper
# ---------------------------------------------------------------------------

def _make_translate_patches(translated_text: str = "Mocked English output"):
    """
    Return a pair of patch context managers:
        patch(_ensure_loaded)  ->  no-op
        patch(_run_inference)  ->  returns translated_text
    Use as:
        with _make_translate_patches() as (mock_load, mock_infer):
            ...
    """
    import contextlib

    @contextlib.contextmanager
    def _cm():
        with patch(
            "backend.app.multilingual.nllb_translator._ensure_loaded"
        ) as mock_load, patch(
            "backend.app.multilingual.nllb_translator._run_inference",
            return_value=translated_text,
        ) as mock_infer:
            yield mock_load, mock_infer

    return _cm()


# ---------------------------------------------------------------------------
# Test 1: English bypass
# ---------------------------------------------------------------------------

class TestEnglishBypass:
    def test_english_bypass_status(self):
        result = translate("Hello world", src_lang=ENGLISH_TAG)
        assert result.status == TranslationStatus.ENGLISH_BYPASS

    def test_english_bypass_fields(self):
        result = translate("Hello world", src_lang=ENGLISH_TAG)
        assert result.bypassed is True
        assert result.success is False
        assert result.translated_text is None
        assert result.error is None
        assert result.src_lang == ENGLISH_TAG
        assert result.src_lang_name == "English"

    def test_english_bypass_preserves_source_text(self):
        original = "Verify your identity at https://example.com"
        result = translate(original, src_lang=ENGLISH_TAG)
        assert result.source_text == original

    def test_english_bypass_never_loads_model(self):
        """The singleton must remain None after an English bypass."""
        translate("Hello", src_lang=ENGLISH_TAG)
        assert _translator_mod._tokenizer is None
        assert _translator_mod._model is None


# ---------------------------------------------------------------------------
# Test 2: Unsupported language
# ---------------------------------------------------------------------------

class TestUnsupportedLanguage:
    def test_french_is_unsupported(self):
        result = translate("Bonjour", src_lang="fra_Latn")
        assert result.status == TranslationStatus.UNSUPPORTED_LANGUAGE
        assert result.success is False
        assert result.bypassed is False
        assert result.translated_text is None
        assert result.src_lang_name is None
        assert "fra_Latn" in (result.error or "")

    def test_german_is_unsupported(self):
        result = translate("Guten Tag", src_lang="deu_Latn")
        assert result.status == TranslationStatus.UNSUPPORTED_LANGUAGE

    def test_unsupported_never_loads_model(self):
        translate("Bonjour", src_lang="fra_Latn")
        assert _translator_mod._tokenizer is None
        assert _translator_mod._model is None

    def test_unsupported_preserves_source_text(self):
        text = "Bonjour, comment allez-vous?"
        result = translate(text, src_lang="fra_Latn")
        assert result.source_text == text


# ---------------------------------------------------------------------------
# Test 3: Hindi translation (TRANSLATED state)
# ---------------------------------------------------------------------------

class TestHindiTranslation:
    def test_hindi_success(self):
        hindi_text = "आपका खाता लॉक हो गया है"
        expected_en = "Your account has been locked"

        with _make_translate_patches(expected_en) as (mock_load, mock_infer):
            result = translate(hindi_text, src_lang="hin_Deva")

        assert result.status == TranslationStatus.TRANSLATED
        assert result.success is True
        assert result.bypassed is False
        assert result.translated_text == expected_en
        assert result.src_lang == "hin_Deva"
        assert result.src_lang_name == "Hindi"
        assert result.error is None
        assert result.source_text == hindi_text

    def test_hindi_ensure_loaded_called(self):
        with _make_translate_patches() as (mock_load, _):
            translate("आपका खाता", src_lang="hin_Deva")
        mock_load.assert_called_once()

    def test_hindi_run_inference_called(self):
        with _make_translate_patches() as (_, mock_infer):
            translate("आपका खाता", src_lang="hin_Deva")
        mock_infer.assert_called_once()

    def test_hindi_model_version_reported(self):
        with _make_translate_patches():
            result = translate("आपका खाता", src_lang="hin_Deva")
        assert "nllb" in result.model_version.lower()
        assert result.model_name == "facebook/nllb-200-distilled-600M"


# ---------------------------------------------------------------------------
# Test 4: Telugu translation
# ---------------------------------------------------------------------------

class TestTeluguTranslation:
    def test_telugu_success(self):
        telugu_text = "మీ ఖాతా నిలిపివేయబడింది"
        expected_en = "Your account has been suspended"

        with _make_translate_patches(expected_en):
            result = translate(telugu_text, src_lang="tel_Telu")

        assert result.status == TranslationStatus.TRANSLATED
        assert result.success is True
        assert result.src_lang == "tel_Telu"
        assert result.src_lang_name == "Telugu"
        assert result.translated_text == expected_en


# ---------------------------------------------------------------------------
# Test 5: Tamil translation
# ---------------------------------------------------------------------------

class TestTamilTranslation:
    def test_tamil_success(self):
        tamil_text = "உங்கள் கணக்கு இடைநிறுத்தப்பட்டுள்ளது"
        expected_en = "Your account has been suspended"

        with _make_translate_patches(expected_en):
            result = translate(tamil_text, src_lang="tam_Taml")

        assert result.status == TranslationStatus.TRANSLATED
        assert result.src_lang == "tam_Taml"
        assert result.src_lang_name == "Tamil"
        assert result.translated_text == expected_en


# ---------------------------------------------------------------------------
# Test 6: Translation failure
# ---------------------------------------------------------------------------

class TestTranslationFailure:
    def test_runtime_error_returns_structured_failure(self):
        with patch(
            "backend.app.multilingual.nllb_translator._ensure_loaded"
        ), patch(
            "backend.app.multilingual.nllb_translator._run_inference",
            side_effect=RuntimeError("CUDA out of memory"),
        ):
            result = translate("आपका खाता", src_lang="hin_Deva")

        assert result.status == TranslationStatus.TRANSLATION_FAILED
        assert result.success is False
        assert result.bypassed is False
        assert result.translated_text is None
        assert "CUDA out of memory" in (result.error or "")

    def test_failure_does_not_raise(self):
        """translate() must NEVER propagate an exception."""
        with patch(
            "backend.app.multilingual.nllb_translator._ensure_loaded"
        ), patch(
            "backend.app.multilingual.nllb_translator._run_inference",
            side_effect=Exception("Unexpected kaboom"),
        ):
            # Must not raise
            result = translate("మీ ఖాతా", src_lang="tel_Telu")

        assert result.status == TranslationStatus.TRANSLATION_FAILED

    def test_failure_preserves_source_text(self):
        original = "আপনার অ্যাকাউন্ট"
        with patch(
            "backend.app.multilingual.nllb_translator._ensure_loaded"
        ), patch(
            "backend.app.multilingual.nllb_translator._run_inference",
            side_effect=ValueError("tokenizer error"),
        ):
            result = translate(original, src_lang="ben_Beng")

        assert result.source_text == original


# ---------------------------------------------------------------------------
# Test 7: Long-input truncation
# ---------------------------------------------------------------------------

class TestLongInputTruncation:
    def test_very_long_input_does_not_crash(self):
        """
        A 3000-character input should not crash -- the tokenizer truncation
        (max_length=512, truncation=True in _run_inference) handles it.
        We patch _run_inference so no actual tokenizer is needed.
        """
        long_text = "आपका खाता संदिग्ध " * 200  # ~3000 chars
        assert len(long_text) > 2000

        with _make_translate_patches("Account is suspicious"):
            result = translate(long_text, src_lang="hin_Deva")

        assert result.status == TranslationStatus.TRANSLATED
        assert result.success is True
        assert result.source_text == long_text  # original always preserved

    def test_long_input_source_text_unchanged(self):
        """Source text in the result must equal what was passed in, even if truncated internally."""
        long_text = "ਤੁਹਾਡੇ ਖਾਤੇ ਵਿੱਚ " * 300
        with _make_translate_patches("Suspicious activity"):
            result = translate(long_text, src_lang="pan_Guru")
        assert result.source_text == long_text


# ---------------------------------------------------------------------------
# Test 8: URL / email preservation (utils layer)
# ---------------------------------------------------------------------------

class TestTechnicalTokenPreservation:
    def test_url_survives_mask_restore_roundtrip(self):
        text = "Please verify at https://secure.bank.example.com/verify?token=abc123"
        masked = mask_technical_tokens(text)
        # The URL should have been replaced
        assert "https://secure.bank.example.com" not in masked.text
        assert "\u27E8URL_0\u27E9" in masked.text
        # Restoration should bring it back
        restored = restore_technical_tokens(masked.text, masked.restoration_map)
        assert "https://secure.bank.example.com/verify?token=abc123" in restored

    def test_email_survives_mask_restore_roundtrip(self):
        text = "Contact attacker@evil-domain.com immediately."
        masked = mask_technical_tokens(text)
        assert "attacker@evil-domain.com" not in masked.text
        restored = restore_technical_tokens(masked.text, masked.restoration_map)
        assert "attacker@evil-domain.com" in restored

    def test_multiple_urls_all_preserved(self):
        text = (
            "Visit https://example.com/login and http://evil.net/phish for details. "
            "Also see ftp://files.example.com/malware.exe"
        )
        masked = mask_technical_tokens(text)
        restored = restore_technical_tokens(masked.text, masked.restoration_map)
        assert "https://example.com/login" in restored
        assert "http://evil.net/phish" in restored
        assert "ftp://files.example.com/malware.exe" in restored

    def test_plain_text_unchanged_after_roundtrip(self):
        text = "No technical tokens here just plain words"
        masked = mask_technical_tokens(text)
        restored = restore_technical_tokens(masked.text, masked.restoration_map)
        assert restored == text

    def test_url_masked_before_translation_integration(self):
        """
        In the full translate() flow, URLs embedded in Indic text survive
        the mask -> (mocked) translate -> restore cycle.
        """
        text = "कृपया https://evil.com/verify पर जाएं"
        expected_inner = "please go to \u27E8URL_0\u27E9"   # what mock returns

        with _make_translate_patches(expected_inner):
            result = translate(text, src_lang="hin_Deva")

        assert result.status == TranslationStatus.TRANSLATED
        # The URL placeholder in the mock output should be restored
        assert "https://evil.com/verify" in (result.translated_text or "")
        # Original is never modified
        assert result.source_text == text


# ---------------------------------------------------------------------------
# Test: TranslationResult.to_dict() contract
# ---------------------------------------------------------------------------

class TestTranslationResultContract:
    def test_to_dict_contains_all_required_keys(self):
        result = translate("Hello", src_lang=ENGLISH_TAG)
        d = result.to_dict()
        required_keys = {
            "status", "src_lang", "src_lang_name", "source_text",
            "translated_text", "success", "bypassed", "model_name",
            "model_version", "error",
        }
        assert required_keys <= set(d.keys())

    def test_to_dict_status_is_string(self):
        result = translate("Bonjour", src_lang="fra_Latn")
        assert isinstance(result.to_dict()["status"], str)

    def test_four_states_are_distinct(self):
        """Sanity: all four status values are distinct strings."""
        statuses = {s.value for s in TranslationStatus}
        assert len(statuses) == 4


# ---------------------------------------------------------------------------
# Test: generation parameter contract (_run_inference level)
#
# These tests call _run_inference() directly rather than translate(), so
# they can inspect model.generate()'s exact call_args without going through
# the full translate() wrapper.
#
# transformers is already installed (it is in requirements.txt) so importing
# GenerationConfig here does NOT download or load the 600M model.
# ---------------------------------------------------------------------------

class TestGenerationParameters:
    """
    Verify that _run_inference() calls model.generate() with max_new_tokens as
    a direct kwarg and that max_length is NOT passed to generate() at all.

    Root-cause fix summary
    ----------------------
    The NLLB model's generation_config.json sets max_length=200.  When
    model.generate() merges the model's own generation_config with any kwargs,
    it drops None values, so passing max_length=None externally does NOT
    suppress the model's 200.  The definitive fix clears max_length on the
    model's own generation_config object immediately after loading (in
    _load_model), so it can never be reintroduced through the merge.
    _run_inference() then passes max_new_tokens as a direct kwarg -- clean and
    free of the conflict.
    """

    @pytest.fixture(autouse=True)
    def inject_mocks(self):
        """
        Populate the translator module's singleton globals with MagicMocks.
        This satisfies _run_inference's precondition that _ensure_loaded()
        has already been called, without actually loading the model.
        """
        import torch
        mock_tok = MagicMock(name="tokenizer")
        mock_inputs = MagicMock(name="inputs")
        mock_inputs.to.return_value = mock_inputs  # .to(device) returns self
        mock_tok.return_value = mock_inputs
        mock_tok.convert_tokens_to_ids.return_value = 256047  # eng_Latn id
        mock_tok.batch_decode.return_value = ["Hello world"]

        mock_model = MagicMock(name="model")
        mock_model.generate.return_value = MagicMock(name="tokens")

        _translator_mod._tokenizer = mock_tok
        _translator_mod._model = mock_model
        _translator_mod._device = torch.device("cpu")

        self.mock_tok = mock_tok
        self.mock_model = mock_model
        yield
        # reset_singleton_state fixture (autouse, function scope) handles teardown

    def _call_run_inference(self) -> None:
        from backend.app.multilingual.nllb_translator import _run_inference
        _run_inference("आपका खाता लॉक है", "hin_Deva")

    def test_generate_called(self):
        """model.generate() must be called exactly once per _run_inference() call."""
        self._call_run_inference()
        self.mock_model.generate.assert_called_once()

    def test_generate_has_max_new_tokens_kwarg(self):
        """max_new_tokens must appear as a direct kwarg to generate()."""
        from backend.app.multilingual.config import MAX_OUTPUT_TOKENS
        self._call_run_inference()
        call_kwargs = self.mock_model.generate.call_args.kwargs
        assert "max_new_tokens" in call_kwargs, (
            "model.generate() must receive max_new_tokens= as a direct kwarg"
        )
        assert call_kwargs["max_new_tokens"] == MAX_OUTPUT_TOKENS, (
            f"Expected max_new_tokens={MAX_OUTPUT_TOKENS}, "
            f"got {call_kwargs['max_new_tokens']}"
        )

    def test_generate_has_no_max_length_kwarg(self):
        """
        max_length must NOT appear as a kwarg to generate().

        The conflict prevention is done by clearing _model.generation_config.max_length
        in _load_model(), not by passing max_length here.  Passing max_length here
        would re-introduce the conflict for callers that inspect both.
        """
        self._call_run_inference()
        call_kwargs = self.mock_model.generate.call_args.kwargs
        assert "max_length" not in call_kwargs, (
            "max_length must not appear as a kwarg to model.generate(); "
            "it is suppressed at the model's generation_config level in _load_model()."
        )

    def test_generate_has_forced_bos_token_id(self):
        """forced_bos_token_id must be passed so the model decodes to English."""
        self._call_run_inference()
        call_kwargs = self.mock_model.generate.call_args.kwargs
        assert "forced_bos_token_id" in call_kwargs, (
            "model.generate() must receive forced_bos_token_id= to select English output"
        )
        assert call_kwargs["forced_bos_token_id"] == 256047

    def test_load_model_clears_generation_config_max_length(self):
        """
        _load_model() must set model.generation_config.max_length = None after
        loading the model.

        This is the definitive fix for the "Both max_new_tokens and max_length
        are set" warning: the model's saved generation_config.json has
        max_length=200, and transformers' merge algorithm drops None values from
        passed kwargs/GenerationConfig objects, so clearing the conflict at its
        source (the model object itself) is the only reliable approach.
        """
        import torch
        from types import SimpleNamespace

        mock_tok = MagicMock(name="tok")
        mock_model = MagicMock(name="model")
        # generation_config must be a real SimpleNamespace so attribute assignment works
        # (MagicMock silently swallows attribute sets without storing them)
        mock_model.generation_config = SimpleNamespace(max_length=200)
        mock_model.to.return_value = mock_model

        import backend.app.multilingual.nllb_translator as tm
        # AutoTokenizer and AutoModelForSeq2SeqLM are locally imported inside
        # _load_model via `from transformers import ...`, so patch at the source.
        with patch("transformers.AutoTokenizer") as mt, \
             patch("transformers.AutoModelForSeq2SeqLM") as mm, \
             patch("backend.app.multilingual.nllb_translator._resolve_device",
                   return_value=torch.device("cpu")):
            mt.from_pretrained.return_value = mock_tok
            mm.from_pretrained.return_value = mock_model
            tm._tokenizer = None
            tm._model = None
            tm._device = None

            from backend.app.multilingual.nllb_translator import _load_model
            _load_model()

        assert mock_model.generation_config.max_length is None, (
            "_load_model() must clear model.generation_config.max_length to None "
            "so the model's saved max_length=200 cannot conflict with max_new_tokens "
            "during generate()."
        )


# ---------------------------------------------------------------------------
# Test: device resolution (_resolve_device)
#
# _resolve_device() is a module-level helper so we can test it directly by
# patching backend.app.multilingual.nllb_translator.DEVICE_MODE and
# torch.cuda.is_available.  No model is loaded; no GPU is needed.
# ---------------------------------------------------------------------------

class TestDeviceResolution:
    """
    Verify _resolve_device() honours DEVICE_MODE for all three modes.

    All three modes are tested against both cuda-available and cuda-absent
    environments by patching torch.cuda.is_available in the translator module.
    """

    def _resolve(self, device_mode: str, cuda_available: bool) -> "torch.device":
        """Patch DEVICE_MODE and cuda availability, then call _resolve_device()."""
        import backend.app.multilingual.nllb_translator as tm
        from backend.app.multilingual.nllb_translator import _resolve_device

        # _resolve_device() does `import torch` locally, so we patch
        # torch.cuda.is_available at the real torch module level.
        with patch.object(tm, "DEVICE_MODE", device_mode), \
             patch("torch.cuda.is_available", return_value=cuda_available):
            return _resolve_device()

    # --- auto mode ---

    def test_auto_cuda_available_returns_cuda(self):
        result = self._resolve("auto", cuda_available=True)
        assert result.type == "cuda"

    def test_auto_cuda_unavailable_returns_cpu(self):
        result = self._resolve("auto", cuda_available=False)
        assert result.type == "cpu"

    # --- cpu mode ---

    def test_cpu_mode_returns_cpu_when_cuda_available(self):
        """cpu mode must ignore CUDA availability entirely."""
        result = self._resolve("cpu", cuda_available=True)
        assert result.type == "cpu"

    def test_cpu_mode_returns_cpu_when_cuda_unavailable(self):
        result = self._resolve("cpu", cuda_available=False)
        assert result.type == "cpu"

    # --- cuda mode ---

    def test_cuda_mode_returns_cuda_when_available(self):
        result = self._resolve("cuda", cuda_available=True)
        assert result.type == "cuda"

    def test_cuda_mode_raises_when_unavailable(self):
        """
        Requesting cuda when CUDA is absent must raise RuntimeError with a
        clear message, not silently fall back to CPU.
        """
        import pytest
        with pytest.raises(RuntimeError, match="torch.cuda.is_available\\(\\) returned False"):
            self._resolve("cuda", cuda_available=False)

    def test_cuda_failure_surfaces_as_translation_failed(self):
        """
        When DEVICE_MODE=cuda and CUDA is absent, translate() must return
        TRANSLATION_FAILED (not raise) because the RuntimeError from
        _resolve_device() is caught by translate()'s except clause.
        """
        import backend.app.multilingual.nllb_translator as tm

        with patch.object(tm, "DEVICE_MODE", "cuda"), \
             patch("backend.app.multilingual.nllb_translator._ensure_loaded",
                   side_effect=RuntimeError(
                       "NLLB_MODEL_DEVICE=cuda was requested but "
                       "torch.cuda.is_available() returned False."
                   )):
            result = translate("आपका खाता", src_lang="hin_Deva")

        assert result.status == TranslationStatus.TRANSLATION_FAILED
        assert result.success is False
        assert "cuda" in (result.error or "").lower()


# ---------------------------------------------------------------------------
# Test: load_nllb_env() convention
# ---------------------------------------------------------------------------

class TestEnvLoading:
    """
    Verify the load_nllb_env() helper:
      - Is a no-op when python-dotenv is absent (ImportError path).
      - Calls load_dotenv() with the correct .env path when dotenv is present.
      - Passes override=False so existing env vars are never overwritten.
    """

    def test_load_nllb_env_is_noop_without_dotenv(self):
        """If dotenv import fails, load_nllb_env() must not raise."""
        import builtins
        real_import = builtins.__import__

        def _blocking_import(name, *args, **kwargs):
            if name == "dotenv":
                raise ImportError("dotenv not installed")
            return real_import(name, *args, **kwargs)

        with patch.object(builtins, "__import__", side_effect=_blocking_import):
            from backend.app.multilingual.config import load_nllb_env
            # Must not raise
            load_nllb_env()

    def test_load_nllb_env_calls_load_dotenv_with_correct_path(self, tmp_path):
        """load_nllb_env() must call load_dotenv(dotenv_path=<project>/.env, override=False)."""
        from backend.app.multilingual.config import load_nllb_env, _PROJECT_ROOT

        # load_dotenv is imported inside load_nllb_env(), so patch it at its
        # source module (dotenv) rather than as a config attribute.
        with patch("dotenv.load_dotenv") as mock_ld, \
             patch("pathlib.Path.exists", return_value=True):
            load_nllb_env()

        mock_ld.assert_called_once()
        call_kwargs = mock_ld.call_args.kwargs
        assert call_kwargs.get("override") is False, (
            "load_dotenv must use override=False so existing env vars are not overwritten"
        )
        assert "dotenv_path" in call_kwargs

    def test_load_nllb_env_skips_dotenv_when_env_absent(self):
        """load_nllb_env() must not call load_dotenv() when .env does not exist."""
        with patch("dotenv.load_dotenv") as mock_ld, \
             patch("pathlib.Path.exists", return_value=False):
            from backend.app.multilingual.config import load_nllb_env
            load_nllb_env()

        mock_ld.assert_not_called()

