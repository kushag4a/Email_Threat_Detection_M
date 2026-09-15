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
    Verify that _run_inference() uses GenerationConfig with max_new_tokens
    as the sole output bound, and that max_length is never simultaneously set.

    Motivation: the NLLB model ships with a generation_config.json that sets
    max_length (typically 200). Transformers >= 4.38 raises a ValueError when
    both max_new_tokens and a non-None max_length are in the effective config.
    The fix routes both generation params through an explicit GenerationConfig
    where max_length is left None, fully superseding the model default.
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

    def test_generate_receives_generation_config(self):
        """generate() must be called with a generation_config kwarg."""
        self._call_run_inference()
        call_kwargs = self.mock_model.generate.call_args.kwargs
        assert "generation_config" in call_kwargs, (
            "model.generate() must receive a generation_config= argument; "
            "bare max_new_tokens= is no longer acceptable."
        )

    def test_generation_config_has_max_new_tokens(self):
        """GenerationConfig.max_new_tokens must equal MAX_OUTPUT_TOKENS."""
        from backend.app.multilingual.config import MAX_OUTPUT_TOKENS
        self._call_run_inference()
        gen_cfg = self.mock_model.generate.call_args.kwargs["generation_config"]
        assert gen_cfg.max_new_tokens == MAX_OUTPUT_TOKENS, (
            f"Expected max_new_tokens={MAX_OUTPUT_TOKENS}, "
            f"got {gen_cfg.max_new_tokens}"
        )

    def test_generation_config_max_length_is_none(self):
        """
        GenerationConfig.max_length must be None.

        A non-None max_length alongside max_new_tokens triggers the conflict
        that this fix addresses (transformers >= 4.38 ValueError).
        """
        self._call_run_inference()
        gen_cfg = self.mock_model.generate.call_args.kwargs["generation_config"]
        assert gen_cfg.max_length is None, (
            f"GenerationConfig.max_length must be None (not {gen_cfg.max_length!r}); "
            "setting it would conflict with max_new_tokens in transformers >= 4.38."
        )

    def test_generate_has_no_raw_max_length_kwarg(self):
        """
        max_length must not be passed as a bare kwarg to generate().

        It must only be set on the tokenizer call (for input truncation),
        never on the generation call.
        """
        self._call_run_inference()
        call_kwargs = self.mock_model.generate.call_args.kwargs
        assert "max_length" not in call_kwargs, (
            "max_length must not appear as a direct kwarg to model.generate(); "
            "it belongs only on the tokenizer call."
        )

    def test_generate_has_no_raw_max_new_tokens_kwarg(self):
        """
        max_new_tokens must not be passed as a bare kwarg to generate() either.

        It must live inside GenerationConfig, not alongside it, to avoid a
        second form of the same conflict.
        """
        self._call_run_inference()
        call_kwargs = self.mock_model.generate.call_args.kwargs
        assert "max_new_tokens" not in call_kwargs, (
            "max_new_tokens must not appear as a bare kwarg to generate(); "
            "it must be set on GenerationConfig instead."
        )

