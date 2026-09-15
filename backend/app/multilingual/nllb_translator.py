"""
NLLB-200 translation singleton.

Key design decisions
--------------------
Lazy singleton
    The model and tokenizer are loaded once on the first translate() call that
    actually needs them.  A threading.Lock ensures concurrent callers from
    different threads never trigger a parallel download.

Four mutually exclusive states
    TranslationStatus.ENGLISH_BYPASS        src_lang == eng_Latn -> skipped
    TranslationStatus.TRANSLATED            Indic -> English succeeded
    TranslationStatus.UNSUPPORTED_LANGUAGE  lang tag not in SUPPORTED_LANGUAGES
    TranslationStatus.TRANSLATION_FAILED    model loaded but inference raised

Safe inference helper
    _run_inference() is isolated from translate() so unit tests can patch it
    without needing torch installed or the model downloaded.

Input/output bounds
    Tokenizer is called with truncation=True, max_length=MAX_INPUT_TOKENS.
    Model generation is bounded by max_new_tokens=MAX_OUTPUT_TOKENS.

Device selection
    GPU when torch.cuda.is_available(), CPU otherwise.
    Never hardcodes a device string.

Fail-safe contract
    translate() NEVER raises.  Any exception is caught and returned as a
    structured TranslationResult with status=TRANSLATION_FAILED.

Technical tokens
    URLs, email addresses, hashes, and filenames are masked before
    translation and restored afterwards.  See utils.py.

Production isolation
    THIS MODULE MUST NEVER BE IMPORTED FROM:
        analysis_service.py, scan_service.py, risk_engine.py,
        ml_classifier.py, or any other existing production module.
"""
from __future__ import annotations

import logging
import threading
from dataclasses import dataclass
from enum import Enum

from backend.app.multilingual.config import (
    CACHE_DIR,
    ENABLED,
    MAX_INPUT_TOKENS,
    MAX_OUTPUT_TOKENS,
    MODEL_NAME,
    MODEL_VERSION,
)
from backend.app.multilingual.language_codes import ENGLISH_TAG, SUPPORTED_LANGUAGES
from backend.app.multilingual.utils import mask_technical_tokens, restore_technical_tokens

logger = logging.getLogger("email_threat_platform.multilingual")


# ---------------------------------------------------------------------------
# TranslationStatus
# ---------------------------------------------------------------------------

class TranslationStatus(str, Enum):
    """
    Mutually exclusive outcome states for a single translate() call.

    ENGLISH_BYPASS
        The caller supplied src_lang=eng_Latn.  The model was never loaded.
        translated_text is None.  bypassed=True.

    TRANSLATED
        A supported Indic language was successfully translated to English.
        translated_text contains the English output.  success=True.

    UNSUPPORTED_LANGUAGE
        The caller supplied a language tag that is neither eng_Latn nor in
        SUPPORTED_LANGUAGES (e.g. fra_Latn, deu_Latn).  The model was never
        loaded.  translated_text is None.  error describes the unknown tag.

    TRANSLATION_FAILED
        A supported language was requested but model loading or inference
        raised an exception.  translated_text is None.  error contains the
        exception message.
    """
    ENGLISH_BYPASS       = "english_bypass"
    TRANSLATED           = "translated"
    UNSUPPORTED_LANGUAGE = "unsupported_language"
    TRANSLATION_FAILED   = "translation_failed"


# ---------------------------------------------------------------------------
# TranslationResult
# ---------------------------------------------------------------------------

@dataclass(frozen=True)
class TranslationResult:
    """
    Immutable result returned by translate().

    Fields
    ------
    status          : TranslationStatus enum value (exactly one of four states)
    src_lang        : NLLB BCP-47 tag supplied by the caller
    src_lang_name   : Human-readable name from SUPPORTED_LANGUAGES, or None
                      when the language is English or unsupported
    source_text     : Original text -- ALWAYS preserved, never overwritten
    translated_text : English output (None when bypassed / unsupported / failed)
    success         : True only when status == TRANSLATED
    bypassed        : True only when status == ENGLISH_BYPASS
    model_name      : Full HuggingFace model ID
    model_version   : Short version string (last path component of model_name)
    error           : Exception message when status == TRANSLATION_FAILED,
                      or description of why the language is unsupported;
                      None for ENGLISH_BYPASS and TRANSLATED
    """
    status: TranslationStatus
    src_lang: str
    src_lang_name: str | None
    source_text: str
    translated_text: str | None
    success: bool
    bypassed: bool
    model_name: str
    model_version: str
    error: str | None = None

    def to_dict(self) -> dict:
        return {
            "status": self.status.value,
            "src_lang": self.src_lang,
            "src_lang_name": self.src_lang_name,
            "source_text": self.source_text,
            "translated_text": self.translated_text,
            "success": self.success,
            "bypassed": self.bypassed,
            "model_name": self.model_name,
            "model_version": self.model_version,
            "error": self.error,
        }


# ---------------------------------------------------------------------------
# Singleton internals
# ---------------------------------------------------------------------------

_lock = threading.Lock()
_tokenizer = None
_model = None
_device = None


def _load_model() -> None:
    """
    Download (first time) or load from cache the tokenizer and model.
    Called once under _lock.  Sets module-level _tokenizer, _model, _device.
    """
    global _tokenizer, _model, _device  # noqa: PLW0603

    import torch
    from transformers import AutoModelForSeq2SeqLM, AutoTokenizer

    _device = torch.device("cuda" if torch.cuda.is_available() else "cpu")
    logger.info(
        "NLLB: loading tokenizer  model=%s  cache=%s", MODEL_NAME, CACHE_DIR
    )
    _tokenizer = AutoTokenizer.from_pretrained(MODEL_NAME, cache_dir=CACHE_DIR)
    logger.info("NLLB: loading model  device=%s", _device)
    _model = AutoModelForSeq2SeqLM.from_pretrained(MODEL_NAME, cache_dir=CACHE_DIR)
    _model = _model.to(_device)
    _model.eval()
    logger.info("NLLB: model ready")


def _ensure_loaded() -> None:
    """Guarantee _tokenizer and _model are populated; load once if not."""
    if _tokenizer is not None and _model is not None:
        return
    with _lock:
        if _tokenizer is None or _model is None:
            _load_model()


def _reset_singleton() -> None:
    """
    Reset the singleton globals to None.

    TEST HELPER ONLY -- not part of the public production API.
    Allows each unit test to start with a clean slate.
    """
    global _tokenizer, _model, _device  # noqa: PLW0603
    _tokenizer = None
    _model = None
    _device = None


# ---------------------------------------------------------------------------
# Inference helper (separated for testability)
# ---------------------------------------------------------------------------

def _run_inference(masked_text: str, src_lang: str) -> str:
    """
    Tokenize *masked_text*, run NLLB generation, and decode the result.

    This is a module-level function so tests can patch it with
        patch("backend.app.multilingual.nllb_translator._run_inference", return_value="...")
    without needing torch installed or the 600M model present.

    Generation bound
    ----------------
    Output length is controlled exclusively by MAX_OUTPUT_TOKENS via
    GenerationConfig.max_new_tokens.  max_length is explicitly left None so
    the model's bundled generation_config.json default (typically 200 for
    NLLB) is fully superseded.  Passing both max_new_tokens and a non-None
    max_length simultaneously raises a ValueError in transformers >= 4.38;
    this design avoids that conflict entirely.

    Precondition: _ensure_loaded() must have been called before this function.
    """
    import torch  # local import: only executed when inference actually runs
    from transformers import GenerationConfig

    device = _device if _device is not None else torch.device("cpu")

    # Tokenizer max_length bounds the INPUT sequence (truncation).
    # It is intentionally separate from the generation bound below.
    inputs = _tokenizer(
        masked_text,
        return_tensors="pt",
        padding=True,
        truncation=True,
        max_length=MAX_INPUT_TOKENS,
    ).to(device)

    # Build a fresh GenerationConfig that sets ONLY max_new_tokens.
    # max_length is left None here, which overrides any value baked into the
    # model's own generation_config.json and removes the conflict warning.
    gen_config = GenerationConfig(
        forced_bos_token_id=_tokenizer.convert_tokens_to_ids(ENGLISH_TAG),
        max_new_tokens=MAX_OUTPUT_TOKENS,
    )

    with torch.no_grad():
        translated_tokens = _model.generate(**inputs, generation_config=gen_config)

    return _tokenizer.batch_decode(translated_tokens, skip_special_tokens=True)[0]


# ---------------------------------------------------------------------------
# Public API
# ---------------------------------------------------------------------------

def translate(text: str, src_lang: str) -> TranslationResult:
    """
    Translate *text* from *src_lang* to English.

    Parameters
    ----------
    text     : Raw email subject and/or body text (original, not pre-processed).
    src_lang : NLLB BCP-47 tag, e.g. "hin_Deva".  Use "eng_Latn" for English.

    Returns
    -------
    TranslationResult
        Always returns a structured result -- NEVER raises an exception.
        Inspect result.status to distinguish the four possible outcomes.

    Notes
    -----
    * The original *text* is preserved in result.source_text regardless of
      outcome.  The caller MUST NOT overwrite the original email content with
      result.translated_text.
    * result.translated_text must only be used for prototype evaluation; it
      MUST NOT be fed into calculate_risk() or any existing risk signal.
    """
    _common: dict = {
        "src_lang": src_lang,
        "source_text": text,
        "model_name": MODEL_NAME,
        "model_version": MODEL_VERSION,
    }

    # ------------------------------------------------------------------ #
    # State 1: English bypass                                              #
    # ------------------------------------------------------------------ #
    if src_lang == ENGLISH_TAG:
        return TranslationResult(
            status=TranslationStatus.ENGLISH_BYPASS,
            src_lang_name="English",
            translated_text=None,
            success=False,
            bypassed=True,
            error=None,
            **_common,
        )

    # ------------------------------------------------------------------ #
    # State 2: Unsupported language                                        #
    # ------------------------------------------------------------------ #
    lang_name = SUPPORTED_LANGUAGES.get(src_lang)
    if lang_name is None:
        return TranslationResult(
            status=TranslationStatus.UNSUPPORTED_LANGUAGE,
            src_lang_name=None,
            translated_text=None,
            success=False,
            bypassed=False,
            error=(
                f"Language tag {src_lang!r} is not in the supported Indic "
                f"language set. Supported: {sorted(SUPPORTED_LANGUAGES)}."
            ),
            **_common,
        )

    # Master enable switch: if NLLB is disabled treat as unsupported
    if not ENABLED:
        return TranslationResult(
            status=TranslationStatus.UNSUPPORTED_LANGUAGE,
            src_lang_name=lang_name,
            translated_text=None,
            success=False,
            bypassed=False,
            error="NLLB translation is disabled (NLLB_ENABLED=false).",
            **_common,
        )

    # ------------------------------------------------------------------ #
    # State 3: Translate (or State 4: fail)                               #
    # ------------------------------------------------------------------ #
    try:
        _ensure_loaded()

        masked = mask_technical_tokens(text)
        raw_translated = _run_inference(masked.text, src_lang)
        restored = restore_technical_tokens(raw_translated, masked.restoration_map)

        return TranslationResult(
            status=TranslationStatus.TRANSLATED,
            src_lang_name=lang_name,
            translated_text=restored,
            success=True,
            bypassed=False,
            error=None,
            **_common,
        )

    except Exception as exc:  # noqa: BLE001 -- intentional catch-all; translate() must not raise
        logger.warning(
            "NLLB translation failed  lang=%s  error=%s", src_lang, exc
        )
        return TranslationResult(
            status=TranslationStatus.TRANSLATION_FAILED,
            src_lang_name=lang_name,
            translated_text=None,
            success=False,
            bypassed=False,
            error=str(exc),
            **_common,
        )
