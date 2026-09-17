"""
Configuration for the NLLB multilingual translation prototype.

Environment variables are loaded from the project .env file at module-import
time (before any constant is evaluated) so they are visible regardless of
which entry-point imports this module first.

Environment variables
---------------------
NLLB_MODEL_NAME         HuggingFace model ID
                        default: facebook/nllb-200-distilled-600M
NLLB_CACHE_DIR          Local cache directory for model weights
                        default: <project_root>/.cache/nllb
NLLB_MAX_INPUT_TOKENS   Tokenizer truncation ceiling (default: 512)
NLLB_MAX_OUTPUT_TOKENS  Generation token ceiling    (default: 512)
NLLB_ENABLED            Master switch; "false"/"0"/"no" disables the
                        translation layer entirely (default: true)
NLLB_MODEL_DEVICE       Device for model inference:
                          auto  (default) -- CUDA when available, else CPU
                          cpu             -- CPU always, even if CUDA present
                          cuda            -- CUDA always; structured failure if
                                            torch.cuda.is_available() is False
TRANSFORMERS_CACHE      Standard HuggingFace override -- respected by the
                        transformers library automatically; NLLB_CACHE_DIR
                        is passed as explicit cache_dir= and takes priority
                        for this prototype only.
"""
from __future__ import annotations

import os
from pathlib import Path

# ---------------------------------------------------------------------------
# .env bootstrap -- runs BEFORE any constant is evaluated
# ---------------------------------------------------------------------------
# Why here and not in the scripts:
#   Module-level constants (DEVICE_MODE, MAX_OUTPUT_TOKENS, ...) are evaluated
#   once at first import.  If load_dotenv() is called from a script *after*
#   this module is imported the constants are already frozen with wrong defaults.
#   Calling load_dotenv() at the very top of this module -- before the constants
#   -- guarantees that os.environ is populated no matter which entry-point runs.
#   dotenv never overwrites vars that are already in the environment (override=False),
#   so shell overrides always win over the .env file.
# ---------------------------------------------------------------------------

def load_nllb_env() -> None:
    """
    Load <project_root>/.env into os.environ via python-dotenv.

    This function is called immediately below (at module import time) and may
    also be called explicitly by scripts for documentation clarity.  Repeated
    calls are safe: dotenv.load_dotenv is idempotent with override=False.
    """
    try:
        from dotenv import load_dotenv
    except ImportError:
        return  # python-dotenv not installed; fall through to os.getenv defaults

    _env_path = Path(__file__).resolve().parents[3] / ".env"
    if _env_path.exists():
        load_dotenv(dotenv_path=_env_path, override=False)


# Execute immediately so constants below see the .env values.
load_nllb_env()


# ---------------------------------------------------------------------------
# Module-level constants
# ---------------------------------------------------------------------------

# backend/app/multilingual/config.py  ->  parents[3] == project root
_PROJECT_ROOT: Path = Path(__file__).resolve().parents[3]

MODEL_NAME: str = os.getenv(
    "NLLB_MODEL_NAME",
    "facebook/nllb-200-distilled-600M",
)

# Short version tag embedded in TranslationResult.model_version
MODEL_VERSION: str = MODEL_NAME.split("/")[-1]

# Project-relative cache for weight isolation; override via env if needed.
CACHE_DIR: str = os.getenv(
    "NLLB_CACHE_DIR",
    str(_PROJECT_ROOT / ".cache" / "nllb"),
)

# Hard ceiling on tokenizer input -- prevents runaway memory on large emails.
MAX_INPUT_TOKENS: int = int(os.getenv("NLLB_MAX_INPUT_TOKENS", "512"))

# Hard ceiling on model generation -- prevents pathological long outputs.
MAX_OUTPUT_TOKENS: int = int(os.getenv("NLLB_MAX_OUTPUT_TOKENS", "512"))

# Master enable switch. When False, translate() returns UNSUPPORTED_LANGUAGE
# for all non-English input without loading the model.
ENABLED: bool = os.getenv("NLLB_ENABLED", "true").lower() not in ("false", "0", "no")

# ---------------------------------------------------------------------------
# Device configuration
# ---------------------------------------------------------------------------

#: Raw string from the environment.
_DEVICE_SETTING: str = os.getenv("NLLB_MODEL_DEVICE", "auto").lower().strip()

#: Validated device mode.  One of "auto", "cpu", "cuda".
_VALID_DEVICE_MODES = frozenset({"auto", "cpu", "cuda"})

if _DEVICE_SETTING not in _VALID_DEVICE_MODES:
    import warnings as _warnings
    _warnings.warn(
        f"NLLB_MODEL_DEVICE={_DEVICE_SETTING!r} is not recognised "
        f"(must be one of {sorted(_VALID_DEVICE_MODES)}); defaulting to 'auto'.",
        stacklevel=2,
    )
    _DEVICE_SETTING = "auto"

#: Public constant consumed by nllb_translator._load_model().
DEVICE_MODE: str = _DEVICE_SETTING
