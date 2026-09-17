"""
NLLB-200 language code registry.

SUPPORTED_LANGUAGES maps NLLB BCP-47 script-tagged codes for the 11 Indic
languages in this prototype to their human-readable names.
Only these codes (plus ENGLISH_TAG) are accepted by the translator.

NLLB BCP-47 format: <iso639-3>_<script>
"""
from __future__ import annotations

# Indic source languages accepted for Indic->English translation.
SUPPORTED_LANGUAGES: dict[str, str] = {
    "hin_Deva": "Hindi",
    "tel_Telu": "Telugu",
    "tam_Taml": "Tamil",
    "kan_Knda": "Kannada",
    "mal_Mlym": "Malayalam",
    "mar_Deva": "Marathi",
    "ben_Beng": "Bengali",
    "guj_Gujr": "Gujarati",
    "ory_Orya": "Odia",
    "pan_Guru": "Punjabi",
    "urd_Arab": "Urdu",
}

# NLLB tag for English (Latn script). Input tagged as this bypasses the model.
ENGLISH_TAG: str = "eng_Latn"

# Fixed translation target -- always English. Never changes.
TARGET_LANGUAGE: str = ENGLISH_TAG
