"""
Prototype-only classifier wrapper.

Applies the existing production V2 classify_email() function to the
translated English text from a TranslationResult.  All returned keys carry
a _proto_ prefix so no caller can accidentally confuse this output with a
live M2 result.

Isolation contract
------------------
THIS MODULE MUST NEVER BE IMPORTED FROM:
    analysis_service.py, scan_service.py, risk_engine.py, ml_classifier.py,
    or any other existing production module.

It is called only from:
    scripts/nllb_cli.py
    scripts/nllb_benchmark.py

The proto classification:
    - Does NOT modify any production risk score.
    - Does NOT feed into calculate_risk().
    - Does NOT appear in any stored scan result or API response.
    - Is purely for offline prototype evaluation.
"""
from __future__ import annotations

from backend.app.multilingual.nllb_translator import TranslationResult, TranslationStatus


def proto_classify_translated(result: TranslationResult) -> dict | None:
    """
    Run the production V2 classifier (read-only) on translated English text.

    Parameters
    ----------
    result : TranslationResult from translate().

    Returns
    -------
    dict with _proto_-prefixed keys, or None if translation was not successful
    (status is ENGLISH_BYPASS, UNSUPPORTED_LANGUAGE, or TRANSLATION_FAILED).

    The production classify_email() is called unchanged -- same models, same
    vectorizer, same logic.  Calling it here does not modify its module state.
    """
    if result.status != TranslationStatus.TRANSLATED or not result.translated_text:
        return None

    # Lazy import: the production pkl models load on first import of this
    # function.  They are never loaded if this module is never called.
    from backend.app.services.ml_classifier import classify_email

    raw = classify_email(result.translated_text)

    return {
        "_proto_src_lang": result.src_lang,
        "_proto_src_lang_name": result.src_lang_name,
        "_proto_translation_model": result.model_name,
        "_proto_safe_probability": raw["safe_probability"],
        "_proto_phishing_probability": raw["phishing_probability"],
        "_proto_threat_categories": raw["threat_categories"],
        "_proto_rule_based_threats": raw["rule_based_threats"],
        "_proto_top_classification": raw["top_classification"],
        "_proto_forensics_triggered": raw["forensics_triggered"],
        "_proto_note": (
            "PROTOTYPE ONLY. These scores are the production V2 classifier "
            "applied to NLLB-translated text. They do NOT affect any "
            "production risk score, threat label, or stored scan result."
        ),
    }
