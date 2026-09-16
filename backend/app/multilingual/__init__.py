"""
ValorProtects -- NLLB multilingual translation prototype.

This package provides an *isolated* translation layer for Indic-language
email text. It has NO production dependencies: nothing in this package
modifies the production V2 model, risk engine, scoring, or any existing API.

Public surface (used by CLI and benchmark only):
    from backend.app.multilingual.nllb_translator import translate, TranslationResult, TranslationStatus
    from backend.app.multilingual.proto_classifier import proto_classify_translated
"""
