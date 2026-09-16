#!/usr/bin/env python
"""
NLLB translation benchmark -- prototype only.

Measures per-language translation latency over a small hardcoded multilingual
sample set using real model inference.

IMPORTANT: This script REQUIRES the NLLB model to be downloaded first.
           It is NOT meant to run in normal CI. Run it explicitly:

    python scripts/nllb_benchmark.py
    python scripts/nllb_benchmark.py --warmup 2 --runs 5

To download the model first (~2.4 GB, one-time):
    python scripts/nllb_benchmark.py --download-only

Output: markdown table to stdout, JSON summary to --json-out if specified.

This script is PROTOTYPE ONLY -- it does not affect any production scan,
risk score, or stored result.
"""
from __future__ import annotations

import argparse
import json
import sys
import time
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))

# Load .env BEFORE importing any project module so that os.getenv() calls
# in config.py see the .env values.  Mirrors the load_dotenv() convention in
# backend/app/main.py.  This is a no-op if the vars are already in the env.
from backend.app.multilingual.config import load_nllb_env
load_nllb_env()

# ---------------------------------------------------------------------------
# Hardcoded multilingual sample set (no external file dependency)
# Samples represent security-relevant email content (phishing lures) so the
# prototype classifier scores are meaningful for evaluation.
# ---------------------------------------------------------------------------
SAMPLES: list[tuple[str, str]] = [
    # English -- bypass path (no model call)
    (
        "eng_Latn",
        "Your account has been compromised. Verify your identity at http://login.example.com immediately.",
    ),
    # Indic languages
    (
        "hin_Deva",
        "आपका खाता संदिग्ध गतिविधि के कारण लॉक कर दिया गया है। "
        "कृपया http://example.com/verify पर जाकर अपनी पहचान सत्यापित करें।",
    ),
    (
        "tel_Telu",
        "మీ ఖాతా నిలిపివేయబడింది. దయచేసి మీ వివరాలను https://example.com వద్ద నవీకరించండి.",
    ),
    (
        "tam_Taml",
        "உங்கள் கணக்கு இடைநிறுத்தப்பட்டுள்ளது. உங்கள் விவரங்களை உடனடியாக சரிபார்க்கவும்.",
    ),
    (
        "kan_Knda",
        "ನಿಮ್ಮ ಖಾತೆಯಲ್ಲಿ ಅನುಮಾನಾಸ್ಪದ ಚಟುವಟಿಕೆ ಪತ್ತೆಯಾಗಿದೆ. ದಯವಿಟ್ಟು ಲಾಗ್ ಇನ್ ಮಾಡಿ.",
    ),
    (
        "mal_Mlym",
        "നിങ്ങളുടെ അക്കൗണ്ട് സസ്പെൻഡ് ചെയ്യപ്പെട്ടിരിക്കുന്നു. ഉടൻ സ്ഥിരീകരിക്കുക.",
    ),
    (
        "mar_Deva",
        "तुमच्या खात्यात संशयास्पद क्रियाकलाप आढळला आहे. कृपया तपशील अद्यतनित करा.",
    ),
    (
        "ben_Beng",
        "আপনার অ্যাকাউন্টে সন্দেহজনক কার্যকলাপ সনাক্ত করা হয়েছে। অনুগ্রহ করে যাচাই করুন।",
    ),
    (
        "guj_Gujr",
        "તમારા ખાતામાં શંકાસ્પદ પ્રવૃત્તિ મળી આવી છે। કૃપા કરીને ચકાસો.",
    ),
    (
        "ory_Orya",
        "ଆପଣଙ୍କ ଖାତାରେ ସନ୍ଦେହଜନକ କ୍ରିୟାକଳାପ ଦେଖାଦେଇଛି। ଦୟାକରି ଯାଞ୍ଚ କରନ୍ତୁ।",
    ),
    (
        "pan_Guru",
        "ਤੁਹਾਡੇ ਖਾਤੇ ਵਿੱਚ ਸ਼ੱਕੀ ਗਤੀਵਿਧੀ ਪਾਈ ਗਈ ਹੈ। ਕਿਰਪਾ ਕਰਕੇ ਤੁਰੰਤ ਪੁਸ਼ਟੀ ਕਰੋ।",
    ),
    (
        "urd_Arab",
        "آپ کے اکاؤنٹ میں مشکوک سرگرمی پائی گئی ہے۔ براہ کرم فوری طور پر تصدیق کریں۔",
    ),
    # Unsupported language -- should return UNSUPPORTED_LANGUAGE without model call
    (
        "deu_Latn",
        "Ihr Konto wurde gesperrt. Bitte bestätigen Sie Ihre Identität sofort.",
    ),
]


def _download_model() -> None:
    """Download and cache the NLLB model weights. One-time setup."""
    from backend.app.multilingual.config import CACHE_DIR, MODEL_NAME
    from transformers import AutoModelForSeq2SeqLM, AutoTokenizer

    print(f"Downloading tokenizer: {MODEL_NAME}")
    AutoTokenizer.from_pretrained(MODEL_NAME, cache_dir=CACHE_DIR)
    print(f"Downloading model (this is ~2.4 GB, please wait)...")
    AutoModelForSeq2SeqLM.from_pretrained(MODEL_NAME, cache_dir=CACHE_DIR)
    print(f"Model cached in: {CACHE_DIR}")


def _fmt_row(cells: list, widths: list[int]) -> str:
    return "| " + " | ".join(str(c).ljust(w) for c, w in zip(cells, widths)) + " |"


def run_benchmark(warmup: int = 1, runs: int = 3, json_out: str | None = None) -> None:
    from backend.app.multilingual.nllb_translator import TranslationStatus, translate

    print(f"\nNLLB Translation Benchmark")
    print(f"Model  : facebook/nllb-200-distilled-600M")
    print(f"Warmup : {warmup} run(s)   Measured: {runs} run(s)\n")

    # Warmup -- triggers model load; not counted in measurements.
    print("Warming up (first call loads the model)...")
    t_load_start = time.perf_counter()
    warmup_result = translate(SAMPLES[1][1], src_lang=SAMPLES[1][0])
    t_load = time.perf_counter() - t_load_start
    if warmup_result.status == TranslationStatus.TRANSLATION_FAILED:
        print(f"ERROR during warmup: {warmup_result.error}", file=sys.stderr)
        sys.exit(1)
    print(f"Model loaded in {t_load:.1f}s\n")

    # Additional warmup runs (not measured)
    for _ in range(warmup - 1):
        translate(SAMPLES[1][1], src_lang=SAMPLES[1][0])

    records = []
    for src_lang, text in SAMPLES:
        times_ms: list[float] = []
        last_result = None
        for _ in range(runs):
            t0 = time.perf_counter()
            last_result = translate(text, src_lang=src_lang)
            times_ms.append((time.perf_counter() - t0) * 1000.0)

        avg = sum(times_ms) / len(times_ms)
        mn = min(times_ms)
        mx = max(times_ms)
        lang_name = last_result.src_lang_name or src_lang
        status = last_result.status.value
        translated_preview = (
            (last_result.translated_text or "")[:60] + "..."
            if last_result.translated_text and len(last_result.translated_text) > 60
            else last_result.translated_text or "-"
        )
        records.append({
            "src_lang": src_lang,
            "lang_name": lang_name,
            "status": status,
            "avg_ms": round(avg, 1),
            "min_ms": round(mn, 1),
            "max_ms": round(mx, 1),
            "translated_preview": translated_preview,
        })

    # Print markdown table
    headers = ["src_lang", "Language", "Status", "avg_ms", "min_ms", "max_ms"]
    widths = [12, 14, 22, 9, 9, 9]
    sep = "|-" + "-|-".join("-" * w for w in widths) + "-|"

    print(_fmt_row(headers, widths))
    print(sep)
    for r in records:
        print(_fmt_row(
            [r["src_lang"], r["lang_name"], r["status"],
             f"{r['avg_ms']:.1f}", f"{r['min_ms']:.1f}", f"{r['max_ms']:.1f}"],
            widths,
        ))

    # Translation preview column
    print("\nTranslation previews:")
    for r in records:
        if r["status"] == TranslationStatus.TRANSLATED.value:
            print(f"  [{r['src_lang']}] {r['translated_preview']}")

    # Summary stats
    n_translated = sum(1 for r in records if r["status"] == TranslationStatus.TRANSLATED.value)
    n_bypass = sum(1 for r in records if r["status"] == TranslationStatus.ENGLISH_BYPASS.value)
    n_unsupported = sum(1 for r in records if r["status"] == TranslationStatus.UNSUPPORTED_LANGUAGE.value)
    n_failed = sum(1 for r in records if r["status"] == TranslationStatus.TRANSLATION_FAILED.value)
    translated_times = [r["avg_ms"] for r in records if r["status"] == TranslationStatus.TRANSLATED.value]
    overall_avg = sum(translated_times) / len(translated_times) if translated_times else 0

    print(f"\nSummary: {n_translated} translated | {n_bypass} English bypass "
          f"| {n_unsupported} unsupported | {n_failed} failed")
    if translated_times:
        print(f"Mean translation latency (Indic only): {overall_avg:.1f} ms")

    if json_out:
        out = {
            "model": "facebook/nllb-200-distilled-600M",
            "warmup_runs": warmup,
            "measured_runs": runs,
            "model_load_seconds": round(t_load, 2),
            "samples": records,
            "summary": {
                "translated": n_translated,
                "english_bypass": n_bypass,
                "unsupported": n_unsupported,
                "failed": n_failed,
                "mean_translation_ms": round(overall_avg, 1),
            },
        }
        Path(json_out).write_text(json.dumps(out, ensure_ascii=False, indent=2), encoding="utf-8")
        print(f"\nJSON results written to: {json_out}")


def main() -> None:
    parser = argparse.ArgumentParser(
        description=(
            "NLLB benchmark -- requires model download. "
            "Run --download-only first if model is not cached."
        )
    )
    parser.add_argument(
        "--warmup", type=int, default=1,
        help="Number of warmup runs before measurement (default: 1).",
    )
    parser.add_argument(
        "--runs", type=int, default=3,
        help="Number of measured runs per language (default: 3).",
    )
    parser.add_argument(
        "--json-out", metavar="FILE",
        help="Write full benchmark results as JSON to this file.",
    )
    parser.add_argument(
        "--download-only", action="store_true",
        help="Download and cache the model, then exit without benchmarking.",
    )
    args = parser.parse_args()

    if args.download_only:
        _download_model()
        sys.exit(0)

    run_benchmark(warmup=args.warmup, runs=args.runs, json_out=args.json_out)


if __name__ == "__main__":
    main()
