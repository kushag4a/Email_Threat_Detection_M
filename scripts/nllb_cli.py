#!/usr/bin/env python
"""
NLLB translation CLI -- prototype only.

Detects/accepts a source language, translates to English via the NLLB-200
singleton, optionally runs the prototype V2 classifier, and prints JSON.

Usage
-----
    # Explicit text on the command line:
    python scripts/nllb_cli.py --lang hin_Deva --text "आपका खाता लॉक हो गया है"

    # Read text from stdin:
    echo "మీ ఖాతా నిలిపివేయబడింది" | python scripts/nllb_cli.py --lang tel_Telu

    # English bypass (no model load):
    python scripts/nllb_cli.py --lang eng_Latn --text "Hello world"

    # Skip the prototype classifier step:
    python scripts/nllb_cli.py --lang hin_Deva --text "..." --no-classify

    # List supported languages and exit:
    python scripts/nllb_cli.py --list-languages

Output
------
JSON to stdout.  Errors and warnings go to stderr.

This script is PROTOTYPE ONLY -- it does not affect any production scan,
risk score, or stored result.
"""
from __future__ import annotations

import argparse
import json
import sys
from pathlib import Path

# Allow running as `python scripts/nllb_cli.py` from the project root.
sys.path.insert(0, str(Path(__file__).resolve().parents[1]))

# Load .env BEFORE importing any project module so that os.getenv() calls
# in config.py see the .env values.  Mirrors the load_dotenv() convention in
# backend/app/main.py.  This is a no-op if the vars are already in the env.
from backend.app.multilingual.config import load_nllb_env
load_nllb_env()

from backend.app.multilingual.language_codes import ENGLISH_TAG, SUPPORTED_LANGUAGES
from backend.app.multilingual.nllb_translator import translate
from backend.app.multilingual.proto_classifier import proto_classify_translated


def _list_languages() -> None:
    rows = [(ENGLISH_TAG, "English (bypass -- no translation)")]
    rows += sorted(SUPPORTED_LANGUAGES.items())
    max_tag_len = max(len(t) for t, _ in rows)
    print(f"{'Tag':<{max_tag_len}}  Language")
    print("-" * (max_tag_len + 2 + 20))
    for tag, name in rows:
        print(f"{tag:<{max_tag_len}}  {name}")


def main() -> None:
    parser = argparse.ArgumentParser(
        description="NLLB multilingual translation prototype CLI",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog=__doc__,
    )
    parser.add_argument(
        "--lang",
        metavar="NLLB_TAG",
        help=(
            "Source language NLLB BCP-47 tag (e.g. hin_Deva). "
            "Run --list-languages for all supported values."
        ),
    )
    parser.add_argument(
        "--text",
        metavar="TEXT",
        default=None,
        help="Text to translate. Omit to read from stdin.",
    )
    parser.add_argument(
        "--no-classify",
        action="store_true",
        help="Skip the prototype V2 classifier step.",
    )
    parser.add_argument(
        "--list-languages",
        action="store_true",
        help="Print all supported language tags and exit.",
    )
    args = parser.parse_args()

    if args.list_languages:
        _list_languages()
        sys.exit(0)

    if not args.lang:
        parser.error("--lang is required unless --list-languages is specified.")

    # Read input text
    text = args.text
    if text is None:
        if sys.stdin.isatty():
            print(
                "Reading from stdin (Ctrl+D / Ctrl+Z to submit)...",
                file=sys.stderr,
            )
        text = sys.stdin.read().strip()

    if not text:
        json.dump({"error": "No input text provided."}, sys.stderr, ensure_ascii=False)
        sys.stderr.write("\n")
        sys.exit(1)

    result = translate(text, src_lang=args.lang)
    output = result.to_dict()

    if not args.no_classify:
        proto = proto_classify_translated(result)
        output["proto_classification"] = proto

    print(json.dumps(output, ensure_ascii=False, indent=2))


if __name__ == "__main__":
    main()
