from __future__ import annotations


''' we are not using SpamAssassin yet.

It is a spam/ham corpus, and treating every spam sample as phishing
would contaminate the binary phishing target. We'll use its ham data later 
as a hard-negative/benign expansion or consider a future separate SPAM class.'''



'''
It uses only the training data from the Seven and Navyasri datasets,
keeps Zefang's labeled rows, does deterministic cleaning/deduplication, 
preserves source information, and creates a fresh 80/10/10 
train/validation/test split.


It never touches backend\app\models\v1_current or your existing model files.




Seven-phishing-email TRAIN
+
Zefang
+
Navyasri TRAIN'''




import hashlib
import json
import re
from pathlib import Path

import pandas as pd
from sklearn.model_selection import train_test_split


# ============================================================
# PROJECT PATHS
# ============================================================

ROOT = Path(__file__).resolve().parents[1]

RAW_DIR = ROOT / "datasets" / "raw"
PROCESSED_DIR = ROOT / "datasets" / "processed"

SEVEN_DIR = RAW_DIR / "seven-phishing-email"
ZEFANG_DIR = RAW_DIR / "zefang-phishing-email"
NAVYASRI_DIR = RAW_DIR / "navyasri-phishing-email"


# IMPORTANT:
# This script ONLY writes to datasets/processed/.
# It does NOT touch backend/app/models/.
# V1 models remain untouched.
# ============================================================


RANDOM_STATE = 42

TRAIN_SIZE = 0.80
VALIDATION_SIZE = 0.10
TEST_SIZE = 0.10


# ============================================================
# TEXT NORMALIZATION
# ============================================================

def clean_text(value: object) -> str:
    """
    Normalize email text without aggressively deleting content.

    We intentionally preserve:
    - words
    - URLs
    - punctuation that may be security-relevant
    - email addresses
    - domain names
    """

    if value is None:
        return ""

    if pd.isna(value):
        return ""

    text = str(value)

    # Normalize line endings.
    text = text.replace("\r\n", "\n").replace("\r", "\n")

    # Collapse excessive whitespace but preserve word boundaries.
    text = re.sub(r"[ \t]+", " ", text)
    text = re.sub(r"\n{3,}", "\n\n", text)

    return text.strip()


def build_subject_body_text(subject: object, body: object) -> str:
    """
    Combine subject + email body into the model input.

    The subject is intentionally retained because phishing emails
    frequently communicate urgency or impersonation through it.
    """

    subject_text = clean_text(subject)
    body_text = clean_text(body)

    if subject_text and body_text:
        return f"Subject: {subject_text}\n\n{body_text}"

    if subject_text:
        return f"Subject: {subject_text}"

    return body_text


def normalize_for_hash(text: str) -> str:
    """
    Conservative normalization for duplicate detection.

    We do NOT strip URLs, punctuation, or email addresses because
    those may be meaningful to security analysis.
    """

    text = text.lower()
    text = re.sub(r"\s+", " ", text)
    return text.strip()


def text_hash(text: str) -> str:
    normalized = normalize_for_hash(text)

    return hashlib.sha256(
        normalized.encode("utf-8", errors="ignore")
    ).hexdigest()


# ============================================================
# LABEL NORMALIZATION
# ============================================================

def normalize_binary_label(value: object) -> int | None:
    """
    Convert supported labels into:

        0 = benign / safe
        1 = phishing

    Return None if a label cannot be safely interpreted.
    """

    if value is None or pd.isna(value):
        return None

    # Numeric labels.
    if isinstance(value, (int, float)):
        numeric = int(value)

        if numeric in (0, 1):
            return numeric

    label = str(value).strip().lower()

    benign_labels = {
        "0",
        "safe",
        "safe email",
        "benign",
        "ham",
        "legitimate",
        "legitimate email",
        "normal",
    }

    phishing_labels = {
        "1",
        "phishing",
        "phishing email",
    }

    if label in benign_labels:
        return 0

    if label in phishing_labels:
        return 1

    return None


# ============================================================
# DATASET LOADERS
# ============================================================

def load_seven_dataset() -> pd.DataFrame:
    """
    Load ONLY train.parquet from the Seven Phishing Email Datasets.

    Known schema from inspection:

        text
        subject
        label
        sender
        receiver
        date
        urls
        dataset_name
    """

    path = SEVEN_DIR / "train.parquet"

    if not path.exists():
        raise FileNotFoundError(
            f"Seven dataset not found:\n{path}"
        )

    df = pd.read_parquet(path)

    required = {"text", "subject", "label"}

    missing = required - set(df.columns)

    if missing:
        raise ValueError(
            f"Seven dataset is missing required columns: {sorted(missing)}\n"
            f"Available columns: {df.columns.tolist()}"
        )

    result = pd.DataFrame()

    result["text"] = [
        build_subject_body_text(subject, body)
        for subject, body in zip(
            df["subject"],
            df["text"],
        )
    ]

    result["label"] = [
        normalize_binary_label(value)
        for value in df["label"]
    ]

    result["source"] = (
        df["dataset_name"].astype(str)
        if "dataset_name" in df.columns
        else "seven-phishing-email"
    )

    result["source_group"] = "seven-phishing-email"
    result["language"] = "en"

    return result


def load_zefang_dataset() -> pd.DataFrame:
    """
    Load Zefang phishing email dataset.

    Known schema:

        Unnamed: 0
        Email Text
        Email Type
    """

    path = ZEFANG_DIR / "Phishing_Email.csv"

    if not path.exists():
        raise FileNotFoundError(
            f"Zefang dataset not found:\n{path}"
        )

    df = pd.read_csv(path)

    required = {"Email Text", "Email Type"}

    missing = required - set(df.columns)

    if missing:
        raise ValueError(
            f"Zefang dataset is missing required columns: {sorted(missing)}\n"
            f"Available columns: {df.columns.tolist()}"
        )

    result = pd.DataFrame()

    result["text"] = df["Email Text"].map(clean_text)

    result["label"] = [
        normalize_binary_label(value)
        for value in df["Email Type"]
    ]

    result["source"] = "zefang-phishing-email"
    result["source_group"] = "zefang-phishing-email"
    result["language"] = "en"

    return result


def load_navyasri_dataset() -> pd.DataFrame:
    """
    Load ONLY the Navyasri training Parquet.

    Known schema from inspection:

        text
        email_type
    """

    train_files = sorted(
        (NAVYASRI_DIR / "data").glob("train-*.parquet")
    )

    if not train_files:
        raise FileNotFoundError(
            "Could not find Navyasri training parquet under:\n"
            f"{NAVYASRI_DIR / 'data'}"
        )

    if len(train_files) != 1:
        raise ValueError(
            "Expected exactly one Navyasri training parquet, found:\n"
            + "\n".join(str(p) for p in train_files)
        )

    path = train_files[0]

    df = pd.read_parquet(path)

    required = {"text", "email_type"}

    missing = required - set(df.columns)

    if missing:
        raise ValueError(
            f"Navyasri dataset is missing required columns: {sorted(missing)}\n"
            f"Available columns: {df.columns.tolist()}"
        )

    result = pd.DataFrame()

    result["text"] = df["text"].map(clean_text)

    result["label"] = [
        normalize_binary_label(value)
        for value in df["email_type"]
    ]

    result["source"] = "navyasri-phishing-email"
    result["source_group"] = "navyasri-phishing-email"
    result["language"] = "en"

    return result


# ============================================================
# CLEAN + DEDUPLICATE
# ============================================================

def clean_and_deduplicate(df: pd.DataFrame) -> tuple[pd.DataFrame, dict]:
    """
    Clean invalid rows, remove empty messages, normalize labels,
    and perform exact normalized-text deduplication.
    """

    stats: dict[str, int] = {}

    stats["rows_before_cleaning"] = len(df)

    # Remove invalid labels.
    df = df[df["label"].isin([0, 1])].copy()

    stats["removed_invalid_labels"] = (
        stats["rows_before_cleaning"] - len(df)
    )

    # Remove empty / extremely tiny text.
    before_empty_filter = len(df)

    df = df[
        df["text"].astype(str).str.len() >= 20
    ].copy()

    stats["removed_empty_or_tiny"] = (
        before_empty_filter - len(df)
    )

    # Conservative duplicate fingerprint.
    df["text_hash"] = df["text"].map(text_hash)

    before_dedupe = len(df)

    # Keep the first occurrence and retain its source.
    df = df.drop_duplicates(
        subset=["text_hash"],
        keep="first",
    ).copy()

    stats["removed_exact_duplicates"] = (
        before_dedupe - len(df)
    )

    # Stable unique ID for the final corpus.
    df["id"] = [
        f"email-{index:07d}"
        for index in range(len(df))
    ]

    # Reorder columns.
    df = df[
        [
            "id",
            "text",
            "label",
            "source",
            "source_group",
            "language",
            "text_hash",
        ]
    ].reset_index(drop=True)

    stats["final_rows"] = len(df)

    return df, stats


# ============================================================
# SPLIT
# ============================================================

def create_splits(
    df: pd.DataFrame,
) -> tuple[pd.DataFrame, pd.DataFrame, pd.DataFrame]:
    """
    Create an honest deterministic:

        80% train
        10% validation
        10% test

    split.

    Exact duplicates have already been removed before this point.
    Stratification preserves the phishing/benign class ratio.
    """

    if len(df) < 100:
        raise ValueError(
            f"Only {len(df)} rows available; refusing to create "
            "a small production training split."
        )

    train_df, temp_df = train_test_split(
        df,
        test_size=(VALIDATION_SIZE + TEST_SIZE),
        stratify=df["label"],
        random_state=RANDOM_STATE,
        shuffle=True,
    )

    # Split the remaining 20% equally into 10% validation / 10% test.
    validation_df, test_df = train_test_split(
        temp_df,
        test_size=0.50,
        stratify=temp_df["label"],
        random_state=RANDOM_STATE,
        shuffle=True,
    )

    train_df = train_df.sample(
        frac=1,
        random_state=RANDOM_STATE,
    ).reset_index(drop=True)

    validation_df = validation_df.sample(
        frac=1,
        random_state=RANDOM_STATE,
    ).reset_index(drop=True)

    test_df = test_df.sample(
        frac=1,
        random_state=RANDOM_STATE,
    ).reset_index(drop=True)

    return train_df, validation_df, test_df


# ============================================================
# REPORTING
# ============================================================

def print_dataset_report(
    name: str,
    df: pd.DataFrame,
) -> None:
    print(f"\n{'=' * 70}")
    print(name)
    print(f"{'=' * 70}")

    print(f"Rows: {len(df):,}")

    print("\nLabels:")
    print(
        df["label"]
        .value_counts()
        .sort_index()
        .rename(
            index={
                0: "BENIGN",
                1: "PHISHING",
            }
        )
        .to_string()
    )

    print("\nSources:")
    print(
        df["source_group"]
        .value_counts()
        .to_string()
    )


def build_stats(
    combined: pd.DataFrame,
    train_df: pd.DataFrame,
    validation_df: pd.DataFrame,
    test_df: pd.DataFrame,
    cleaning_stats: dict,
) -> dict:

    def counts(df: pd.DataFrame) -> dict:
        return {
            "total": int(len(df)),
            "benign": int((df["label"] == 0).sum()),
            "phishing": int((df["label"] == 1).sum()),
        }

    return {
        "random_state": RANDOM_STATE,
        "split_strategy": "80/10/10 stratified split after exact normalized-text deduplication",
        "sources_used": [
            "puyang2025/seven-phishing-email-datasets/train.parquet",
            "zefang-liu/phishing-email-dataset/Phishing_Email.csv",
            "Navyasri17/phishing_emails-data/data/train-00000-of-00001.parquet",
        ],
        "datasets_not_used_for_training": [
            "puyang2025/seven-phishing-email-datasets/test.parquet",
            "puyang2025/seven-phishing-email-datasets/eval.parquet",
            "Navyasri17/phishing_emails-data/data/test-00000-of-00001.parquet",
            "talby/spamassassin",
        ],
        "cleaning": cleaning_stats,
        "combined": counts(combined),
        "train": counts(train_df),
        "validation": counts(validation_df),
        "test": counts(test_df),
        "source_counts_combined": {
            str(k): int(v)
            for k, v in combined["source_group"]
            .value_counts()
            .to_dict()
            .items()
        },
    }


# ============================================================
# MAIN
# ============================================================

def main() -> None:
    print("\nValorProtects ML Dataset Preparation")
    print("=" * 70)

    print("\nLoading datasets...")

    seven = load_seven_dataset()
    print(
        f"Seven dataset loaded: {len(seven):,} rows"
    )

    zefang = load_zefang_dataset()
    print(
        f"Zefang dataset loaded: {len(zefang):,} rows"
    )

    navyasri = load_navyasri_dataset()
    print(
        f"Navyasri dataset loaded: {len(navyasri):,} rows"
    )

    print("\nCombining datasets...")

    combined = pd.concat(
        [
            seven,
            zefang,
            navyasri,
        ],
        ignore_index=True,
    )

    print(
        f"Combined before cleaning: {len(combined):,}"
    )

    combined, cleaning_stats = clean_and_deduplicate(
        combined
    )

    print("\nCleaning results:")
    for key, value in cleaning_stats.items():
        print(f"{key}: {value:,}")

    print_dataset_report(
        "COMBINED CORPUS",
        combined,
    )

    print("\nCreating stratified 80/10/10 split...")

    train_df, validation_df, test_df = create_splits(
        combined
    )

    print_dataset_report(
        "TRAIN",
        train_df,
    )

    print_dataset_report(
        "VALIDATION",
        validation_df,
    )

    print_dataset_report(
        "TEST",
        test_df,
    )

    # --------------------------------------------------------
    # Output paths
    # --------------------------------------------------------

    PROCESSED_DIR.mkdir(
        parents=True,
        exist_ok=True,
    )

    combined_path = (
        PROCESSED_DIR
        / "combined_email_corpus.parquet"
    )

    train_path = (
        PROCESSED_DIR
        / "train.parquet"
    )

    validation_path = (
        PROCESSED_DIR
        / "validation.parquet"
    )

    test_path = (
        PROCESSED_DIR
        / "test.parquet"
    )

    stats_path = (
        PROCESSED_DIR
        / "dataset_stats.json"
    )

    # --------------------------------------------------------
    # Save
    # --------------------------------------------------------

    combined.to_parquet(
        combined_path,
        index=False,
    )

    train_df.to_parquet(
        train_path,
        index=False,
    )

    validation_df.to_parquet(
        validation_path,
        index=False,
    )

    test_df.to_parquet(
        test_path,
        index=False,
    )

    stats = build_stats(
        combined=combined,
        train_df=train_df,
        validation_df=validation_df,
        test_df=test_df,
        cleaning_stats=cleaning_stats,
    )

    stats_path.write_text(
        json.dumps(
            stats,
            indent=2,
        ),
        encoding="utf-8",
    )

    print("\n" + "=" * 70)
    print("DATASET PREPARATION COMPLETE")
    print("=" * 70)

    print(f"\nSaved:")
    print(f"  {combined_path}")
    print(f"  {train_path}")
    print(f"  {validation_path}")
    print(f"  {test_path}")
    print(f"  {stats_path}")

    print("\nV1 models were NOT touched.")
    print("backend/app/models/v1_current remains unchanged.")
    print("backend/app/models/v2 remains unchanged.")
    print("\nReady for V2 model training.")


if __name__ == "__main__":
    main()