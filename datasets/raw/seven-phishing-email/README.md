---
pretty_name: Seven Phishing/Spam Email Datasets
language:
  - en
task_categories:
  - text-classification
task_ids:
  - multi-class-classification
multilinguality:
  - monolingual
size_categories:
  - 100K<n<1M
source_datasets:
  - original
annotations_creators:
  - no-annotation
license: other
tags:
  - email
  - phishing
  - spam
  - security
  - nlp
---

# Dataset Card for Seven Phishing/Spam Email Datasets

## Dataset Summary

This dataset is a unified, row-level email corpus built from seven commonly used public email datasets. It is intended for research on phishing/spam detection and related email-text classification tasks.

Each row contains the email body (`text`), optional header-like fields (e.g., `sender`, `receiver`, `date`), the source dataset name (`dataset_name`), and a binary label (`label`).

## Supported Tasks and Leaderboards

- Binary classification: phishing/spam vs benign/legitimate email.

## Languages

- Primarily English (`en`).

## Dataset Structure

### Data Instances

Each example has the following fields:

- `text` (`string`): Email body content (may include quoted replies/forwards).
- `subject` (`string`): Email subject line.
- `label` (`int64`): Binary label where `0 = benign/legitimate (ham)` and `1 = phishing/spam`.
- `sender` (`string`, nullable): Sender address/name when available.
- `receiver` (`string`, nullable): Receiver address/name when available.
- `date` (`timestamp[ns]`, nullable): Parsed timestamp when available.
- `urls` (`int64`, nullable): Count of URL-like substrings detected in the email content (when available).
- `dataset_name` (`string`): Source dataset identifier (`Assassin`, `CEAS-08`, `Enron`, `Ling`, `TREC-05`, `TREC-06`, `TREC-07`).

### Data Splits

The repository contains Parquet shards for a single split:

- `train`: 203,017 examples total (8 Parquet shards: `train-00000-of-00008.parquet` … `train-00007-of-00008.parquet`).

### Usage

With the `datasets` library:

```python
from datasets import load_dataset

ds = load_dataset("YOUR_HF_ORG/seven-phishing-email-datasets")
ds["train"][0]
```

Per-source counts:

| dataset_name | benign (label=0) | phishing/spam (label=1) | total |
|---|---:|---:|---:|
| TREC-05 | 32,329 | 22,946 | 55,275 |
| TREC-07 | 24,358 | 29,399 | 53,757 |
| CEAS-08 | 17,312 | 21,842 | 39,154 |
| Enron | 15,791 | 13,976 | 29,767 |
| TREC-06 | 12,411 | 3,989 | 16,400 |
| Assassin | 4,087 | 1,718 | 5,805 |
| Ling | 2,401 | 458 | 2,859 |
| **Total** | **108,689** | **94,328** | **203,017** |

Missingness notes (null counts over the full dataset):

- `sender`: 32,626 nulls
- `receiver`: 32,626 nulls
- `date`: 36,084 nulls
- `urls`: 32,626 nulls

## Dataset Creation

### Source Data

The dataset aggregates emails from seven widely-used sources (as present in `data_raw/`):

- `Assassin.csv` (SpamAssassin public corpus–derived)
- `CEAS-08.csv` (CEAS 2008 email dataset)
- `Enron.csv` (Enron email corpus–derived)
- `Ling.csv` (Ling-Spam dataset)
- `TREC-05.csv` (TREC 2005 spam track–derived)
- `TREC-06.csv` (TREC 2006 spam track–derived)
- `TREC-07.csv` (TREC 2007 spam track–derived)

### Data Processing

This Hugging Face distribution provides a normalized schema across sources and exports the result as Parquet. Some header fields are missing for certain sources, which is reflected by null values in `sender`, `receiver`, `date`, and `urls`.

## Considerations for Using the Data

### Social Impact and Intended Use

This dataset is intended for security/NLP research (e.g., spam/phishing detection, robustness evaluation, domain adaptation). It should not be used for surveillance or to make high-stakes decisions without additional validation and safeguards.

### Risks, Biases, and Limitations

- **Label semantics**: `label=1` represents phishing/spam content in the original sources; depending on the source, it may include marketing spam and other unwanted email that is not strictly phishing.
- **Temporal/domain shift**: Many sources are historical; modern phishing campaigns and email formats may differ substantially.
- **Duplicates and thread text**: Emails may contain quoted replies/forwards and signatures; naive splitting can leak information between train/test if you create your own splits.
- **PII**: Emails can contain personal data (names, addresses, phone numbers, email addresses) and should be handled accordingly.
- **Malicious content**: Emails may include harmful URLs or instructions. Do not click links or execute attachments referenced in the text.

### Recommendations

- Create your own `train/validation/test` split carefully (e.g., group by thread, sender domain, or near-duplicate clustering) to reduce leakage.
- Consider redacting PII (addresses, phone numbers, account numbers) for downstream sharing or model release.

## Licensing

This repository aggregates multiple datasets with potentially different licensing terms and usage restrictions. No single license is asserted for the combined dataset here; please consult the original sources for each component dataset and ensure your intended use complies with their terms.

## Citation

If you use this dataset, cite the original source datasets as appropriate (e.g., TREC Spam Track corpora, CEAS 2008, Enron email corpus, Ling-Spam, SpamAssassin public corpus) and also cite this Hugging Face dataset entry.

## Contact

For questions or issues with this Hugging Face conversion, please open an issue or discussion in the repository hosting this dataset.
