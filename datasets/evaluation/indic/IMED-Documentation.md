# Indic Multilingual Evaluation Dataset

## Purpose

`indic_eval.csv` is a **synthetic** benchmark used to evaluate how the
NLLB-200 translation prototype (`scripts/evaluate_indic_nllb.py`) affects
phishing-classification performance on non-English, Indic-language email
text, compared to running the production V2 classifier on the raw text
directly. It exists purely for **offline evaluation** of the translation
prototype. It is not training data, is never loaded by the production
pipeline (`risk_engine.py`, `analysis_service.py`, `ml_classifier.py`),
and does not influence any live scan result.

## Languages (11)

| Code       | Language  |
|------------|-----------|
| `hin_Deva` | Hindi     |
| `tel_Telu` | Telugu    |
| `tam_Taml` | Tamil     |
| `kan_Knda` | Kannada   |
| `mal_Mlym` | Malayalam |
| `mar_Deva` | Marathi   |
| `ben_Beng` | Bengali   |
| `guj_Gujr` | Gujarati  |
| `ory_Orya` | Odia      |
| `pan_Guru` | Punjabi   |
| `urd_Arab` | Urdu      |

These match `SUPPORTED_LANGUAGES` in `backend/app/multilingual/language_codes.py`.

## Schema

CSV columns, UTF-8 encoded:

```
id,language,text,label,source
```

- `id` — integer, unique across the whole file (1..1100).
- `language` — one of the 11 NLLB BCP-47 codes above.
- `text` — synthetic email text, formatted as `<subject>\n<body>`.
- `label` — `0` = legitimate, `1` = phishing.
- `source` — always `synthetic` (see Provenance below).

Note: `scripts/evaluate_indic_nllb.py`'s `load_dataset()` also accepts
optional `language_name` / `notes` columns via `row.get(...)` with
fallback defaults, but this generator intentionally emits the minimal
5-column schema above.

## Class distribution

Total: **1,100 rows** across 11 languages, **100 per language**
(55 legitimate / 45 phishing per language — see exact counts below).
The split is not forced to an exact 50/50 balance; template availability
and realism were prioritized over perfect balance, per the dataset brief.

| Language   | Total | Legitimate (0) | Phishing (1) |
|------------|-------|-----------------|--------------|
| hin_Deva   | 100   | 55              | 45           |
| tel_Telu   | 100   | 55              | 45           |
| tam_Taml   | 100   | 55              | 45           |
| kan_Knda   | 100   | 55              | 45           |
| mal_Mlym   | 100   | 55              | 45           |
| mar_Deva   | 100   | 55              | 45           |
| ben_Beng   | 100   | 55              | 45           |
| guj_Gujr   | 100   | 55              | 45           |
| ory_Orya   | 100   | 55              | 45           |
| pan_Guru   | 100   | 55              | 45           |
| urd_Arab   | 100   | 55              | 45           |
| **Total**  | **1100** | **605**      | **495**      |

## Synthetic data disclosure

**Every row in this dataset is synthetic.** `source` is always
`synthetic`. No row was collected from a real mailbox, a real phishing
campaign, or any other real-world source. Company names (`SafePay`,
`TrustBank`, `QuickShop`, `CloudMail`, `SwiftCourier`), links
(e.g. `secure-verify-update.info`), amounts, dates, and order IDs are
all fictional placeholders — none resolve to real services, and none
are meant to impersonate any specific real company.

## Generation methodology

`scripts/generate_indic_eval_dataset.py` generates the CSV deterministically:

1. For each language, hand-written **subject/body templates** cover 6
   legitimate categories (order/delivery, invoice, login-alert,
   workplace/meeting, newsletter, password-changed) and 6 phishing
   categories (credential harvesting, BEC-style urgent wire request,
   account-suspension scare, fake security alert, tax/refund
   impersonation, delivery-fee scam).
2. Templates are filled with varying `{name}`, `{company}`, `{amount}`,
   `{date}`, `{link}`, `{order_id}` values, round-robining across
   templates so category mix stays even per language and no two rows
   in the same language are textually identical.
3. A fixed seed (`SEED = 1729`) plus stable iteration order
   (dict/list order, `itertools.product` order) makes re-running the
   script byte-for-byte reproducible.
4. IDs are assigned sequentially and are unique across the whole file.

Run it with:

```
python scripts/generate_indic_eval_dataset.py
```

Optional `--out <path>` overrides the default output location
(`datasets/evaluation/indic/indic_eval.csv`).

## Limitations

- **Template-based, not organic.** Real phishing and legitimate email
  vary far more than a fixed set of 12 templates per language; this
  dataset tests recognizable *patterns*, not the full diversity of
  real-world Indic-language email.
- **No native-speaker review.** All template text was authored by an
  LLM. Confidence is higher for languages with more available training
  data (e.g. Hindi, Bengali, Urdu, Marathi) and lower for
  lower-resource languages in this set (e.g. Odia, Malayalam, Kannada).
  A native speaker has not verified grammar, register, or naturalness
  in any language here.
- **Fictional brand names/links only.** The dataset does not include
  impersonation of real, named companies or banks, which real-world
  phishing frequently does — this may make some phishing signals
  easier to catch than in the wild.
- **Small, templated vocabulary.** Slot-filled values (5 companies, 10
  dates, 10 amounts, 8 link domains, 10 names per language) repeat
  across rows, which real corpora would not.
- **Why this must NOT be treated as production performance evidence:**
  results measured against this dataset reflect performance on a
  narrow, synthetic, template-derived distribution. A high or low
  score here says nothing reliable about accuracy on real Indic-language
  phishing traffic. It is only useful as a **relative, directional**
  signal (e.g., "does routing through NLLB translation help or hurt
  the baseline classifier on this fixed set of patterns") — not as an
  absolute accuracy claim, and not as a substitute for evaluation on
  real, reviewed, native-language email data.
