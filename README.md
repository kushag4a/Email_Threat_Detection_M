🛡️ ValorProtects

AI-Powered Email Threat Detection, Geolocation & Forensic Intelligence Platform

ValorProtects is a provider-independent email security platform built around a FastAPI backend and an analyst-focused dashboard. It analyzes Gmail/Microsoft mailbox messages or uploaded .eml evidence through a staged pipeline combining machine learning, email authentication/header analysis, URL and attachment inspection, threat intelligence, geolocation/infrastructure context, BEC detection, and explainable risk scoring.

Security principle: email is treated as hostile evidence. Attachments are inspected without execution, and message-originated remote resources are not executed as part of analysis.

✨ What ValorProtects Detects

ValorProtects keeps different threat classes conceptually separate:

Phishing / credential theft — production V2 text classifier

BEC / financial fraud — deterministic behavioral and phrase-based detection

Brand impersonation / lookalike domains

Authentication spoofing — SPF, DKIM, DMARC and related identity signals

Malicious redirects and URL obfuscation

Malware / suspicious attachments — file-type/magic-byte inspection and YARA

Threat-intelligence matches — local PhishTank / Spamhaus data

Suspicious infrastructure / origin context — geolocation and related evidence

These signals are combined by the explainable risk engine rather than treating one ML probability as the final security decision.

🧭 Analysis Pipeline

Browser / Dashboard
        │
        ▼
     FastAPI
        │
        ├── Gmail / Microsoft provider
        │
        └── .eml upload
                │
                ▼
       Canonical email parser
                │
                ▼
      Conditional attachment scan
       (only when attachments exist)
                │
                ▼
      Header / authentication analysis
      SPF • DKIM • DMARC • identity
                │
                ▼
       AI phishing classification
                │
                ├── Production V2
                │
                └── Indic NLLB advisory path
                │
                ▼
       Threat intelligence / URLs
                │
                ▼
       Geo / infrastructure context
                │
                ▼
          BEC detection
                │
                ▼
        Explainable risk engine
                │
                ▼
       Threat types + evidence
       + score + severity
       + recommended action

🧠 Production ML Model

The production phishing classifier is V2:

backend/app/models/v2/

V2 uses TF-IDF text features with a calibrated linear classifier.

Previously evaluated model versions include V1 and V2.1, but V2 is the current production model. V2.1 was an experimental hard-mining variant and is not promoted to production.

The repository intentionally does not retrain or silently replace the production model during application execution.

🌏 Indic Multilingual NLLB Evaluation

ValorProtects includes an offline research/evaluation path for Indic-language email.

The experiment compares:

Path A:
Indic text ───────────────► V2

Path B:
Indic text ─► NLLB-200 ─► English ─► V2

The NLLB path is advisory/prototype-only. It does not alter the live risk score or production scan result.

Evaluation dataset

datasets/evaluation/indic/indic_eval.csv

The current benchmark contains:

1,100 samples

100 samples per language

11 Indic languages

605 legitimate

495 phishing

all rows marked as synthetic

Languages:

hin_Deva  tel_Telu  tam_Taml  kan_Knda  mal_Mlym
mar_Deva  ben_Beng  guj_Gujr  ory_Orya  pan_Guru
urd_Arab

Validate the dataset:

.\.venv\Scripts\python.exe scriptsalidate_indic_eval_dataset.py

Run a small smoke test:

.\.venv\Scripts\python.exe scripts\evaluate_indic_nllb.py --lang hin_Deva --max-per-lang 3

Run the full benchmark:

.\.venv\Scripts\python.exe scripts\evaluate_indic_nllb.py

Results are written to:

datasets/evaluation/indic/results/

The benchmark records per-language results, pooled and macro metrics, paired A/B outcomes, McNemar analysis, latency, failures, and per-sample translated English text for inspection.

Current benchmark result

The current 1,100-sample run produced:

Metric

Path A: Indic → V2

Path B: Indic → NLLB → English → V2

Accuracy

79.73%

85.00%

Precision

72.52%

83.54%

Recall

88.48%

83.03%

F1

79.71%

83.28%

The paired run had:

1,100 / 1,100 successful Path A classifications

1,100 / 1,100 successful translations

1,100 / 1,100 successful Path B classifications

1,100 / 1,100 paired samples

These figures are benchmark-specific only. The dataset is synthetic and template-derived and has not been native-speaker reviewed. They must not be presented as production accuracy.

🧪 Evaluation Methodology

The same email is passed through both paths, making the comparison paired at the sample level.

The evaluator:

keeps failed operations separate from legitimate predictions

exposes explicit evaluation denominators

reports micro/pooled and macro averages

computes paired disagreement counts

runs McNemar's test when applicable

measures baseline, translation, translated-classifier, and total Path B latency

records source and translated text for diagnostic inspection

produces reproducible JSON/CSV outputs

Model-free evaluation tests live in:

tests/test_indic_evaluation.py

🔐 Security & Privacy Design

OAuth tokens remain server-side and are not exposed to frontend JavaScript.

OAuth callback state is verified for CSRF protection.

Cached/scanned mailbox data is scoped to the authenticated session, provider, account, and message.

Threat intelligence feeds are local; end users do not need their own threat-intel API keys for the core pipeline.

Attachments are analyzed without executing them.

The old sih.py IMAP-based architecture with hardcoded credentials is not used.

Local secrets belong in .env and must never be committed.

📬 Mailbox Support

Gmail

Configure a Google OAuth web application and use:

http://localhost:8000/auth/google/callback

Set:

GOOGLE_CLIENT_ID
GOOGLE_CLIENT_SECRET
GOOGLE_REDIRECT_URI

Microsoft

Configure an Azure app registration with delegated Microsoft Graph permissions:

Mail.Read
User.Read
offline_access

Callback:

http://localhost:8000/auth/microsoft/callback

Set:

MICROSOFT_CLIENT_ID
MICROSOFT_CLIENT_SECRET
MICROSOFT_TENANT_ID

⚡ Mailbox Pagination & Scanning

The dashboard supports page sizes of:

5 / 10 / 20 / 50 / 100

Provider-native pagination is used rather than downloading the full mailbox and slicing it locally.

Inbox scans operate on the current page with bounded concurrency. A message that fails to parse or fetch does not abort the remainder of the batch; the dashboard reports the requested/analyzed/failed/skipped summary.

🚀 Quick Start

1. Create and activate a virtual environment

Windows:

python -m venv .venv
.\.venv\Scripts\Activate.ps1

2. Install dependencies

pip install -r requirements.txt

3. Create local configuration

Copy-Item .env.example .env

Fill in only the credentials/services you actually use.

4. Start ValorProtects

uvicorn backend.app.main:app --reload --port 8000

Open:

http://localhost:8000

You can use .eml upload mode without configuring OAuth.

🧪 Testing

Run the complete test suite:

.\.venv\Scripts\python.exe -m pytest -q

The current release checkpoint has the complete regression suite passing.

Useful focused suites include:

.\.venv\Scripts\python.exe -m pytest tests	est_risk_engine_config.py -q
.\.venv\Scripts\python.exe -m pytest tests	est_risk_scoring_safety.py -q
.\.venv\Scripts\python.exe -m pytest tests	est_nllb_translation.py -q
.\.venv\Scripts\python.exe -m pytest tests	est_indic_evaluation.py -q

📁 Important Project Areas

backend/
└── app/
    ├── multilingual/          # NLLB prototype
    ├── models/v2/             # production V2 phishing model
    ├── providers/             # Gmail / Microsoft providers
    ├── services/              # parsing, analysis, BEC, scanning, risk
    └── threat_intel/          # local threat-intelligence logic

datasets/
└── evaluation/
    └── indic/                 # offline multilingual benchmark

scripts/
├── evaluate_indic_nllb.py
├── generate_indic_eval_dataset.py
└── validate_indic_eval_dataset.py

tests/
└── ...                        # regression and subsystem tests

static/
└── ...                        # dashboard assets

For deeper architecture/contracts/limitations, see:

PROJECT_CONTEXT.md
ARCHITECTURE.md
MERGE_LOG.md

⚠️ Known Limitations

The Indic benchmark uses synthetic, template-derived emails.

The synthetic Indic text has not received native-speaker review.

NLLB translation quality is surfaced for inspection but is not independently scored against reference translations.

The first NLLB inference in a process includes model-loading cost, so median/p95 latency are more informative than a short-run mean.

OAuth integrations require real credentials for live mailbox access.

scikit-learn may emit artifact-version mismatch warnings when model files were produced under a slightly different patch version; this does not by itself indicate that loading failed.

NLLB remains an evaluation/prototype pathway and is not currently part of the production risk score.

A benchmark result on synthetic data is not a substitute for evaluation on real, native-reviewed email.

🔭 Roadmap

Spam classification as a separate signal from phishing.

Multilingual evaluation using real/native-reviewed data where legally and practically available.

Evidence-based calibration only after new signals have been evaluated.

Final analyst dashboard flow with drill-down explanations for every risk contribution.

Production hardening and release cleanup.

The design intentionally keeps:

PHISHING ≠ SPAM ≠ MALWARE ≠ BEC

rather than forcing every threat type into one classifier.

📚 Documentation

PROJECT_CONTEXT.md — architecture, contracts, and limitations

ARCHITECTURE.md — system diagrams

MERGE_LOG.md — major merges/replacements and rationale

datasets/evaluation/indic/README.md — Indic dataset and benchmark methodology

⚖️ Project Status

ValorProtects is an academic/security-research and demonstration platform.

Production-style security controls are implemented for the local application, but benchmark figures—especially those derived from synthetic evaluation data—should be treated as engineering/research measurements rather than claims about real-world detection rates.