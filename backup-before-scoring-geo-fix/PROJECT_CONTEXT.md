# PROJECT_CONTEXT.md

## Objective
AI-Powered Email Threat Detection, GeoLocation and Forensic Intelligence
Platform. One FastAPI backend + one dashboard, supporting Gmail and
Microsoft mailboxes through a single provider-independent analysis
pipeline.

## Team roles
- M1 - Email header / authentication forensics
- M2 - AI / phishing / threat classification
- M3 - Threat intelligence (local feeds + heuristics)
- M4 - Geolocation / infrastructure intelligence
- M5 - Backend integration / API / parser / orchestration (this codebase)
- M6 - Frontend / dashboard

## Current architecture
```
Provider (Gmail | Microsoft | .eml upload)
  -> canonical parser (backend/app/services/email_parser.py)
  -> NormalizedEmail (backend/app/schemas/email_message.py)
  -> Analysis orchestrator (backend/app/services/analysis_service.py)
       -> Cheap header/auth checks (Header & Authentication Analysis)
            backend/app/forensic/m1_header_analyzer.py
       -> Has attachment?
            NO  -> attachment_analysis.py returns immediately
                   (scanned=false, reason="No attachments") - YARA
                   and the magic-byte detector are never invoked.
            YES -> Attachment Security Engine
                   backend/app/services/attachment_analysis.py
                     -> magic bytes: backend/app/services/file_type_detector.py
                     -> SHA-256 (computed at parse time)
                     -> YARA Scanner: backend/app/security/yara/scanner.py
                        (rules: backend/app/security/yara/rules/*.yar)
       -> has_high_severity conditionally forces a deeper rule-based
          scan in the AI stage, even at low ML probability (additive
          only - never skips a stage)
       -> AI Threat Classification: backend/app/services/ml_classifier.py
       -> Threat Intelligence Engine: backend/app/threat_intel/*
       -> IP Geolocation & Infrastructure: backend/app/services/geolocation.py
       -> Composite Risk Engine: backend/app/services/risk_engine.py
          (a YARA high/medium match forces an explicit risk floor -
          cannot be diluted by a low AI/body score)
  -> Explainable result dict
  -> SOC Dashboard (static/*)
```
One pipeline. Gmail and Microsoft differ only at the Mail Provider
Layer (`backend/app/providers/gmail_provider.py`,
`backend/app/providers/microsoft_provider.py`), both implementing
`backend/app/providers/base.py::MailProvider`.

**Functional naming**: "M1"-"M6" were internal team-task labels only
and must not appear in the product, docs, or presentation. Use: Email
Parser, Header & Authentication Analysis, AI Threat Classification,
Threat Intelligence Engine, Attachment Security Engine, YARA Scanner,
URL/Domain Analysis, IP Geolocation & Infrastructure Analysis, Risk
Engine, Mail Provider Layer, OAuth Authentication, SOC Dashboard. The
API response still has `m1`/`m2`/`m3`/`m4` dict keys internally (not
yet renamed - see Known limitations) - the dashboard renders them
under functional section headings (Authentication, AI / Body
Analysis, Threat Intelligence, Geolocation) so no "M1"/"M2" label
reaches the UI.

## API contracts
- M1 input/output: `backend/app/schemas/m1.py` (matches the original
  documented contract exactly - sender/reply_to/return_path/received
  headers/urls/attachments in, spf/dkim/dmarc/origin_ip out).
- M3 output is source-transparent: every result carries
  `"source": "phishtank" | "spamhaus_drop" | "local_heuristics"` and
  never claims an external provider was consulted when it wasn't.
- Unified result: `backend/app/schemas/analysis.py::AnalysisResult`.

## Provider integrations
- **Gmail**: OAuth Authorization Code (web) flow, `gmail.readonly`
  scope, native `nextPageToken` pagination.
- **Microsoft**: MSAL confidential-client Authorization Code flow,
  delegated `Mail.Read`/`User.Read`/`offline_access` scopes, native
  `@odata.nextLink` pagination. Requires `internetMessageHeaders` to
  be requested explicitly to recover SPF/DKIM/DMARC/Received data.
- Core M3 threat intelligence requires **no end-user API keys** -
  PhishTank + Spamhaus DROP are local, bundled feeds.

## File ownership (this merge)
- `backend/app/forensic/m1_header_analyzer.py` - M1's file, copied
  verbatim, unmodified.
- `backend/app/services/threat_classifier.py` - the rule-based keyword
  classifier, copied verbatim.
- `backend/app/services/risk_engine.py`, `email_parser.py`,
  `ml_classifier.py`, `geolocation.py`, `analysis_service.py`,
  `scan_service.py`, `store.py` - written/consolidated fresh for this
  merge (see MERGE_LOG.md for what each replaces).
- `backend/app/providers/*`, `backend/app/auth/*`,
  `backend/app/main.py`, `static/*` - written fresh; the described
  friend's `api/server.py` / `api/store.py` / `static/*` files never
  actually arrived in the workspace (see MERGE_LOG.md).
- `sih.py` - ignored entirely per explicit instruction, not deleted,
  not imported anywhere.

## Known limitations
- **In-memory storage only.** Sessions, OAuth tokens, scan results,
  and the result cache all live in a single Python process's memory
  (`backend/app/auth/session.py::SESSION_STORE`,
  `backend/app/services/store.py::STORE`). Restarting the server
  clears everything. Acceptable for the hackathon; if persistence is
  needed, add SQLite rather than new infrastructure.
- **OAuth needs real credentials to run.** Neither
  `GOOGLE_CLIENT_ID`/`GOOGLE_CLIENT_SECRET` nor
  `MICROSOFT_CLIENT_ID`/`MICROSOFT_CLIENT_SECRET` are set by default.
  Without them, `/auth/google/login` and `/auth/microsoft/login`
  return a clear 503 rather than silently failing. The `.eml` upload
  path (`POST /api/analyze`) works with zero configuration and is the
  fastest way to demo the analysis pipeline.
- **This sandbox has no outbound network access**, so `fastapi`,
  `pydantic`, `google-auth-oauthlib`, `googleapiclient`, and `msal`
  could not be installed or run live here. Every business-logic module
  (parser, M1, M2, M3, M4, risk engine, scan concurrency/failure
  isolation, session/result ownership isolation) was integration-
  tested directly against real trained models and synthetic raw
  emails using a tiny local pydantic shim
  (`/home/claude/pyshim`, not part of the shipped project). The
  FastAPI route wiring itself was reviewed carefully but not executed
  live; run it in a real environment with `pip install -r
  requirements.txt` to confirm.
- **M2 model quirk**: the trained phishing model can return
  surprisingly high phishing probability (~60%) on very short, sparse
  legitimate text with a single link (observed on a synthetic short
  internal-email test). It still stayed within LOW risk overall
  because the risk engine weighs it alongside other evidence, but if
  you see a short legitimate email scoring higher than expected,
  this is the likely cause - not a pipeline bug. Retraining/expanding
  the phishing model's training data would address it; out of scope
  for this merge.
- **scikit-learn version mismatch warning**: the bundled `.pkl` models
  were trained with scikit-learn 1.9.0; this sandbox has 1.8.0
  installed, which prints `InconsistentVersionWarning` on load but
  loads and predicts correctly. Recommend matching scikit-learn
  versions in the real deployment environment.
- **Microsoft provider is implemented but never tested against a real
  tenant** (no credentials available). The Graph API calls follow the
  documented v1.0 REST contract; validate against a real app
  registration before the demo.
- **YARA is not actually installed in the sandbox this project was
  built in, and could not be installed (no outbound network access,
  confirmed with both `pip install yara-python` and `pip download
  yara-python` failing with "No matching distribution found").**
  `backend/app/security/yara/scanner.py` is written defensively: it
  detects the missing import and every scan call returns
  `{"scanned": false, "matches": [], "reason": "yara-python is not
  installed in this environment (...)"}`  rather than faking a match
  or a clean result. `requirements.txt` includes `yara-python`; once
  installed in a real environment with network access, the scanner
  activates automatically with no code changes - `_get_yara_module()`
  re-checks on first use. **The regression test for a genuine YARA
  match ("Test D") could not use a real match for this reason** - it
  mocks only `yara_scanner.scan_bytes()`'s return value and runs the
  rest of the real pipeline (attachment flagging, the conditional
  AI-scan trigger, the risk-engine floor rule, evidence_sources) for
  real. See MERGE_LOG.md for the full test output.
- **M1-M4 dict keys in the internal API response were not renamed**
  to functional names this pass (e.g. the response still has
  `result["m1"]`, not `result["authentication"]`). Renaming this
  touches `analysis_service.py`'s return shape, every consumer in
  `main.py` (5 aggregation endpoints), and `app.js` - correctly out of
  scope for the "verify + fix real bugs" instruction that governed
  this pass, since it isn't a bug, it's a naming migration. The
  dashboard already renders these under functional section headings
  (Authentication, Header/Routing, Attachment Security, AI/Body
  Analysis, Geolocation, Threat Intelligence), so no "M1"/"M2" label
  reaches the UI even though the wire format still uses them
  internally.
- **Scan-level attachment/YARA statistics** (e.g. "18 with attachment,
  3 YARA matches" on the Scans page) are not yet implemented - the
  per-email `attachment_analysis`/`attachments[].yara` data needed to
  compute them is now present in every stored result, so this is a
  straightforward addition to `/api/reports/summary` when needed, not
  a redesign.

## Current working endpoints
See `backend/app/main.py`:
`/health`, `/auth/google/{login,callback,status}` + POST logout,
`/auth/microsoft/{login,callback,status}` + POST logout,
`GET /api/emails`, `POST /api/scan`, `GET /api/scan/{scan_id}`,
`POST /api/analyze` (file upload), `GET /api/analysis/{provider}/{account_id}/{message_id}`,
`GET /` (dashboard).

## How to run
```
python -m venv venv
source venv/bin/activate         # or venv\Scripts\activate on Windows
pip install -r requirements.txt
cp .env.example .env             # fill in OAuth credentials if testing OAuth
uvicorn backend.app.main:app --reload --port 8000
```
Open http://localhost:8000. Without OAuth credentials configured, use
the "No mailbox connected yet" upload panel to analyze a `.eml` file
directly - no setup required.

## Current TODOs
- Wire real Google Cloud / Azure OAuth credentials and do a live
  end-to-end OAuth test (blocked on credentials, not code).
- Add SQLite-backed persistence if time allows (P1).
- Consider trimming/rebuilding `phishtank.json` (currently ~17MB) if
  load time on startup becomes noticeable.
