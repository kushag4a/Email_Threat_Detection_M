# LaterBugFixes — ValorProtects

This is the persistent handoff/checklist for future debugging and feature work.
It records known bugs, gaps, limitations, deferred features, regression tests, and
implementation notes identified from the current ValorProtects documentation.

**Project path:** `C:\Users\Kushagra Singh\Downloads\EmailThreatDetection-v2\project`

## 1. Known correctness bugs

### B1 — Gmail provider-name inconsistency
**Status:** KNOWN BUG / LATENT

Routes/frontend use `google`, while `GmailProvider.name` uses `gmail`.
Stored results therefore use `gmail`, while the direct analysis lookup route can
be called with `google`.

Affected route:
`GET /api/analysis/{provider}/{account_id}/{message_id}`

The frontend currently does not call this route.

**Future fix:** standardize provider identifiers across OAuth, routes, storage,
and API responses, then test the direct analysis lookup.

### B2 — Custom Email upload results are ephemeral
**Status:** KNOWN PRODUCT GAP

`POST /api/analyze/batch` returns results directly but does not store them in
`STORE`. Therefore uploaded `.eml` results do not populate Scans, Cases, Reports,
or Threat Intelligence history.

**Future decision:** keep uploads ephemeral, store them for the session, or
persist them to durable storage.

### B3 — No automated test suite
**Status:** KNOWN GAP

Current verification is mostly ad-hoc scripts/manual testing rather than a
repeatable `pytest` suite.

Add automated tests for parser, auth/header checks, attachments, YARA, risk,
threat intelligence, sessions, scan failure isolation, API validation, uploads,
and provider normalization.

## 2. YARA / attachment security

### A1 — Real YARA engine must be installed and tested
**Status:** PARTIAL

The YARA code path exists, but `yara-python` was unavailable in the development
environment, so real YARA matching was not executed there.

**Test:** no attachment -> scanner not called; normal PDF -> scanned with no
malicious match; rule-triggering sample -> match returned.

### A2 — Improve YARA rules
**Status:** FUTURE

Expand beyond the current local/demo rules and add rule regression tests and
versioning.

### A3 — Improve file-type / magic-byte detection
**Status:** FUTURE

Expand signatures and mismatch/malformed-file detection.

### A4 — Add attachment statistics
**Status:** GAP

Future Scans/Reports metrics:
- total analyzed
- no attachment
- with attachment
- YARA matches
- suspicious attachment types
- attachment processing time

### A5 — Preserve attachment-first order
**Status:** REGRESSION CHECK

No attachment:
`Parser -> cheap checks -> AI/body -> enrichment -> risk`

Attachment:
`Parser -> cheap checks -> magic bytes -> SHA-256 -> YARA -> AI/body -> enrichment -> risk`

Strong attachment evidence must not be erased by a low body-AI score.

## 3. AI / classification

### C1 — scikit-learn/joblib compatibility warning
**Status:** KNOWN LIMITATION

Models load and predict, but the documentation notes a dependency/version warning.

**Future fix:** pin compatible versions and keep model artifacts reproducible.

### C2 — Add model regression corpus
**Status:** GAP

Keep fixed examples for legitimate mail, phishing, BEC, suspicious mail,
normal attachments, and malicious attachments.

### C3 — Preserve false-positive regression
A legitimate newsletter must not become malicious merely because it has a PDF,
many URLs, Google infrastructure, or mailing-list headers.

## 4. Threat intelligence

### T1 — Feed freshness is approximate
**Status:** LIMITATION

The UI uses local feed file modification time as a proxy for last update. There is
no dedicated update-tracking database.

**Future fix:** record feed version/update metadata explicitly.

### T2 — External enrichment remains optional
Core PhishTank/Spamhaus intelligence is local and does not require end-user API
keys. Keep that property unless there is an explicit organization-managed
enrichment design.

## 5. Geolocation

### G1 — Live external geolocation needs verification
**Status:** PARTIAL

Verify public-IP lookup, cache hits, failure handling, and private/invalid IP handling
in a real environment.

## 6. OAuth / accounts

### O1 — Google OAuth live round-trip
**Status:** NOT LIVE VERIFIED IN THE RESTRICTED DEVELOPMENT ENVIRONMENT

Verify:
login -> consent -> callback -> token exchange -> dashboard -> inbox -> logout.

### O2 — Microsoft OAuth live round-trip
**Status:** NOT LIVE VERIFIED

Needs a real Azure app registration/tenant test.

### O3 — Keep-me-signed-in
**Status:** NOT IMPLEMENTED

No 30-day option exists. Do not expose it until long-lived sessions are designed
and secured.

## 7. Security hardening

### S1 — Session secret fallback
**Status:** SECURITY GAP

There is a clearly labeled development fallback secret.

**Future fix:** fail fast in production when `SESSION_SECRET_KEY` is missing.

### S2 — No dedicated CSRF token for normal API routes
**Status:** SECURITY GAP

OAuth uses state protection, but ordinary cookie-authenticated state-changing API
routes do not have a dedicated CSRF token mechanism.

### S3 — No rate limiting
**Status:** SECURITY GAP

No route-level rate limits currently exist for OAuth, inbox, scans, or analysis.

### S4 — Direct analysis endpoint account/message scoping edge case
**Status:** SECURITY / ARCHITECTURE EDGE CASE

`GET /api/analysis/{provider}/{account_id}/{message_id}` relies on the storage key
and session ownership. Future hardening should also scope requests to the
currently connected account/provider.

### S5 — SESSION_COOKIE_SECURE missing from env example
**Status:** CONFIGURATION GAP

`SESSION_COOKIE_SECURE` exists in code but should be documented in `.env.example`.

Local HTTP development may use false; production behind HTTPS should use true.

## 8. Storage / persistence

### P1 — Storage is in-memory
**Status:** MAJOR PRODUCTION GAP

Sessions and results are process-local. Restarting clears them.

Future:
- PostgreSQL for durable data
- Redis for shared session/cache/short-lived state

### P2 — Multi-worker / multi-container deployment not ready
Current in-memory state is not shared across workers/processes.

### P3 — Uploaded attachment bytes stay transient
Current behavior does not persist raw `content_bytes`. Preserve this unless
controlled evidence storage is intentionally designed.

## 9. Scanning / performance

### PERF1 — Real Gmail 100-message benchmark
**Status:** REQUIRED LIVE TEST

Measure:
fetch, parse, attachment, AI, threat-intel, geolocation, risk, total time,
success/failure counts.

### PERF2 — Prevent event-loop blocking regression
Do not put blocking provider/model/network calls directly inside `async` routes.
Preserve the executor/non-blocking pattern.

### PERF3 — Preserve bounded concurrency
Current scan concurrency is bounded. Tune only using measurements.

### PERF4 — Preserve failure isolation
One bad message must not terminate the entire batch.

## 10. Frontend gaps

### F1 — Full theme system is partial
Current: six presets + system mode.

Not implemented from the broader request:
glassy family, gradient family, wallpaper, dim/blur, derived accent behavior.

### F2 — GitHub update checker
**Status:** NOT IMPLEMENTED

Future:
latest/current version, minor/major distinction, major-update indicator,
hover preview, graceful offline failure.

### F3 — Terms & Conditions
**Status:** NOT IMPLEMENTED

Need modal, acceptance action, and persisted acceptance state.

### F4 — Settings/About stale text
**Status:** CONTENT GAP

Review About text so it matches the current ValorProtects implementation.

### F5 — Inbox search/filter
**Status:** CURRENT LIMITATION

No full inbox search/filter is implemented.

### F6 — Inbox folders
**Status:** CURRENT LIMITATION

Only INBOX is supported.

### F7 — Accessibility audit
**Status:** INCOMPLETE

Some contrast/disabled-button work exists, but there has not been a complete WCAG-style
audit across all themes.

### F8 — Custom Email history
Related to B2: upload results currently do not flow into historical analytics.

## 11. Scans page

### SC1 — Rich hover interactions
**Status:** PARTIAL / REVIEW NEEDED

Current page has a trend visualization, high-risk history, and suspicious-source
grouping. The richer requested hover behavior should be checked in the live UI:
email preview, sender/domain/count/reason, graph-point daily count/distinct senders,
and clear critical markers.

### SC2 — Attachment-specific scan metrics
See A4. Values must always come from actual scan results.

## 12. Threat Intelligence product gaps

### TI1 — Organization protection policies
**Status:** NOT IMPLEMENTED

Future:
external-email policy, allowlists, sender/domain trust or block lists,
content/keyword policies, alert/quarantine/delete actions, organization mode.

### TI2 — Personal protection
**Status:** NOT IMPLEMENTED

Future:
sender/domain block, smart mute, optional auto-archive/delete.

### TI3 — No true pre-delivery blocking
**Status:** IMPORTANT LIMITATION

Current OAuth-based MVP analyzes already-delivered mail retrieved through a provider
API. True pre-delivery blocking/quarantine requires enterprise mail-gateway/admin
integration.

## 13. Cases

### CA1 — Cases are lightweight
Current grouping is mainly by sender domain.

Future clustering could use subject, URLs/domains, IPs, attachment hashes, timeline,
and campaign relationships.

### CA2 — Case workflow
**Status:** NOT IMPLEMENTED

Future:
status, analyst assignment, notes, evidence, timeline, close/reopen, export.

## 14. Reports

### R1 — Date-range filtering
**Status:** NOT IMPLEMENTED

### R2 — Export/download
**Status:** NOT IMPLEMENTED

Possible formats: PDF, CSV, JSON.

### R3 — Uploaded-file analytics
See B2.

## 15. API / technical debt

### D1 — Internal m1/m2/m3/m4 result keys
**Status:** TECHNICAL DEBT

UI uses functional names, but some API data still contains internal keys.
Renaming would be a breaking API change and should be planned carefully.

### D2 — Dead import in main.py
The documentation inspection found an unused threat-intel import in `main.py`.
Remove only after confirming there is no intended import side effect.

### D3 — Legacy code review
Do not revive `sih.py`. Review older/duplicate files before deleting anything.

### D4 — README alignment
Keep README aligned with current OAuth, attachment-first flow, YARA status,
limitations, and future architecture.

## 16. Future production architecture

Not current runtime:

`Browser -> Node/API Gateway -> Redis -> FastAPI workers -> PostgreSQL/object storage
-> Gmail/Microsoft/enterprise integration`

Do not implement this solely for the hackathon.

## 17. Non-regression security rules

Never execute attachments, launch scripts, enable macros, open attachments with
external applications, or execute YARA matches.

Never expose OAuth client secrets or provider tokens to frontend JavaScript.

Never claim YARA is antivirus.

Never claim YARA alone decides the final verdict.

Never claim true pre-delivery blocking without a gateway/admin integration.

Never fabricate scan statistics.

## 18. Regression checklist

### Analysis
- [ ] No-attachment email skips YARA and magic-byte scanning.
- [ ] Attachment email follows magic bytes -> hash -> YARA -> AI.
- [ ] AI/body analysis still runs with attachments.
- [ ] Strong attachment evidence survives low AI/body score.
- [ ] Legitimate newsletter remains low risk.
- [ ] Phishing regression remains high/critical.

### Authentication
- [ ] Google OAuth live test
- [ ] Google logout
- [ ] Microsoft OAuth live test
- [ ] Microsoft logout
- [ ] Tokens never reach frontend
- [ ] Cross-session result isolation

### Scanning
- [ ] 5-message scan
- [ ] 100-message scan
- [ ] One-message failure does not kill batch
- [ ] Progress polling remains responsive

### Frontend
- [ ] Sidebar navigation
- [ ] Inbox loading
- [ ] Scan progress
- [ ] Detail panel
- [ ] Theme persistence
- [ ] Custom Email batch
- [ ] Empty states show real zero/empty values

### API
- [ ] Page sizes 5/10/20/50/100
- [ ] Invalid page size rejected
- [ ] 25MB per-file limit
- [ ] 10-file batch limit
- [ ] Provider identifier is consistent

## 19. Recommended implementation order

### Priority 0 — demo reliability
1. Run current app locally.
2. Fix provider-name inconsistency.
3. Live-test Google scan.
4. Enable and test real YARA.
5. Re-test attachment-first flow.
6. Benchmark 5 and 100 message scans.
7. Add critical automated regression tests.

### Priority 1 — product completeness
8. Decide Custom Email persistence.
9. Add attachment statistics.
10. Improve Scans interactions.
11. Add report filtering/export.
12. Fix stale About text.
13. Clean API naming drift.

### Priority 2 — security hardening
14. Production session-secret validation.
15. Explicit CSRF protection.
16. Rate limiting.
17. Shared persistent storage.

### Priority 3 — advanced product
18. Organization policies.
19. Personal protection.
20. Advanced Cases.
21. Update checker.
22. T&C acceptance.
23. Full theme system.
24. Enterprise mail-gateway enforcement.

### Priority 4 — production scaling
25. Redis
26. PostgreSQL
27. Node/API gateway
28. multi-worker/container architecture
29. centralized observability

## 20. Current starting procedure

Open PowerShell in:

`C:\Users\Kushagra Singh\Downloads\EmailThreatDetection-v2\project`

Run:

```powershell
Get-Location
Get-ChildItem
```

Then:

```powershell
.\.venv\Scripts\python.exe --version
```

If `.venv` does not exist:

```powershell
py -m venv .venv
```

Install:

```powershell
.\.venv\Scripts\python.exe -m pip install -r requirements.txt
```

Compile before edits:

```powershell
.\.venv\Scripts\python.exe -m compileall backend
```

Start:

```powershell
.\.venv\Scripts\python.exe -m uvicorn backend.app.main:app --reload
```

Open:

`http://127.0.0.1:8000`

Swagger:

`http://127.0.0.1:8000/docs`

### First work session
Do not add a new feature immediately.

1. Confirm the server starts.
2. Open Dashboard.
3. Open Custom Email.
4. Analyze one legitimate `.eml`.
5. Analyze one phishing-style `.eml`.
6. Inspect the results/detail panel.
7. Check terminal timing/error logs.
8. Then fix one issue at a time, starting with the highest-value correctness issue.

## 21. Change log

| Date | Item | Result |
|---|---|---|
| 2026-09-06 | Initial LaterBugFixes baseline | Recorded known bugs, gaps, security issues, deferred features, and testing plan |
