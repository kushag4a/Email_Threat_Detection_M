# MERGE_LOG.md

## Honesty note on "the friend's project"
The task described a second, already-working project folder
containing `api/server.py`, `api/store.py`, `static/index.html`,
`static/styles.css`, `static/app.js`, and `credentials.json`, plus a
working Gmail OAuth + dashboard. After being told these files had
been added to the workspace, I searched explicitly
(`find /mnt/user-data/uploads -iname "*server*" -o -iname "*store*" ...`)
and confirmed **none of them were ever actually present** - only a
`README_DASHBOARD.md` describing what they were supposed to do, and a
`gmail_pipeline.py` that uses those models. What did arrive alongside
that message was a batch of additional *M5* backend files
(`m1_adapter.py`, `analysis_service.py`, `main.py`, `domain_extractor.py`,
`url_extractor.py`, `url_normalizer.py`, `threat_intel.py`,
`local_engine.py`, `m1_input.py`, `m1_output.py`, `phishtank.json`,
`spamhaus_drop.txt`), all referencing a `backend.app.*` /
`forensic.*` / `threat_intel.*` package layout that didn't exist as
real directories, plus a `parse_eml_file` call with no matching
function anywhere in the upload.

Per the explicit instruction to stop asking and proceed, `api/server.py`,
`api/store.py`, and the `static/*` dashboard were **built fresh** in
this merge, implementing the architecture the README described,
rather than recovered as a "preserved" artifact. This log calls that
out plainly instead of claiming a merge that didn't happen.

## What was preserved unmodified
- `backend/app/forensic/m1_header_analyzer.py` - M1's contract
  (input/output shape) already matched the documented spec exactly;
  copied verbatim.
- `backend/app/services/threat_classifier.py` - rule-based keyword
  threat scoring; copied verbatim, only its import location changed.
- The trained ML artifacts (`phishing_model.pkl`,
  `phishing_vectorizer.pkl`, `multithreat_model.pkl`,
  `multithreat_vectorizer.pkl`) - reused as-is. Verified they load and
  predict correctly with the scikit-learn/joblib available in this
  environment (see PROJECT_CONTEXT.md for the version-mismatch
  warning).
- The `gmail_pipeline.py` text-assembly convention for feeding the
  models (`From:` / `Reply-To:` / `Return-Path:` / `Subject:` / body)
  and its 0.40 phishing-probability threshold for triggering
  rule-based forensics - both reproduced in `ml_classifier.py`.
- PhishTank + Spamhaus DROP local feed *data* (`phishtank.json`,
  `spamhaus_drop.txt`) copied as-is.

## What was consolidated (duplicate implementations removed)
| Responsibility | Duplicates found | Canonical choice | Why |
|---|---|---|---|
| Email parsing | `email_parser.py`, `email_security_features.py`, `gmail_reader.extract_email_body`, `gmail_pipeline`'s inline parsing | New `backend/app/services/email_parser.py` | None of the four handled the full set required (repeated headers + HTML body + attachments + SHA-256 + URLs) in one place; each is a strict subset. Consolidating avoids four call sites drifting out of sync. |
| PhishTank lookup | Two near-identical `phishtank_local.py` (flat-upload version re-read+re-scanned the 17MB JSON file on every single call) | Rewritten version that indexes the feed once at first use | Real performance bug for a 100-email scan: the original did O(N) file reads and O(N*M) linear scans across N emails' URLs. |
| Spamhaus lookup | Two near-identical `spamhaus.py` (same re-parse-every-call issue) | Rewritten version, networks parsed once and cached | Same reasoning as PhishTank. |
| Risk scoring | Original `risk_engine.py` | Rewritten `risk_engine.py`, same shape/output, different weights | The original's `url_count > 0 -> +5` rule directly violates the project's explicit false-positive requirement (a newsletter with 2 links would get flagged for having links at all). Replaced with intelligence-driven URL scoring (PhishTank/Spamhaus listing, local heuristic score) - see risk_engine.py's documented weights and the regression tests below. |
| OAuth (Gmail) | `gmail_reader.py`'s `InstalledAppFlow` + `run_local_server()` | New web Authorization Code flow (`backend/app/auth/google_oauth.py`) | `InstalledAppFlow` writes one shared `token.json` and pops a local browser - it has no way to keep User A's and User B's tokens apart on a running server. This is an architectural incompatibility with the spec's user-isolation requirement, not a style preference. Documented here per "choose the implementation that is already demonstrably working, or the one that satisfies the actual requirement when neither fully does." |
| Dashboard / API server | Described but never delivered (`api/server.py`, `api/store.py`, `static/*`) | Built fresh (`backend/app/main.py`, `static/*`) | Nothing to merge against - see honesty note above. |

## What was ignored entirely
- `sih.py` - per explicit instruction. Uses hardcoded IMAP
  credentials and a different geolocation approach. Not imported
  anywhere, not deleted from the source tree.

## Bugs found and fixed during integration testing
1. **`email.py` filename collision.** One uploaded file was named
   `email.py`, shadowing Python's stdlib `email` module when the
   working directory was on `sys.path` - this silently broke
   `numpy`/`scikit-learn` imports. Fixed by naming the canonical
   schema module `email_message.py` instead.
2. **False-positive Reply-To/Return-Path mismatch.** The original
   `email_security_features.py` compared raw header strings
   (`"SCOPE Newsletter <newsletter@scope.org>"` vs
   `"newsletter@scope.org"`) and flagged this as a mismatch purely
   because of the display name. Caught by running a synthetic
   SCOPE-newsletter-style email through the real end-to-end pipeline;
   fixed in `analysis_service._header_analysis` by comparing addresses
   extracted with `email.utils.parseaddr` instead of raw strings.
   Re-verified against both the newsletter case (no false mismatch)
   and the phishing regression case (real mismatch still detected).

## Regression tests run (see PROJECT_CONTEXT.md for the testing-environment caveat)
- Synthetic SCOPE-newsletter-style email (3 Received hops, Google
  relay, SPF/DKIM/DMARC pass, 2 tracking-style URLs, PDF attachment)
  through the real end-to-end pipeline: **LOW, score 6, no false
  reasons.**
- Synthetic phishing email (SPF/DKIM/DMARC fail, Reply-To/Return-Path
  mismatch, PhishTank-listed URL, `.exe` attachment) through the same
  pipeline: **CRITICAL, score 100 (raw dict inputs) / 89 (full
  end-to-end via parser), all expected reasons present.**
- Batch scan of 9 synthetic messages (1 deliberately raising an
  exception) through `scan_service.run_scan`: 8 analyzed, 1
  `analysis_failed`, scan still completed - confirms per-message
  failure isolation.
- Cross-session scan lookup: session B could not read session A's
  scan - confirms ownership isolation.
- Microsoft Graph JSON message normalized through `parse_graph_message`
  and run through the full pipeline successfully (provider-independence
  check) - not tested against a real Graph tenant (no credentials
  available).

## Pass 2: production bugfix + P0/P1 demo-completion pass

### Root-cause bugs found and fixed
1. **`/api/emails` returned bare `{message_id, thread_id}` pairs** -
   this is exactly why the live inbox showed sender=`—`,
   subject=`(no subject)`, date=`—` despite a real inbox. Fixed by
   adding `MailProvider.get_message_summary()` (cheap, metadata-only
   fetch - Gmail's `format="metadata"` with a header allowlist, Graph's
   `$select` on a handful of fields) and having `/api/emails` fetch
   summaries for the current page concurrently via a small
   `ThreadPoolExecutor`. Full body/attachment/header parsing still
   only happens in `get_message()`, called on-demand by scan/open -
   inbox listing stays cheap as required.
2. **Event-loop-blocking bug (the most likely cause of "everything
   becomes unresponsive during a scan").** `POST /api/scan`'s
   pagination loop and `POST /api/analyze`'s ML inference call were
   both synchronous, blocking calls made directly inside `async def`
   route handlers. FastAPI/Starlette run a single event loop; a
   blocking call inside an `async def` (as opposed to a plain `def`,
   which FastAPI auto-threads) freezes that loop for every other
   request on the server for the call's duration - including the
   scan-progress polling requests, the logout call, and any other
   navigation. This is the most likely explanation for "scanning is
   slow AND unrelated buttons stop responding at the same time" -
   those two symptoms sharing one root cause is a strong signal it
   was this bug, not two separate ones. Fixed by wrapping both blocking
   calls in `loop.run_in_executor(...)`, matching the pattern already
   used correctly inside `scan_service.run_scan`.
3. **Session cookie `Secure=True` hardcoded**, which some browsers
   (notably Firefox) refuse to persist on a plain `http://localhost`
   origin - a strong candidate for "requires repeated login/reload
   before the UI state becomes correct." Made configurable via
   `SESSION_COOKIE_SECURE` (default `false` for local dev; set `true`
   once actually deployed behind HTTPS).
4. **Fragile cookie-setting pattern** in `google_login`/
   `microsoft_login`: the session cookie was set on a throwaway
   `Response` object and then copied via `redirect.headers.update(...)`
   onto the actual `RedirectResponse`. Replaced with setting the
   cookie directly on the response that's actually returned.
5. **Sidebar was entirely decorative** - Inbox/Scans/Threat
   Intelligence/Cases/Reports/Settings had zero click handlers, i.e.
   exactly the "button that looks functional but silently does
   nothing" this project's own spec calls out as unacceptable. Fixed
   with real view-switching plus real backing data for every section
   (see below) - none of them fabricate data; each shows genuinely
   empty state until a scan has produced something to show.
6. **`alert()` was the only error surface** for scan/upload failures,
   and background status-check failures were silently swallowed.
   Replaced with a toast/banner system (`showToast`) used consistently
   across every API call, and `apiGet`/`apiPost` now distinguish
   network failure from a parsed error body in every caller.
7. **Logout left stale state on screen** - it cleared the connect/
   disconnect UI but not `resultsByMessageId`, the scan poll interval,
   or pagination state. `doLogout()` now resets all of it explicitly.

### What was NOT diagnosable in this sandbox, and why
The reported "5 messages stuck at 2/5 for ~2 minutes / 100 messages
stuck for 10+ minutes" could not be reproduced or precisely measured
here - this sandbox has no outbound network access at all (confirmed
in Pass 1), so no real Gmail API call has ever actually been made from
this codebase. What *was* verified directly:
- Added per-stage timing instrumentation (`analysis_service._StageTimer`,
  logged as `email <id>: m1=..s m2=..s m3=..s m4=..s risk=..s total=..s`,
  plus a separate `fetch=..s` log line in `scan_service`) and ran it
  against 5 synthetic emails in one process: M3's local-feed loading
  cost ~0.7s **once** (parsing the 17MB PhishTank JSON on first use)
  and then ~0.3ms on every subsequent email in the same process - i.e.
  the existing module-level caching in `phishtank_local.py`/
  `spamhaus.py` (added in Pass 1) is working as intended and is not
  the live bottleneck.
- The event-loop-blocking bug (#2 above) is the strongest remaining
  candidate: it would make an entire *scan* look frozen (because
  progress-polling requests queue up behind it) even if the
  underlying per-message work is fast, which matches the reported
  symptom shape (scan stuck + other buttons unresponsive at the same
  time) better than "the pipeline itself is slow" would.
- If scans are still slow after this fix once you have real
  credentials, the timing logs will show exactly which of fetch /
  parse / M1 / M2 / M3 / M4 / risk is actually expensive for your real
  inbox - that's what to paste back for a further fix, rather than
  guessing again.

### New endpoints added (Scans / Threat Intelligence / Cases / Reports / Custom Email)
All of these compute real numbers from `STORE.list_results()` (this
session's actual analyzed results) - **nothing is fabricated**. An
empty session correctly returns empty/zero results, not manufactured
sample data:
- `GET /api/scans/history` - up to the last 70 HIGH/CRITICAL results
  this session has actually seen, plus a daily trend computed from
  `analyzed_at` timestamps.
- `GET /api/scans/bad-sources` - HIGH/CRITICAL results grouped by
  sender domain, worded as "Repeated suspicious activity from this
  source" rather than any attacker-intent claim, per spec.
- `GET /api/threat-intel/summary` - match counts per source (PhishTank/
  Spamhaus/local heuristics) from this session's results, plus each
  local feed file's last-modified time as a proxy for "last feed
  update" (there is no separate update-tracking database).
- `GET /api/reports/summary` - total/risk breakdown, top domains/
  senders/categories/attachment types, and authentication-failure
  counts, all aggregated from this session's results.
- `GET /api/cases` - HIGH/CRITICAL results grouped by domain into a
  lightweight "campaign" view (case id, first/last seen, distinct
  senders/IPs, categories, highest risk). This is a real grouping of
  real data, not a full case-management system.
- `POST /api/analyze/batch` - up to 10 `.eml` files in one request,
  used by the new Custom Email page (moved out of the main dashboard
  per spec), each offloaded through the same executor fix as the
  single-file endpoint.

### Frontend rebuild
- Rebranded ThreatLens -> **ValorProtects** throughout (title, sidebar
  brand, page metadata).
- Sidebar now genuinely switches between Dashboard/Inbox (alias),
  Scans, Threat Intelligence, Cases, Reports, Custom Email, and
  Settings - each with real content, empty states, and real fetches.
- Theme picker moved from the top bar into Settings -> Appearance, per
  spec; top bar simplified to provider status + refresh + logout.
- Disabled-button opacity raised from 0.5 to 0.62 (contrast audit) -
  this is a small, mechanical fix; a full WCAG-level contrast audit of
  all six themes was not performed given the time budget (see Known
  limitations).
- Custom Email page: drag-and-drop + browse, up to 10 files, per-file
  remove, batch analyze, and a results table - the old single-file
  fallback panel on the dashboard was removed as instructed.

### Explicitly deferred (per the spec's own P1/P2 ordering and the
### two-hour budget) - not implemented, not faked
- YARA attachment scanning
- Organization/Personal protection policy pages (external-email
  policy, sender/domain lists, content-policy rules, smart-mute,
  auto-archive/auto-delete)
- Quarantine / "Automated Mail Protection" mail actions
- GitHub-Releases-based update checker
- Terms & Conditions modal with acceptance state
- "Keep me signed in" duration option (spec explicitly says not to
  expose this until session behavior actually supports it long-lived
  sessions - it doesn't yet, so it's correctly left out rather than
  added and mislabeled)
- Glassy/gradient/wallpaper theme families (the 6 existing
  light/dark presets + system were kept and moved to Settings; a full
  wallpaper-with-dimming-and-derived-accent system was out of scope
  for this pass)
- Node.js/Redis production architecture - intentionally documented
  only (see ARCHITECTURE.md), never implemented, per explicit
  instruction.

## Pass 3: attachment-first/conditional canonical analysis order

New requirement: attachments are analyzed FIRST in the pipeline, and
their findings conditionally control downstream analysis depth.

### What changed (inspected current code first; no duplication introduced)
- **Before**: attachment severity (executable/script extension check)
  was computed once, inline, at the very end of `risk_engine.py`, and
  nothing upstream (M2) ever saw it.
- **After**: extracted into a new single-responsibility module,
  `backend/app/services/attachment_analysis.py` - this is the ONE
  place that decides attachment severity now; `risk_engine.py` no
  longer has its own copy of the executable-extension list, it just
  consumes `attachment_analysis`'s output. New categories beyond the
  original exe/script list: `macro_enabled_document` (.docm/.xlsm/.pptm)
  and `disguised_double_extension` (e.g. "invoice.pdf.exe").
- `analysis_service.analyze_normalized_email` now runs attachment
  analysis as stage 0, before M1, and its `has_high_severity` flag is
  passed into `ml_classifier.classify_email(..., force_rule_based=...)`,
  which OR's it with the existing ML-probability threshold trigger.
  **This is strictly additive**: a suspicious attachment can only turn
  on the deeper rule-based text scan for a borderline email, it never
  turns anything off - M1/M2/M3/M4 still run unconditionally for every
  email, so this cannot introduce a false negative relative to the
  previous behavior.
- No new parser, risk engine, provider, or analysis service was
  created - `risk_engine.py`, `ml_classifier.py`, and
  `analysis_service.py` were edited in place; `attachment_analysis.py`
  is new because attachment severity genuinely didn't have its own
  module before (it was buried inside the risk engine), not because
  an existing module was duplicated.

### Verified (all three, see test commands below)
1. Legit newsletter with a plain PDF attachment: `has_high_severity=False`,
   risk stays LOW (7/100) - no regression.
2. Original phishing email with an `.exe` attachment: `has_high_severity=True`,
   risk stays CRITICAL (100/100) - no regression.
3. **New conditional-trigger test**: a bland, generic "see attached
   numbers" email (ML phishing probability 20.71%, well below the 40%
   auto-trigger threshold) with a macro-enabled `.xlsm` attachment -
   `forensics_forced_by_attachment=True` confirms the attachment
   finding correctly forced the deeper rule-based scan on despite the
   low ML score, while the overall risk correctly stayed LOW (23/100)
   because the email text itself had no other genuine evidence of
   malice - the attachment flag alone doesn't manufacture a false
   positive, it just ensures the deeper check actually ran.

## Pass 4: attachment-first verification pass - honest inspection finding, then real implementation

**This pass was framed as "verify the attachment-first architecture
already exists and just run regression tests." Inspection (step 1,
before touching any code) found that was only half true**: the
attachment-first *ordering* and the conditional AI-scan trigger from
Pass 3 were real and working, but magic-byte file-type detection and
YARA scanning - both required for the mandated regression tests C and
D - had never actually been built, only discussed. Worse, the parser
was discarding raw attachment bytes right after hashing them, so even
if YARA existed there would have been nothing left to scan. This is
reported plainly rather than running tests C/D against code that
couldn't possibly pass them.

### What was built to close that gap
- `backend/app/schemas/email_message.py`: `AttachmentMeta` gained a
  transient `content_bytes` field - held in memory for one request's
  pipeline only, never logged, never cached, never included in any
  API response (stripped by construction - `attachment_analysis.py`'s
  output items never copy this field forward).
- `backend/app/services/email_parser.py`: both the Gmail/`.eml` path
  and the Microsoft Graph path now retain the decoded attachment bytes
  on `AttachmentMeta` instead of discarding them after hashing.
- `backend/app/services/file_type_detector.py` (new): magic-byte
  signature detection (PDF, PE/MZ, ELF, OLE2, ZIP/OOXML, PNG/JPEG/GIF,
  RTF, PostScript) plus an extension-vs-detected-category mismatch
  check. No execution, no external library - just reading the first
  few bytes.
- `backend/app/security/yara/scanner.py` + `rules/demo_rules.yar`
  (new): lazy-singleton compiled ruleset, static in-memory scanning
  only (`yara.compile(...).match(data=...)`, never a file execution),
  a size limit (20MB) and a match timeout (5s), and honest graceful
  degradation when `yara-python` isn't installed - see Known
  limitations. Four demonstrative rules: PowerShell dropper pattern,
  generic PE-executable indicator, Office macro auto-exec + shell
  combination, and obfuscated-script indicators.
- `backend/app/services/attachment_analysis.py` rewritten: genuinely
  conditional now (`if not attachments: return {"scanned": False,
  "reason": "No attachments", ...}` immediately, before importing or
  calling anything YARA/magic-byte related) - not just cheap, actually
  skipped. When attachments exist, each one goes through: category by
  extension -> magic-byte detection -> mismatch check -> YARA scan,
  in that order, matching the mandated flow exactly.
- `backend/app/services/risk_engine.py`: added an explicit, documented
  floor rule - a YARA high/medium-severity match forces the score to
  at least 65 (HIGH) on top of (not instead of) the normal additive
  scoring, specifically so a bland/benign-looking body cannot dilute
  away real attachment evidence. This is a deliberate policy, not
  "YARA matched -> 100": the additive score can still land higher than
  the floor on its own evidence.
- `backend/app/services/analysis_service.py`: output reshaped to
  `attachments_present: bool`, `attachments: [...]` (now the rich
  per-item shape with `declared_type`/`detected_type`/`category`/
  `flags`/`yara`), and `attachment_analysis: {scanned, reason,
  has_high_severity, high_severity_filenames}` as a summary (items
  moved to `attachments` to avoid duplicating the same list twice).

### Bug this reshape introduced, found and fixed before shipping
Moving `items` out of `attachment_analysis` broke `static/app.js`'s
detail panel, which was cross-referencing
`result.attachment_analysis.items` to find each attachment's flags -
that list is now always empty (it's a summary, not the item list).
Fixed by reading `flags`/`yara` directly from `result.attachments[i]`,
where they now live. Caught by re-reading the frontend code after the
backend reshape rather than assuming it still worked - the AI/body-
analysis section was also found completely missing from the detail
panel at the same time (a pre-existing gap from Pass 3, not something
this pass broke) and was added.

### The four required regression tests - actual output, not claimed
```
TEST A - legit email, no attachment:
  attachment_analysis: {'scanned': False, 'reason': 'No attachments', ...}
  timing log: "attachments=0.0s" (confirms YARA/magic-byte code path never entered)
  risk: LOW 8
  PASS

TEST B - legit email, normal PDF:
  detected_type: application/pdf (magic bytes correctly identified real PDF)
  flags: [] (no false positive)
  yara: {'scanned': False, 'reason': "yara-python is not installed..."}
  risk: LOW 7
  PASS (with the caveat below - see "What Test B does NOT prove")

TEST C - filename says .pdf, magic bytes are a real MZ/PE stub:
  declared_type: application/pdf | detected_type: application/x-msdownload
  flags: ['extension_content_type_mismatch']
  risk: LOW 28 (up from a 7-point clean-PDF baseline - meaningfully higher, as required)
  PASS

TEST D - bland body (AI phishing probability 4.62%) + YARA match on attachment:
  forensics_forced_by_attachment: True
  attachment flags: ['yara_rule_match']
  evidence_sources includes 'yara_local_rules'
  FINAL risk: HIGH 65 (not diluted by the near-zero AI score)
  PASS - but the YARA match itself was MOCKED, see below
```

### What Test B does NOT prove, and why Test D used a mock
`yara-python` cannot be installed in the sandbox this project was
built in - no outbound network access at all (confirmed by both
`pip install yara-python` and `pip download yara-python` failing with
"No matching distribution found", the same constraint noted in Pass 1
for `fastapi`/`pydantic`/etc.). That means:
- Test B's "YARA runs, no match" was only partially demonstrated: the
  scanner was *called* and correctly reported *why* it didn't scan
  (`yara-python is not installed`), which is the honest, intended
  degradation path - but it is not the same as a real YARA engine
  examining the bytes and finding nothing.
- Test D's YARA match was produced by mocking
  `attachment_analysis.yara_scanner.scan_bytes()`'s return value for
  that one test only. Everything downstream of that mock - the flag
  being set, the conditional AI-scan trigger firing, the risk engine's
  floor rule activating, `evidence_sources` including
  `yara_local_rules` - is the real code path, exercised for real. Only
  the YARA engine itself is simulated.
- `requirements.txt` already lists `yara-python`. In any environment
  with normal internet access, `pip install -r requirements.txt`
  installs it and the scanner activates automatically on next use -
  `scanner.py`'s `_get_yara_module()` re-attempts the import lazily,
  there is no code path that needs to be re-enabled manually.

### Previous fixes re-verified intact (not re-implemented)
Re-ran the Pass-2 batch-scan concurrency/failure-isolation/session-
isolation test against the new pipeline (6 good messages + 1 forced
failure): `analyzed: 6, failed: 1, status: complete`,
cross-session isolation still holds. Grep-verified `get_message_summary`,
the `run_in_executor` fixes, the configurable cookie `Secure` flag, the
direct-cookie-on-redirect fix, `ALLOWED_PAGE_SIZES`, and session-scoped
`STORE` keys are all still present and unmodified in this pass.



