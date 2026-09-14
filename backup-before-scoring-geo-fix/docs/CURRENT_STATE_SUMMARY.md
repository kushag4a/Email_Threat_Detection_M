# CURRENT_STATE_SUMMARY.md

Compiled from direct code inspection and the other files in this
`docs/` set (SYSTEM_ARCHITECTURE.md, FILE_BY_FILE_GUIDE.md,
DATA_FLOW.md, AUTH_FLOW.md, API_FLOW.md, FRONTEND_FLOW.md,
SECURITY_MODEL.md, DEMO_FLOW.md). Nothing below is invented; every
item traces back to a specific file/function referenced in those
documents.

## WORKING

- FastAPI app boots via `uvicorn backend.app.main:app`, serves the
  dashboard at `/` and API docs at `/docs`.
- Session/cookie mechanism (`backend/app/auth/session.py`) - signed,
  HttpOnly, random session id; verified isolation between sessions.
- Google OAuth code path (`google_oauth.py` + `main.py` routes) -
  code-reviewed, structurally correct, CSRF-state-protected. (See
  UNTESTED below for the live-network caveat.)
- Microsoft OAuth code path (`microsoft_oauth.py` + `main.py` routes) -
  same caveat.
- `GmailProvider`/`MicrosoftGraphProvider` both implement the common
  `MailProvider` interface; the analysis pipeline never branches on
  provider identity.
- Canonical email parser (`email_parser.py`) - one parser, two entry
  points (RFC822 bytes, Graph JSON), both produce `NormalizedEmail`.
- Attachment-first/conditional pipeline (`analysis_service.py`,
  `attachment_analysis.py`) - verified: zero-attachment emails skip
  YARA/magic-byte code entirely; attachments run magic-byte detection
  -> SHA-256 -> YARA in that order; a high-severity attachment finding
  conditionally forces the deeper AI-side rule-based scan.
- Risk engine floor rule - a YARA high/medium match forces the score
  to at least 65 regardless of a low AI/body score (verified with a
  mocked YARA result, see MERGE_LOG.md "Test D").
- False-positive protection - a synthetic legitimate newsletter (many
  headers, Google relay, tracking URLs, PDF attachment) scored LOW in
  direct testing; a synthetic phishing email with a malicious
  attachment scored CRITICAL/HIGH.
- ML classification (`ml_classifier.py`) - all 4 `.pkl` model/
  vectorizer files load and produce real predictions in this
  environment.
- Local threat intelligence (`threat_intel/*`) - PhishTank and
  Spamhaus lookups work against the bundled local data files, no
  network call required; lazy-singleton loading verified via timing
  test (~0.7s first call, ~0.0003s after).
- Geolocation caching (`geolocation.py`) - TTL cache verified to
  return a cache hit on a repeated IP.
- Batch scanning (`scan_service.py`) - bounded concurrency
  (`asyncio.Semaphore(5)`), non-blocking (uses
  `run_in_executor` for all blocking calls), per-message failure
  isolation, and session-ownership isolation all verified directly
  with a fake provider (6 successes + 1 forced failure -> scan still
  completed; a different session could not read the scan).
- `.eml` upload path (single + batch) - works with zero OAuth
  configuration; this is the only path actually exercised end-to-end
  with real (synthetic) email content in this environment.
- Frontend: sidebar routing, pagination, scan progress polling, theme
  system (6 presets + system), toast-based error handling, and the
  Custom Email drag-and-drop uploader are all implemented and
  code-verified against their respective backend endpoints (see
  FRONTEND_FLOW.md's action-to-endpoint table).
- Scans/Threat Intelligence/Reports/Cases pages - all compute real
  numbers from the session's actual stored results; an empty session
  correctly shows empty/zero states rather than fabricated data.

## PARTIALLY WORKING

- **YARA scanning** - the code path is complete and correct
  (rule-loading, size limits, timeout, honest degradation), but
  `yara-python` is not installed in this environment and could not be
  installed (no outbound network access here), so every real scan
  currently returns `scanned: false`. The rule file itself
  (`demo_rules.yar`) has never actually been compiled by a real YARA
  engine in this environment.
- **Reports page** - real aggregation, but no date-range filtering
  and no export/download capability.
- **Cases page** - real grouping by sender domain, but explicitly a
  "lightweight" view (no IP/subject/attachment-hash clustering) per
  its own code comment.
- **Settings page** - Appearance and Accounts sections are fully
  functional; the About section's text is present but contains one
  now-stale claim (see LEGACY/DRIFT below).

## NOT LIVE TESTED

- The entire Google OAuth round trip against a real Google Cloud
  OAuth client (browser redirect -> consent -> callback -> token
  exchange) - no outbound network access in this development
  environment.
- The entire Microsoft OAuth round trip against a real Azure app
  registration - no credentials were available.
- Gmail API calls (`list_messages`, `get_message`,
  `get_message_summary`) against a real Gmail inbox.
- Microsoft Graph API calls against a real mailbox.
- A real YARA match from an actual compiled ruleset (the equivalent
  logic downstream of a match WAS tested, using a mocked scanner
  return value - see MERGE_LOG.md).
- IP geolocation's success path against a live, reachable `ipapi.co`
  (the failure/honest-degradation path WAS verified, since this
  environment has no network access to reach it).
- `feed_updater.py`'s live fetch from `data.phishtank.com`.

## LEGACY / UNUSED (confirmed dead by import trace, not assumption)

- `backend/app/schemas/analysis.py` (`AnalysisResult` and friends) -
  zero importers anywhere in the codebase outside itself. The
  orchestrator returns a plain dict instead.
- `backend/app/schemas/threat_intel.py` - imported only by the
  above-dead `analysis.py`, so it is transitively dead too.
- `backend/app/services/domain_extractor.py` - zero importers
  anywhere.
- `backend/app/schemas/m1.py`'s `M1Output` class - imported only by
  the dead `analysis.py`; `M1Input` (in the same file) IS live and
  used by `m1_adapter.py`.
- `POST /api/analyze` (the single-file upload endpoint) - still
  defined and functional in `main.py`, but has no frontend caller;
  the Custom Email page exclusively uses `/api/analyze/batch`.
- `GET /api/analysis/{provider}/{account_id}/{message_id}` - defined
  and functional, but has no frontend caller, and would need
  `"gmail"` rather than `"google"` in its path to ever match a
  Gmail-sourced stored result (see KNOWN BUGS).
- `.theme-menu` CSS ruleset in `static/styles.css` - no matching
  element exists in the current `index.html` (the top-bar dropdown it
  styled was replaced by the Settings page's `.theme-grid`).
- The `phishtank_local, spamhaus, local_engine` import in `main.py`
  (line ~25) - imported, never referenced elsewhere in that file.
- The `pandas` entry in `requirements.txt` - not directly imported by
  any file found in this inspection.

## KNOWN BUGS (found during inspection, not fixed per this task's scope)

1. **Provider-name inconsistency**: `GmailProvider.name = "gmail"`,
   but every OAuth/query-param route uses `"google"` for the same
   provider. Stored results are keyed with `"gmail"` (via
   `provider.name` in `scan_service.py`), so `GET /api/analysis/
   {provider}/...` would need `"gmail"` in its URL, not `"google"`.
   Currently latent because nothing calls that route.
2. **Stale UI copy**: the Settings -> About section states YARA
   scanning is "not implemented in this build" - the backend code
   contradicts this (it IS implemented, just non-functional in this
   specific environment due to a missing dependency).
3. **`.env.example` is missing `SESSION_COOKIE_SECURE`** - the
   variable is read by `session.py` and materially affects whether
   login works over plain HTTP, but an operator following
   `.env.example` alone would never learn it exists.

## KNOWN LIMITATIONS (by design or by environment, documented plainly)

- In-memory-only session and result storage - everything is lost on
  process restart; does not scale past one process.
- Session cookie `Secure` flag defaults to off, appropriate only for
  local HTTP development - must be manually set to `true` behind real
  HTTPS.
- `SESSION_SECRET_KEY` has an insecure hardcoded fallback if the env
  var is unset.
- No CSRF token on the application's own API routes (only the OAuth
  flow itself has state-based CSRF protection).
- No rate limiting anywhere.
- No automated test suite - all verification in this project was done
  via ad hoc scripts during development.
- No enterprise pre-delivery mail gateway capability - this is
  fundamentally a post-delivery, read-API-based analysis tool.
- `yara-python` non-functional in the reference development
  environment (see PARTIALLY WORKING above).
- Microsoft OAuth entirely untested against a real tenant.
- scikit-learn version mismatch warning on model load (models were
  trained with a different scikit-learn version than the one
  installed in this environment) - predictions still succeed, but the
  warning itself indicates the training/serving environments are not
  pinned to the same version, a real reproducibility gap worth fixing
  before any retraining.

## NEXT HIGH-VALUE TASKS (derived directly from the above - not new ideas)

1. Fix the `"google"`/`"gmail"` provider-name inconsistency (or wire a
   real caller to the affected endpoint and fix it there first, since
   it's currently harmless dead code either way).
2. Update the stale YARA claim in `static/index.html`'s About section.
3. Add `SESSION_COOKIE_SECURE` to `.env.example`.
4. Install `yara-python` in a real deployment environment (already in
   `requirements.txt`; no code change needed) and verify a real match
   against `demo_rules.yar`.
5. Obtain real Google Cloud and Microsoft Azure OAuth credentials and
   perform the first live end-to-end login test for each provider.
6. Decide whether to delete or wire in the dead schema files
   (`schemas/analysis.py`, `schemas/threat_intel.py`,
   `services/domain_extractor.py`) - currently harmless but adds
   reading overhead for future maintainers.
7. Pin scikit-learn to the exact version the shipped `.pkl` models
   were trained with, or retrain them against the currently-pinned
   version, to remove the `InconsistentVersionWarning`.
8. Add an automated test suite - all current verification is ad hoc
   and not repeatable via a single command.
