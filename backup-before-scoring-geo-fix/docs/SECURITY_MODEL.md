# SECURITY_MODEL.md

Documents security properties VERIFIED from the current code. This is
a prototype/hackathon-stage system - see the "Security limitations /
production gaps" section for an explicit, non-euphemistic list of
what is NOT production-grade.

## Properties that CURRENTLY exist

**OAuth**
- Google: Authorization Code flow via `google-auth-oauthlib.flow.Flow`
  (web flow, confidential client with a real client secret).
- Microsoft: Authorization Code flow via `msal.ConfidentialClientApplication`.
- Both use a random `state` value bound to the initiating session id
  in an in-process dict (`_PENDING_STATE`), checked on callback - CSRF
  protection for the OAuth redirect.
- Neither flow exposes a client secret to the browser - both secrets
  are read from environment variables server-side only
  (`GOOGLE_CLIENT_SECRET`, `MICROSOFT_CLIENT_SECRET`).

**Session isolation**
- Every session gets a random `session_id` (`secrets.token_urlsafe(32)`).
- OAuth credentials/tokens are stored server-side only, in
  `SESSION_STORE[session_id]` - never sent to the browser.
- Every analysis result and scan is stored keyed by
  `(session_id, provider, account_id, message_id)` or
  `scan.owner_session_id` respectively - `STORE.get_scan()` explicitly
  returns `None` if the requesting session doesn't own the scan id,
  verified by direct test (a fake `session-B` could not read
  `session-A`'s scan).

**Token/cookie handling**
- The browser cookie (`eta_session`) carries only a signed random
  session id (`itsdangerous.URLSafeSerializer`), never a token.
- Cookie is `httponly=True` (inaccessible to page JavaScript) and
  `samesite="lax"`.
- No token, session id, or client secret appears in
  `static/app.js` or any other file served to the browser.

**CSRF/state**
- Covered under OAuth above. There is no separate CSRF token for the
  application's own API routes (`/api/emails`, `/api/scan`, etc.) -
  these rely on `samesite="lax"` cookie behavior plus the fact that
  they are read/action routes callable only with a valid session
  cookie, not on a distinct anti-CSRF token mechanism.

**Upload limits**
- `POST /api/analyze`: 25MB max, `.eml`/`.txt` extension only.
- `POST /api/analyze/batch`: same per-file limit, plus a hard cap of
  10 files per request (checked before any file is processed).

**Attachment handling**
- Attachments are never executed, opened with an external
  application, or have macros enabled - confirmed by reading every
  function that touches `content_bytes`: `file_type_detector.py`
  reads bytes for signature comparison only; `yara/scanner.py` passes
  bytes to `yara.compile(...).match(data=...)`, which is YARA's
  documented static in-memory matching API, not execution.
- `content_bytes` is explicitly transient - never logged, never
  stored in `STORE`, never serialized into an API response (verified:
  `attachment_analysis.py`'s output items list exactly `filename,
  declared_type, detected_type, extension, category, size_bytes,
  sha256, flags, yara` - `content_bytes` is not among them).

**YARA static scanning**
- Rule files are local, trusted project artifacts
  (`backend/app/security/yara/rules/*.yar`) - never downloaded or
  compiled from a remote source at request time.
- Enforces `MAX_SCAN_BYTES = 20MB` and `SCAN_TIMEOUT_SECONDS = 5`
  before/during scanning.
- Honest degradation: if `yara-python` isn't importable, every call
  reports `scanned: False` with a reason - never a fabricated "clean"
  result. Currently ALWAYS in this degraded state in this environment
  (see Known limitations).

**No attachment execution (general)**
- No code path in the entire attachment-handling chain
  (`email_parser.py` -> `attachment_analysis.py` ->
  `file_type_detector.py` -> `yara/scanner.py`) calls `subprocess`,
  `os.system`, `exec`, `eval`, or opens the bytes with any external
  program. Verified by direct code reading of every file in that
  chain.

**Secret handling**
- All secrets (`SESSION_SECRET_KEY`, `GOOGLE_CLIENT_SECRET`,
  `MICROSOFT_CLIENT_SECRET`) are read from environment variables via
  `os.environ.get(...)`, never hardcoded (aside from the explicit,
  clearly-labeled `"dev-only-insecure-secret-change-me"` fallback for
  `SESSION_SECRET_KEY` if the env var is unset).
- `.gitignore` excludes `.env`, `credentials.json`, `token.json`.

**Logging**
- The only application logging found is `analysis_service.py`'s
  per-stage timing log (`logger.info("email %s: %s total=%ss", ...)`)
  and `scan_service.py`'s per-message fetch-timing log. Neither logs
  email bodies, attachment contents, OAuth tokens, or session ids -
  verified by reading every `logger.info(...)` call site in the
  codebase (there are exactly these two).

**Feed handling**
- PhishTank/Spamhaus lookups are pure local file reads - no
  outbound network call is made during the actual analysis path for
  threat-intelligence checks (confirmed: `phishtank_local.py` and
  `spamhaus.py` contain no `requests`/`urllib` imports at all).
  `feed_updater.py` DOES make an outbound call, but is explicitly
  documented as not being on the request path.

**Error isolation**
- A single message's parse/analysis failure never aborts a batch
  scan (`analyze_email_safe` catches all exceptions;
  `scan_service.process_one` additionally catches provider-level
  fetch failures separately).
- A single attachment's YARA/magic-byte failure does not fail the
  whole email's analysis - `yara_scanner.scan_bytes` and
  `file_type_detector.detect_file_type` never raise for bad/oversized/
  unreadable content; they return an honest failure-state dict instead.

## Security limitations / production gaps (explicit, not softened)

- **In-memory sessions and results.** `SESSION_STORE` and `STORE` are
  plain Python dicts in one process's memory. Restarting the server
  logs everyone out and discards every cached result. There is no
  encryption at rest for OAuth tokens (they are simply Python objects
  in memory) - anyone with process memory access on the host has
  access to every active user's Gmail/Graph credentials. This does
  not scale past a single process/host.
- **Development-mode HTTP is the default.** `COOKIE_SECURE` defaults
  to `False` so the session cookie works on plain `http://localhost`.
  Running this in production over HTTP (not HTTPS) would transmit the
  session cookie in cleartext. `SESSION_COOKIE_SECURE=true` MUST be
  set once deployed behind real HTTPS - this is a manual operator
  step, not automatic.
- **Environment-based secrets with an insecure default.**
  `SESSION_SECRET_KEY` falls back to a hardcoded, publicly-visible
  (it's in this repository's source) string if the env var isn't set.
  A deployment that forgets to set this env var would sign session
  cookies with a known key, allowing session forgery.
- **No CSRF token on application API routes** (see above) - relies
  entirely on cookie `SameSite` behavior and browser same-origin
  policy for `fetch()`, not a dedicated per-request CSRF token.
- **Untested Microsoft OAuth flow.** Never exercised against a real
  Azure app registration in this environment - correctness of the
  MSAL integration beyond static code review is unverified.
- **YARA is currently non-functional in this deployment
  environment** (`yara-python` not installed, could not be installed
  due to no outbound network access during development). Every
  attachment currently gets `yara: {"scanned": false, ...}` - the
  YARA layer provides zero actual detection value until a real
  environment installs the dependency.
- **No enterprise pre-delivery mail gateway.** This system only ever
  analyzes mail that has already been delivered to the mailbox and
  retrieved via the provider's read API - it cannot block, quarantine,
  or otherwise intervene before a message reaches the inbox. No code
  in this repository claims otherwise, but this is worth stating
  explicitly since it's a common misconception about what an
  API-based mail security tool can do.
- **The `"google"`/`"gmail"` provider-name inconsistency** (see
  SYSTEM_ARCHITECTURE.md, API_FLOW.md) is not a security hole per se
  (the affected route requires a valid session and only returns that
  session's own data), but it is exactly the kind of naming drift
  that produces security bugs later if someone wires a new consumer
  to that endpoint without noticing the mismatch.
- **`GET /api/analysis/{provider}/{account_id}/{message_id}` accepts
  arbitrary `account_id`/`message_id` path segments** and relies
  solely on the `(session_id, provider, account_id, message_id)` tuple
  match in `STORE` to prevent cross-account access within the SAME
  session - i.e. if a session had ever connected two different Gmail
  accounts sequentially (not currently possible via the UI, which
  only tracks one active provider), stale results from the first
  account would technically remain queryable by an attacker who knew
  its `account_id`, since nothing currently scopes results to "the
  currently connected account" beyond the key itself. This is a
  theoretical edge case given the current single-account-at-a-time UI
  flow, not a demonstrated exploit.
- **No rate limiting** on any route, including the OAuth login routes
  or the scan-start route - a client could start many concurrent
  scans or hammer `/api/emails`.
- **No automated test suite** exists in this repository - all
  verification described in this documentation set and in
  MERGE_LOG.md was done via ad hoc scripts during development, not a
  repeatable `pytest` (or similar) suite.
