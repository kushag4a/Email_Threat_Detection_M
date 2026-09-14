# FILE_BY_FILE_GUIDE.md

Every meaningful source file in the current workspace, traced by
actual imports and call sites (not assumed from filename). Files
under `__pycache__/`, `.venv/`, and compiled artifacts are omitted.

============================================================
## backend/app/main.py
============================================================
**Purpose:** The single FastAPI application. Defines every HTTP
route: health check, Google/Microsoft OAuth, mailbox listing, scan
lifecycle, `.eml` upload (single + batch), and the Scans/Threat
Intelligence/Reports/Cases aggregation endpoints consumed by the
dashboard's non-Dashboard pages. Also mounts `static/` and serves
`index.html` at `/`.

**Called by:** Uvicorn (`uvicorn backend.app.main:app`). Every route
is called by `static/app.js` via `fetch()` (see API_FLOW.md for the
exact mapping), except `GET /api/analysis/{provider}/{account_id}/{message_id}`
which currently has NO frontend caller (verified: `grep` for
`api/analysis` in `static/app.js` only matches inside larger strings
like `api/analyze`, never this exact path).

**Calls:** `backend.app.auth.google_oauth`, `backend.app.auth.microsoft_oauth`,
`backend.app.auth.session` (all of it), `backend.app.providers.gmail_provider.GmailProvider`,
`backend.app.providers.microsoft_provider.MicrosoftGraphProvider`,
`backend.app.services.analysis_service.analyze_eml_upload`,
`backend.app.services.scan_service.run_scan`,
`backend.app.services.store.STORE`.

**Inputs:** HTTP requests (query params, path params, cookies,
uploaded files).

**Outputs:** JSON responses; one HTML file response (`/`); OAuth
redirects.

**Important functions:** `google_login`, `google_callback`,
`google_status`, `google_logout`, `microsoft_login`,
`microsoft_callback`, `microsoft_status`, `microsoft_logout`,
`_get_provider` (resolves the session's stored credentials into a
`MailProvider` instance), `list_emails`, `start_scan`, `get_scan`,
`analyze_upload`, `analyze_upload_batch`, `get_analysis`,
`scans_history`, `scans_bad_sources`, `threat_intel_summary`,
`reports_summary`, `list_cases`, `dashboard_index`.

**Security relevance:** Every mailbox/scan/analysis route calls
`get_session_id()` or `_get_provider()` first and raises 401 if there
is no valid session - this is the enforcement point for user
isolation. Upload routes enforce a 25MB per-file limit and a 10-file
batch limit.

**Performance relevance:** `list_emails` fetches per-message summaries
concurrently via a local `ThreadPoolExecutor` (max 10 workers). `start_scan`'s
message-ID pagination loop and `analyze_upload`'s ML inference are both
explicitly offloaded via `loop.run_in_executor(None, ...)` - a documented
bug fix (see inline comments and MERGE_LOG.md) for an earlier version
that ran these blocking calls directly inside `async def` routes,
freezing the whole event loop.

**Current status:** Working. **Found during this inspection:** the
module-level import `from backend.app.threat_intel import
phishtank_local, spamhaus, local_engine` (line 25) is never referenced
anywhere else in the file - dead import, harmless but unused.

============================================================
## backend/app/auth/session.py
============================================================
**Purpose:** Server-side session management via a signed, random,
HttpOnly cookie.

**Called by:** `main.py` (every route that needs session context),
`google_oauth.py`/`microsoft_oauth.py` indirectly (they receive a
`session_id` string, not the module itself).

**Calls:** `itsdangerous.URLSafeSerializer`, `fastapi.Request`/`Response`.

**Inputs:** `Request` (to read the cookie), `Response` (to set it).

**Outputs:** A session id string; mutates the module-level
`SESSION_STORE` dict; sets/reads the `eta_session` cookie.

**Important functions/values:** `get_or_create_session`,
`get_session_id`, `get_session_data`, `clear_provider`,
`SESSION_STORE` (the actual dict), `SESSION_COOKIE_NAME = "eta_session"`,
`COOKIE_SECURE` (read from `SESSION_COOKIE_SECURE` env var, default
`False`).

**Security relevance:** This is the entire session-isolation
mechanism. The cookie never carries a token, only a signed session id.
`COOKIE_SECURE` defaults to `False` specifically so the cookie
persists on plain `http://localhost` during development (a documented
fix for an earlier `secure=True` hardcoding that broke login in some
browsers - see inline comment and MERGE_LOG.md).

**Performance relevance:** O(1) dict lookups; no I/O.

**Current status:** Working. **Configuration gap found during this
inspection:** `SESSION_COOKIE_SECURE` is read by this file but is
**not listed in `.env.example`** - an operator following
`.env.example` alone would not know this variable exists.

============================================================
## backend/app/auth/google_oauth.py
============================================================
**Purpose:** Google OAuth 2.0 Authorization Code flow (web flow, not
the desktop `InstalledAppFlow` used in an earlier version of this
project - see module docstring for the documented reasoning).

**Called by:** `main.py`'s `google_login` and `google_callback` routes.

**Calls:** `google_auth_oauthlib.flow.Flow`, `google.oauth2.credentials.Credentials`.
Imports `GMAIL_SCOPES` from `backend.app.providers.gmail_provider`.

**Inputs:** `session_id` (to tag pending state), the full callback
URL (`authorization_response_url`).

**Outputs:** An authorization URL to redirect the browser to;
`(session_id, Credentials)` on successful exchange.

**Important functions:** `is_configured()` (true only if
`GOOGLE_CLIENT_ID`/`GOOGLE_CLIENT_SECRET`/`GOOGLE_REDIRECT_URI` are
all set), `build_authorization_url`, `exchange_code_for_credentials`.

**Dependencies:** `google-auth-oauthlib`, `google-auth` (both in
`requirements.txt`).

**Security relevance:** `_PENDING_STATE` is an in-process dict mapping
a random `state` value to the session id that started the flow - this
is the CSRF protection for the OAuth callback. `exchange_code_for_credentials`
raises `ValueError` (-> HTTP 400) on an unknown/expired state.

**Current status:** Working (code-reviewed and structurally sound),
but **not live-tested against a real Google Cloud OAuth client** in
this environment - this environment has no outbound network access,
so the actual redirect-to-Google/consent/callback round trip has
never executed here. See CURRENT_STATE_SUMMARY.md.

============================================================
## backend/app/auth/microsoft_oauth.py
============================================================
**Purpose:** Microsoft identity platform OAuth via MSAL
(`ConfidentialClientApplication`), Authorization Code flow.

**Called by:** `main.py`'s `microsoft_login` and `microsoft_callback` routes.

**Calls:** `msal.ConfidentialClientApplication`. Imports
`GRAPH_SCOPES` from `backend.app.providers.microsoft_provider`.

**Inputs:** `session_id`, authorization `code`.

**Outputs:** Authorization URL; `(session_id, token_result dict)`.

**Important functions:** `is_configured()`, `build_authorization_url`,
`exchange_code_for_token`.

**Dependencies:** `msal` (in `requirements.txt`).

**Security relevance:** Same `_PENDING_STATE`-based CSRF protection
pattern as `google_oauth.py`. Uses delegated scopes only
(`Mail.Read`, `User.Read`, `offline_access`) - never
application/tenant-wide permissions.

**Current status:** Implemented, never live-tested (no Azure app
registration/credentials available in this environment). Explicitly
flagged as such in PROJECT_CONTEXT.md.

============================================================
## backend/app/providers/base.py
============================================================
**Purpose:** Defines the provider-independent interface every mail
provider must implement, plus the plain data classes passed across
that interface.

**Called by:** `gmail_provider.py`, `microsoft_provider.py` (both
subclass `MailProvider`); `main.py` type-hints against it;
`scan_service.py` type-hints its `provider` parameter against it.

**Calls:** Nothing (no imports beyond `abc` and the schema module for
type hints).

**Important classes:** `MessageListItem` (message_id, thread_id),
`MessagePage` (items + next_page_token), `MessageSummary` (cheap
list-view metadata, has a `to_dict()` method), `MailProvider` (ABC
with abstract `get_current_user`, `list_messages`, `get_message`,
`get_message_summary`, plus a non-abstract no-op `disconnect`).

**Current status:** Working, canonical - the only provider interface
in the codebase.

============================================================
## backend/app/providers/gmail_provider.py
============================================================
**Purpose:** Gmail API v1 implementation of `MailProvider`.

**Called by:** `main.py` (`_get_provider`, `google_callback`),
`google_oauth.py` (imports `GMAIL_SCOPES` only, not the class).

**Calls:** `googleapiclient.discovery.build`,
`google.oauth2.credentials.Credentials`,
`backend.app.services.email_parser.parse_rfc822_bytes`.

**Inputs:** A `google.oauth2.credentials.Credentials` object (from
`google_oauth.py`).

**Outputs:** `MessagePage`, `MessageSummary`, `NormalizedEmail`.

**Important functions:** `get_current_user` (calls
`users().getProfile()`, cached on the instance after first call),
`list_messages` (Gmail `users().messages().list()`, `labelIds=["INBOX"]`,
native `pageToken`), `get_message_summary` (Gmail `format="metadata"`
with `metadataHeaders=["From","To","Subject","Date"]` - deliberately
cheap, does NOT fetch the body), `get_message` (Gmail `format="raw"` -
the full RFC822 message, base64-decoded then handed to
`parse_rfc822_bytes`).

**Class attribute:** `name = "gmail"` (see the naming-inconsistency
note in SYSTEM_ARCHITECTURE.md - this differs from the `"google"`
string used in OAuth routes/query params).

**Security relevance:** Requests only
`https://www.googleapis.com/auth/gmail.readonly` (`GMAIL_SCOPES`).

**Performance relevance:** `get_message_summary` uses Gmail's cheap
metadata format specifically to keep inbox listing fast; `get_message`
uses the expensive raw format and is only called during a scan or
explicit open, never during listing (verified: `main.py`'s
`list_emails` route calls `get_message_summary`, never `get_message`).

**Current status:** Working (code-reviewed), never exercised against
a real Gmail account in this environment (no network access here).

============================================================
## backend/app/providers/microsoft_provider.py
============================================================
**Purpose:** Microsoft Graph v1.0 REST implementation of
`MailProvider`, using the `requests` library directly (no Microsoft
Graph SDK dependency).

**Called by:** `main.py` (`_get_provider`, `microsoft_callback`),
`microsoft_oauth.py` (imports `GRAPH_SCOPES` only).

**Calls:** `requests.get`,
`backend.app.services.email_parser.parse_graph_message`.

**Inputs:** A bearer `access_token` string.

**Outputs:** `MessagePage`, `MessageSummary`, `NormalizedEmail`.

**Important functions:** `get_current_user` (`GET /me`, cached),
`list_messages` (`GET /me/mailFolders/inbox/messages` with `$top`/
`$select`, or follows a previously-returned `@odata.nextLink` verbatim
when paginating), `get_message_summary` (single `$select`-limited
fetch: id/conversationId/subject/from/toRecipients/receivedDateTime/
bodyPreview/hasAttachments), `get_message` (fetches the message with
`$expand=attachments`, then makes a SECOND request specifically for
`internetMessageHeaders` since Graph only returns those when
explicitly selected - wrapped in try/except so a header-fetch failure
degrades to empty headers rather than failing the whole message).

**Class attribute:** `name = "microsoft"`.

**Security relevance:** `GRAPH_SCOPES = ["Mail.Read", "User.Read",
"offline_access"]` - delegated, least-privilege.

**Performance relevance:** `get_message` makes 2 HTTP requests per
message (main fetch + headers fetch) - not a single round trip. This
is a real, documented cost specific to the Microsoft path that the
Gmail path does not have (Gmail's raw format includes headers in one
call).

**Current status:** Implemented, never live-tested (no Microsoft
Graph credentials/tenant available in this environment).

============================================================
## backend/app/services/email_parser.py
============================================================
**Purpose:** THE canonical email parser - the only one in the
codebase. Two entry points producing the same `NormalizedEmail` shape
regardless of source.

**Called by:** `gmail_provider.py` (`parse_rfc822_bytes`),
`microsoft_provider.py` (`parse_graph_message`),
`analysis_service.py`'s `analyze_eml_upload` (`parse_rfc822_bytes`,
imported locally inside that function).

**Calls:** Python stdlib `email` package,
`backend.app.schemas.email_message.AttachmentMeta`/`NormalizedEmail`,
`backend.app.services.url_extractor.extract_urls`.

**Inputs:** `parse_rfc822_bytes`: raw RFC822 bytes (Gmail `format="raw"`
output, or a raw `.eml` file's bytes) plus `provider`/`account_id`/
`message_id`/`thread_id` kwargs. `parse_graph_message`: a Microsoft
Graph message JSON dict plus `account_id`.

**Outputs:** `NormalizedEmail`.

**Important functions:** `decode_mime_header` (RFC 2047 decoding),
`_extract_bodies` (returns `(plain_text, html)`, never raises on a
malformed MIME part), `_extract_attachments` (walks multipart
messages, computes SHA-256, and - as of the attachment-first pass -
**retains the raw attachment bytes** on `AttachmentMeta.content_bytes`
for magic-byte/YARA scanning downstream), `parse_rfc822_bytes`,
`parse_graph_message`.

**Security relevance:** `content_bytes` is explicitly documented as
transient (see `schemas/email_message.py`) - it is never written to
logs or included in any API response; `attachment_analysis.py`
constructs its output items without copying that field forward.

**Performance relevance:** Single pass per body/attachment extraction;
no repeated parsing. `parse_graph_message` makes a second internal
`import base64` call per attachment (function-local import, not
module-level - harmless but slightly unconventional style).

**Current status:** Working, canonical. This file's docstring
explicitly states it replaces four separate historical parsers
(`email_parser.py`, `email_security_features.py`,
`gmail_pipeline.extract_body`, `gmail_reader.extract_email_body`) -
**none of those four files exist in the current workspace**; they
were consolidated away before the current file tree was reached, per
MERGE_LOG.md. There is no duplicate parser currently in the codebase.

============================================================
## backend/app/services/analysis_service.py
============================================================
**Purpose:** THE single analysis orchestrator - every email, from
any provider, is analyzed by calling `analyze_normalized_email()` or
its safe wrapper.

**Called by:** `scan_service.py` (`analyze_email_safe`, per message
in a batch scan), `main.py` (`analyze_eml_upload`, for single and
batch `.eml` uploads).

**Calls:** `backend.app.forensic.m1_header_analyzer.analyze_email`,
`backend.app.services.attachment_analysis.analyze_attachments`,
`backend.app.services.geolocation.get_ip_geolocation`,
`backend.app.services.m1_adapter.prepare_m1_input`,
`backend.app.services.ml_classifier.build_analysis_text`/`classify_email`,
`backend.app.services.risk_engine.calculate_risk`,
`backend.app.threat_intel.aggregator.analyze_threat_intelligence`,
and (locally imported inside `analyze_eml_upload`)
`backend.app.services.email_parser.parse_rfc822_bytes`.

**Inputs:** A `NormalizedEmail` (for `analyze_normalized_email`/
`analyze_email_safe`) or raw `.eml` bytes (for `analyze_eml_upload`).

**Outputs:** A plain Python dict (NOT a `schemas.analysis.AnalysisResult`
instance - that schema class exists but is never used here or
anywhere else; see the schemas section below) with keys: `message_id`,
`provider`, `account_id`, `email`, `header_analysis`, `m1`, `m2`, `m3`,
`m4`, `urls`, `attachments_present`, `attachments`, `attachment_analysis`,
`risk`, `evidence_sources`, `status`, `error`, `analyzed_at`.

**Important functions/classes:** `_StageTimer` (records
`time.perf_counter()` deltas between named stages and logs them via
Python's `logging` module at INFO level - this is how scan
performance is diagnosed, see PERFORMANCE section of DATA_FLOW.md),
`_header_analysis` (computes `reply_to_mismatch`/`return_path_mismatch`
by comparing actual addresses via `email.utils.parseaddr`, NOT raw
header strings - a documented bug fix for a false positive on display
names), `analyze_normalized_email` (the real pipeline), `analyze_email_safe`
(catches any exception from the above and returns a
`status: "analysis_failed"` dict instead of raising - this is what
lets a batch scan survive one bad message), `analyze_eml_upload`
(entry point for file uploads, no provider/OAuth needed).

**Execution order inside `analyze_normalized_email`** (verified from
source, top to bottom): (1) `analyze_attachments` - first; (2)
`m1_analyze` + `_header_analysis`; (3) `classify_email` with
`force_rule_based=attachment_result["has_high_severity"]`; (4)
`analyze_threat_intelligence`; (5) `get_ip_geolocation` per IP; (6)
`calculate_risk`. This is the actual, current, code-verified
attachment-first/conditional order.

**Security relevance:** Builds `evidence_sources` list transparently
(only appends `"yara_local_rules"` if at least one attachment's YARA
scan actually ran).

**Performance relevance:** The `_StageTimer` logs
`attachments=Xs m1=Xs m2=Xs m3=Xs m4=Xs risk=Xs total=Xs` per email at
INFO level under logger name `"email_threat_platform.analysis"` - this
is the mechanism for diagnosing scan slowness, not a separate
profiling tool.

**Current status:** Working, canonical - the only orchestrator.

============================================================
## backend/app/services/attachment_analysis.py
============================================================
**Purpose:** The Attachment Security Engine. Genuinely conditional:
returns immediately for an email with no attachments, without
importing or calling anything YARA/magic-byte related for that call.

**Called by:** `analysis_service.py` only.

**Calls:** `backend.app.security.yara.scanner` (`scan_bytes`,
`highest_severity`), `backend.app.services.file_type_detector`
(`detect_file_type`, `check_extension_mismatch`).

**Inputs:** `list[dict]` - each dict is one attachment's
`AttachmentMeta.model_dump()` output (filename, content_type,
extension, size_bytes, sha256, content_bytes).

**Outputs:** `{"scanned": bool, "reason": str|None, "items": [...],
"has_high_severity": bool, "high_severity_filenames": [...]}`. Each
item in `items` has: filename, declared_type, detected_type,
extension, category, size_bytes, sha256, flags (list of strings),
yara ({"scanned", "matches", "reason"}). **`content_bytes` is never
copied into an item** - verified by reading the `items.append(...)`
call, which lists exactly those fields.

**Important functions:** `analyze_attachments` (the only public
entry point), `_categorize` (extension -> category:
executable_or_script / macro_enabled_document / archive / document /
image / unknown), `_has_disguised_extension` (catches
`invoice.pdf.exe`-style double extensions).

**Constants:** `EXECUTABLE_EXTENSIONS`, `ARCHIVE_EXTENSIONS`,
`MACRO_DOCUMENT_EXTENSIONS`, `DOCUMENT_EXTENSIONS`, `IMAGE_EXTENSIONS`.

**Security relevance:** This is the single source of truth for "is
this attachment suspicious" - `risk_engine.py` has no attachment
severity logic of its own and only consumes this module's `items`.
Never executes, opens, or renders attachment content.

**Performance relevance:** For zero attachments, the function returns
on its second line (`if not attachments: return {...}`) - confirmed
by direct testing that this path produces a `0.0s` timing entry with
no YARA/file-type-detector call. For each attachment WITH bytes, both
`file_type_detector.detect_file_type` and `yara_scanner.scan_bytes`
are called unconditionally (no short-circuit between them).

**Current status:** Working, canonical, the only attachment analysis
implementation in the codebase.

============================================================
## backend/app/services/file_type_detector.py
============================================================
**Purpose:** Magic-byte (file signature) detection, independent of
filename/extension/declared MIME type.

**Called by:** `attachment_analysis.py` only.

**Calls:** Nothing external - pure Python, reads bytes directly.

**Inputs:** `content_bytes: bytes | None`.

**Outputs:** `detect_file_type` -> `{"detected_type": str,
"detected_category": str}`. `check_extension_mismatch` -> `bool`.

**Important data:** `_SIGNATURES` (list of (signature bytes, offset,
mime-ish type, category) tuples covering PDF, PE/MZ, ELF, OLE2,
ZIP/OOXML, PNG, JPEG, GIF, PostScript, RTF), `_EXPECTED_CATEGORY_BY_EXTENSION`
(maps a handful of extensions to the category their real content
should match).

**Security relevance:** This is what catches "invoice.pdf" that is
actually a PE executable - an independent signal from the
attacker-controlled filename/extension.

**Performance relevance:** O(number of signatures) per attachment,
each a byte-slice comparison - negligible cost.

**Current status:** Working, canonical, the only file-type detector
in the codebase.

============================================================
## backend/app/security/yara/scanner.py
============================================================
**Purpose:** The YARA Scanner - static, rule-based pattern matching
over attachment bytes. Explicitly documented as NOT an ML model and
NOT a guaranteed virus detector.

**Called by:** `attachment_analysis.py` only.

**Calls:** The third-party `yara` package (`yara-python`), imported
lazily inside `_get_yara_module()` - NOT at module top level, so
importing `scanner.py` itself never fails even if `yara-python` is
absent.

**Inputs:** `content_bytes: bytes | None`.

**Outputs:** `scan_bytes` -> `{"scanned": bool, "matches": [{"rule":
str, "severity": str}], "reason": str|None}`. `highest_severity` ->
`str|None`.

**Important functions/values:** `_get_yara_module` (lazy import,
caches the failure reason so it isn't re-attempted every call),
`_get_compiled_rules` (lazy singleton - compiles
`rules/*.yar` once per process via `yara.compile(filepaths=...)`),
`scan_bytes`, `highest_severity`, `RULES_DIR` (`security/yara/rules/`),
`MAX_SCAN_BYTES = 20MB`, `SCAN_TIMEOUT_SECONDS = 5`.

**Security relevance:** Never executes the attachment. Rule files are
loaded from a fixed local directory shipped with the project - never
downloaded or compiled from a remote/untrusted source at request
time. Enforces a size limit and a match timeout so a crafted
attachment can't hang or exhaust memory during a scan.

**Performance relevance:** The compiled ruleset is a true singleton
(`_compiled_rules` module-level variable) - compiled once per process,
not once per email or per attachment.

**Current status: NOT LIVE-VERIFIED WITH A REAL YARA MATCH.**
`yara-python` could not be installed in the environment this project
was built in (no outbound network access - confirmed via
`pip install yara-python` and `pip download yara-python`, both
failing with "No matching distribution found"). Every call to
`scan_bytes` in this environment returns `scanned: False` with reason
`"yara-python is not installed in this environment (...)"` - this is
the intended, honest degradation path, not a bug. The
attachment-flagging logic downstream of a YARA match (in
`attachment_analysis.py` and `risk_engine.py`) was tested by directly
mocking this module's `scan_bytes` return value - see MERGE_LOG.md's
"Test D" for the exact test. `requirements.txt` lists `yara-python`;
in an environment with normal network access, `pip install -r
requirements.txt` installs it and this module activates automatically
on next use, no code change required.

============================================================
## backend/app/security/yara/rules/demo_rules.yar
============================================================
**Purpose:** The only YARA rule file in the project - a small,
explicitly-labeled-as-demonstrative rule set (see the file's own
header comment: "NOT a production malware-detection rule set").

**Called by:** Loaded by `scanner.py::_get_compiled_rules()` via
`RULES_DIR.glob("*.yar")` - any `.yar` file dropped into this
directory would be picked up automatically; currently there is
exactly one.

**Contents (4 rules):** `Suspicious_PowerShell_Dropper` (severity:
high - looks for `DownloadString`/`IEX(`/`-EncodedCommand`/
`FromBase64String`, 2-of-4 match), `Suspicious_Executable_Indicators`
(severity: medium - PE header + the standard DOS-stub string),
`Suspicious_Macro_AutoExec_Shell` (severity: high - macro
auto-execution keywords combined with shell-execution keywords),
`Suspicious_Script_Obfuscation` (severity: medium - common obfuscated
script-execution patterns).

**Current status:** Present and syntactically written for YARA, but
**never actually compiled or matched in this environment** since
`yara-python` is absent - see the scanner.py entry above. Not
verified to compile cleanly against a real `yara` installation.

============================================================
## backend/app/services/risk_engine.py
============================================================
**Purpose:** THE composite risk engine - the only one in the
codebase. Combines evidence from every other stage into a final
score/level/reasons.

**Called by:** `analysis_service.py` only.

**Calls:** Nothing external - pure scoring logic over the dicts
passed in.

**Inputs:** `calculate_risk(*, m1, m2, m3, header_analysis,
attachment_analysis)` - all plain dicts, the exact shapes produced by
`m1_header_analyzer.analyze_email`, `ml_classifier.classify_email`,
`threat_intel.aggregator.analyze_threat_intelligence`,
`analysis_service._header_analysis`, and
`attachment_analysis.analyze_attachments` respectively.

**Outputs:** `{"score": int 0-100, "level": "LOW"|"MEDIUM"|"HIGH"|"CRITICAL",
"reasons": [str], "contributing_modules": [str]}`.

**Documented weights** (verified against source, see the module
docstring for the full table): AI phishing probability up to 40pts;
multithreat category bonuses (+10/+5/+6/+3); SPF/DKIM/DMARC fail
+8 each; Reply-To mismatch +10, Return-Path mismatch +8; PhishTank/
Spamhaus listed indicators +20 each (capped +40 each); local
heuristic average score contributes up to +10; flagged attachments
+15 each (capped +30). **Explicit floor rule**: if any attachment's
YARA result contains a high or medium severity match,
`score = max(score, 65)` is applied AFTER the additive scoring and
AFTER clamping to 0-100, specifically so a low AI/body score cannot
dilute a real attachment finding below HIGH. This is implemented as
`yara_high_severity_hit` computed while iterating `attachment_analysis["items"]`.

**Security relevance:** This is the single point where all evidence
is fused into one decision. `contributing_modules` still uses the
internal labels `"M1"`, `"M2"`, `"M3"`, `"attachments"` (see the
naming note in SYSTEM_ARCHITECTURE.md - not renamed to functional
names in the wire format).

**Performance relevance:** Pure in-memory computation, no I/O,
negligible cost (confirmed by timing logs: `risk=0.0s` in every
observed test run).

**Current status:** Working, canonical, the only risk engine.

============================================================
## backend/app/services/ml_classifier.py
============================================================
**Purpose:** The AI Threat Classification stage. Wraps two
pre-trained scikit-learn models loaded from disk, plus a rule-based
keyword fallback.

**Called by:** `analysis_service.py` only.

**Calls:** `joblib.load` (at module import time, not per-call),
`backend.app.services.threat_classifier.detect_threats`.

**Inputs:** `classify_email(analysis_text: str, *, force_rule_based:
bool = False)`. `build_analysis_text(email)` takes a `NormalizedEmail`.

**Outputs:** `{"safe_probability", "phishing_probability",
"threat_categories" (dict of category->percent), "rule_based_threats"
(dict, only populated if triggered), "top_classification"
({"label","probability"}), "forensics_triggered": bool,
"forensics_forced_by_attachment": bool}`.

**Important functions/values:** `classify_email`, `build_analysis_text`
(formats `From:`/`Reply-To:`/`Return-Path:`/`Subject:`/body into one
string, matching an earlier `gmail_pipeline.py`'s convention),
`FORENSICS_TRIGGER_THRESHOLD = 0.40`, and the four module-level
loaded objects: `_phishing_model`, `_phishing_vectorizer`,
`_multithreat_model`, `_multithreat_vectorizer`.

**Model files loaded:** `backend/app/models/phishing_model.pkl`,
`phishing_vectorizer.pkl`, `multithreat_model.pkl`,
`multithreat_vectorizer.pkl` (path: `Path(__file__).parent.parent /
"models"`, i.e. `backend/app/models/`).

**Dependencies:** `joblib`, `scikit-learn` (for unpickling the model
objects), `pandas` is listed in `requirements.txt` but not directly
imported by this file.

**Security/correctness relevance:** `force_rule_based` is the
"conditional" half of attachment-first/conditional: when
`attachment_analysis.has_high_severity` is `True`, the deeper
rule-based keyword scan runs even if `phishing_probability` alone is
below the 0.40 threshold. This is strictly additive (only ever turns
on more scanning).

**Performance relevance:** Models are loaded ONCE at import time (
module-level `joblib.load` calls, not inside `classify_email`) -
confirmed as a true singleton, not reloaded per email. **Verified
working**: directly tested in this environment - the 4 `.pkl` files
load successfully and `predict_proba` returns real probabilities
(confirmed with `scikit-learn` 1.8.0 installed here; a version
mismatch warning is printed since the models were originally trained
with a different scikit-learn version, but predictions are still
produced correctly).

**Current status:** Working, canonical, verified.

============================================================
## backend/app/services/threat_classifier.py
============================================================
**Purpose:** A rule-based keyword scanner (phishing, impersonation,
BEC, financial fraud, credential theft, malware categories), each
scored by counting keyword-phrase hits.

**Called by:** `ml_classifier.py` only (`detect_threats`), and only
when `forensics_triggered` is true.

**Calls:** Nothing external.

**Inputs:** `detect_threats(email_text: str)`.

**Outputs:** `dict[str, int]` - one score 0-100 per category.

**Current status:** Working. Contains a `if __name__ == "__main__":`
self-test block at the bottom (a standalone demo/print block) - this
never runs on import, only if the file is executed directly; it does
not affect the running application.

============================================================
## backend/app/services/geolocation.py
============================================================
**Purpose:** IP Geolocation & Infrastructure Analysis. The only
geolocation implementation in the codebase.

**Called by:** `analysis_service.py` only.

**Calls:** `requests.get` against `https://ipapi.co/{ip}/json/`.

**Inputs:** `get_ip_geolocation(ip: str)`.

**Outputs:** `{"ip", "country", "region", "city", "organization"}`.
Never fabricates a location: private/reserved IPs return
`"Not applicable (private/reserved IP)"`, invalid IPs return
`"Invalid IP"`, and network/API failures return `"Lookup failed"` in
every field - distinct, honest states, never a guessed default.

**Important values:** `_GEO_CACHE` (module-level dict, `ip ->
(timestamp, result)`), `_GEO_CACHE_TTL_SECONDS = 3600`.

**Performance relevance:** The cache means a batch scan with many
messages sharing one origin IP (e.g. all routed through the same
mail-relay infrastructure) only pays the ~5s-timeout network call
once per distinct IP per hour, not once per email.

**Current status:** Working (code-reviewed, and directly tested in
this environment - it correctly returns `"Lookup failed"` for a
public IP because this sandbox has no outbound network access,
demonstrating the honest-failure path works; the success path against
a real reachable `ipapi.co` was not exercised here).

============================================================
## backend/app/services/m1_adapter.py
============================================================
**Purpose:** Converts a `NormalizedEmail` into the exact input shape
`m1_header_analyzer.py` expects (`M1Input`).

**Called by:** `analysis_service.py` only.

**Calls:** `backend.app.schemas.m1.M1Input`.

**Current status:** Working, small and stable - a pure data-shape
adapter with no logic beyond field mapping.

============================================================
## backend/app/forensic/m1_header_analyzer.py
============================================================
**Purpose:** Header & Authentication Analysis. Extracts SPF/DKIM/
DMARC results from `Authentication-Results` (with a fallback to
`Received-SPF` for SPF only) and a probable origin IP from the
`Received` header chain.

**Called by:** `analysis_service.py` only (via `m1_analyze` alias in
that file's import: `from backend.app.forensic.m1_header_analyzer
import analyze_email as m1_analyze`).

**Calls:** Python stdlib `re` only.

**Inputs:** A dict matching `M1Input`'s shape (sender, reply_to,
return_path, received_headers, received_spf, authentication_results,
body, urls, attachments).

**Outputs:** `{"spf", "dkim", "dmarc", "origin_ip"}` - each of
spf/dkim/dmarc is one of pass/fail/softfail/neutral/none/temperror/
permerror/unknown; `origin_ip` is a string or `None`.

**Important functions:** `_extract_auth_result` (regex over
`Authentication-Results` entries), `_extract_origin_ip` (scans
`Received` headers in REVERSE order - oldest hop first - for the
first IPv4-looking match), `analyze_email` (the public entry point).

**Security relevance:** Explicitly documents that the extracted IP is
"only a probable infrastructure/source IP candidate, not proof of the
attacker's physical location" (see the function's own docstring).

**Current status:** Working, canonical - this file's docstring
elsewhere in the project states its input/output contract "already
matched the documented spec exactly" and it was copied into the
current codebase verbatim rather than rewritten. Note: file uses
Windows-style `\r\n` line endings (visible when read raw) - cosmetic,
does not affect execution.

============================================================
## backend/app/threat_intel/aggregator.py
============================================================
**Purpose:** The Threat Intelligence Engine's entry point - combines
PhishTank, Spamhaus, and local heuristic results into one dict.

**Called by:** `analysis_service.py` only.

**Calls:** `phishtank_local.check_url`, `spamhaus.check_ip`,
`local_engine.analyze_url`/`analyze_ip`.

**Inputs:** `analyze_threat_intelligence(ips: list[str], urls: list[str])`.

**Outputs:** `{"phishtank": [...], "spamhaus": [...], "local_heuristics": [...]}`.

**Security relevance:** Module docstring: "No end-user API keys are
required" - confirmed true, every call in this file is either a local
file lookup or pure computation, no outbound network call.

**Current status:** Working, canonical.

============================================================
## backend/app/threat_intel/phishtank_local.py
============================================================
**Purpose:** Local PhishTank feed lookup by normalized URL.

**Called by:** `aggregator.py` only.

**Calls:** `backend.app.services.url_normalizer.normalize_url`.

**Data file:** `backend/app/threat_intel/data/phishtank.json`
(present in the workspace, confirmed via file listing).

**Important functions:** `_load` (lazy singleton - loads and indexes
the JSON file by normalized URL on first call only, cached in
module-level `_index`), `check_url`.

**Performance relevance:** Verified by direct timing test: the first
call in a process pays the full JSON parse + index-build cost
(observed ~0.7s for this project's feed file); every subsequent call
in the same process is a dict lookup (observed ~0.0003s).

**Current status:** Working, canonical, verified.

============================================================
## backend/app/threat_intel/spamhaus.py
============================================================
**Purpose:** Local Spamhaus DROP feed lookup - checks whether an IP
falls inside any listed CIDR network.

**Called by:** `aggregator.py` only.

**Data file:** `backend/app/threat_intel/data/spamhaus_drop.txt`
(present in the workspace).

**Important functions:** `_load_drop_networks` (lazy singleton -
parses the text file into `ipaddress.ip_network` objects once, cached
in module-level `_networks`), `check_ip`.

**Current status:** Working, canonical, same lazy-singleton pattern
as `phishtank_local.py`.

============================================================
## backend/app/threat_intel/local_engine.py
============================================================
**Purpose:** Pure local heuristics requiring no feed file and no
network - IP heuristics (private/loopback/link-local/reserved
flagging) and URL heuristics (suspicious keywords, punycode domains,
userinfo-in-URL, unusual ports, very long URLs).

**Called by:** `aggregator.py` only.

**Current status:** Working, canonical.

============================================================
## backend/app/threat_intel/feed_updater.py
============================================================
**Purpose:** An operator/maintenance CLI script to refresh the local
PhishTank feed from `https://data.phishtank.com/data/online-valid.json`.

**Called by:** Nothing in the running application - explicitly
documented in its own module docstring as "NOT called on the request
path". Only invoked manually via `python -m backend.app.threat_intel.feed_updater`.

**Current status:** Present, standalone, not part of any live request
path. Not exercised in this environment (no network access to
`data.phishtank.com` here).

============================================================
## backend/app/services/url_extractor.py
============================================================
**Purpose:** Regex-based URL extraction from text.

**Called by:** `email_parser.py` (`extract_urls`, used on both plain
and HTML body text during parsing).

**Current status:** Working, canonical - the only URL extractor.

============================================================
## backend/app/services/url_normalizer.py
============================================================
**Purpose:** Normalizes a URL (lowercase scheme/host, strips
fragment, strips trailing slash) for threat-intel comparison.

**Called by:** `threat_intel/phishtank_local.py` only.

**Current status:** Working, canonical.

============================================================
## backend/app/services/domain_extractor.py
============================================================
**Purpose:** Extracts unique hostnames from a list of URLs.

**Called by:** **Nobody.** Verified via `grep -rln "domain_extractor"
backend/` - no other file imports this module.

**Current status:** DEAD / UNUSED. The domain-grouping logic actually
used by the Scans/Cases/Reports pages lives inline in `main.py` as
`_extract_domain()` (a different, simpler function operating on a
single sender address, not a list of URLs) - this file is not that
function and is not called by it either. Kept in the tree, not
deleted, per this task's "document, don't change" instruction.

============================================================
## backend/app/services/store.py
============================================================
**Purpose:** The in-memory `ResultStore` - both the analysis result
cache and the scan-progress tracker.

**Called by:** `main.py` (most endpoints), `scan_service.py` (writes
results/progress during a scan).

**Important class:** `ResultStore` with `save_result`, `get_result`,
`list_results` (all keyed by `(session_id, provider, account_id,
message_id)` for results - a comment in the file states this
explicitly prevents cross-session/cross-mailbox collisions), plus
`create_scan`, `get_scan` (returns `None` if the requesting
`session_id` doesn't own the scan - the enforcement point for
scan-level isolation), `update_scan`, `append_scan_result`.

**Module-level singleton:** `STORE = ResultStore()`.

**Current status:** Working, canonical - the only result/scan store.
In-memory only; explicitly documented in its own module docstring as
a "DEMO LIMITATION" cleared on process restart.

============================================================
## backend/app/services/scan_service.py
============================================================
**Purpose:** Runs a bounded-concurrency batch scan over N message
ids, updating progress as it goes, surviving individual message
failures.

**Called by:** `main.py`'s `start_scan` route (via
`asyncio.create_task`, i.e. fire-and-forget from the route's
perspective - the route returns `scan_id` immediately while this
function continues running in the background).

**Calls:** `provider.get_message` (the `MailProvider` passed in),
`analysis_service.analyze_email_safe`, `store.STORE`.

**Important function:** `run_scan(*, scan_id, session_id, provider,
message_ids)`. Uses `asyncio.Semaphore(MAX_CONCURRENT_ANALYSES=5)` to
bound concurrency, and `loop.run_in_executor(None, ...)` for both the
provider fetch and the analysis call (both are blocking/synchronous
functions) so they don't block the event loop while multiple run
concurrently. Logs `email <id>: fetch=Xs` at INFO level per message
(logger name `"email_threat_platform.scan"`) - a separate timing
signal from `analysis_service`'s per-stage log, specifically isolating
provider network latency.

**Security relevance:** Every result is saved via
`STORE.save_result(session_id=session_id, ...)` - ties every scan
result back to the session that requested it.

**Current status:** Working, canonical - verified directly in this
environment with a fake provider (6 successful + 1 forced-failure
message): scan completed with `analyzed=6, failed=1`, and a
cross-session read of the same `scan_id` correctly returned `None`.

============================================================
## backend/app/schemas/email_message.py
============================================================
**Purpose:** The canonical, provider-independent email representation.

**Called by:** `email_parser.py` (constructs it), `providers/base.py`
(type hint), `analysis_service.py`, `m1_adapter.py` (all consume its
fields).

**Important classes:** `AttachmentMeta` (filename, content_type,
extension, size_bytes, sha256, and the transient `content_bytes`
field - see its own inline comment: "never written to logs, the
result cache, or the JSON API response"), `NormalizedEmail` (provider,
account_id, message_id, thread_id, sender, recipient, cc, bcc,
subject, date, reply_to, return_path, received_headers, received_spf,
authentication_results, all_headers, body, html_body, urls,
attachments).

**Dependencies:** `pydantic` (`BaseModel`, `Field`).

**Current status:** Working, canonical - the only email schema
actually used by running code.

============================================================
## backend/app/schemas/m1.py
============================================================
**Purpose:** `M1Input`/`M1Output` - the documented input/output
contract for the header/auth analyzer.

**Called by:** `m1_adapter.py` (`M1Input`). **`M1Output` itself is
imported by `schemas/analysis.py` only** (see below - that file is
dead), so `M1Output` is constructed nowhere in the live pipeline;
`m1_header_analyzer.py` returns a plain dict, not an `M1Output`
instance.

**Current status:** `M1Input` is Working/canonical (real input
shape). `M1Output` is defined but not actually instantiated by any
live code path - low-severity dead code (the shape it describes is
still produced, just as a dict, not this class).

============================================================
## backend/app/schemas/threat_intel.py
============================================================
**Purpose:** Pydantic models mirroring the threat-intelligence result
shape (`PhishTankResult`, `SpamhausResult`, `LocalHeuristicResult`,
`ThreatIntelligenceResult`).

**Called by:** Only `backend/app/schemas/analysis.py` imports this
file. Verified via `grep -rln "schemas.threat_intel"` across
`backend/` - the only hit is `analysis.py` itself.

**Current status: DEAD CODE (transitively).** Since `analysis.py`
(the only importer of this file) is itself never imported anywhere
live (see next entry), these model classes are never instantiated by
the running application. `threat_intel/aggregator.py` returns plain
dicts, not these classes.

============================================================
## backend/app/schemas/analysis.py
============================================================
**Purpose:** A fully-specified Pydantic model (`AnalysisResult`) for
the unified analysis result, plus supporting models
(`EmailSummary`, `Classification`, `M2Result`, `HeaderAnalysis`,
`GeoResult`, `AttachmentInfo`, `RiskResult`).

**Called by:** NOBODY. Verified via `grep -rn "schemas.analysis\|schemas
import analysis"` across `backend/` - zero matches outside the file
itself.

**Current status: DEAD CODE - confirmed by import trace, not
assumed.** `analysis_service.py`'s `analyze_normalized_email` builds
and returns a plain Python dict with a similar-but-not-identical shape
(the field names happen to mostly match, but the object returned is a
`dict`, never an `AnalysisResult` instance, so this class's
validation, defaults, and type coercion never actually run). This
appears to be a schema that was designed early and then the
orchestrator was implemented against plain dicts instead, without the
schema being wired in or removed.

============================================================
## static/index.html
============================================================
**Purpose:** The single HTML page for the entire dashboard. Defines
8 `<section class="view" data-view-id="...">` blocks (dashboard,
scans, intel, cases, reports, custom-email, settings - "dashboard"
doubles as "inbox" via a JS-side alias) plus a slide-over detail panel
and a toast container, all controlled by `app.js`.

**Loads:** `/assets/styles.css`, `/assets/app.js` (served by
`main.py`'s `StaticFiles` mount at `/assets`, which maps to the
`static/` directory - i.e. `index.html`'s own directory).

**Current status:** Working. **Found during this inspection: stale
copy in the UI.** The Settings -> About section's text says: "YARA
attachment scanning ... documented as planned in PROJECT_CONTEXT.md
but are not implemented in this build" - this is now factually
incorrect. YARA scanning IS implemented (`backend/app/security/yara/`)
even though it currently degrades to `scanned: false` because
`yara-python` isn't installed in this dev environment. This is a
documentation-vs-code drift inside the shipped HTML itself, not fixed
in this pass per the "document, don't change" instruction.

============================================================
## static/app.js
============================================================
**Purpose:** All frontend logic - state management, every `fetch()`
call to the backend, theme handling, sidebar routing, the detail
panel, and the Custom Email drag-and-drop uploader. Wrapped in a
single IIFE, no framework, no build step.

**Calls:** See API_FLOW.md for the exhaustive endpoint list. Verified
by direct grep of every `apiGet(...)`/`apiPost(...)` call site.

**Important functions:** `showToast`, `applyTheme`/`initTheme`,
`switchView` (sidebar routing), `refreshConnectionStatus`/
`renderConnectionStatus` (auth-state lifecycle), `doLogout`,
`loadEmailPage` (pagination), the scan button handler + `pollScan`,
`renderTable`/`riskBadge`/`updateSummaryCards`, `openDetailPanel`/
`closeDetailPanel`, `loadScansView`, `loadIntelView`, `loadCasesView`,
`loadReportsView`, `loadSettingsView`/`renderSettingsAccountArea`,
the Custom Email drag-and-drop handlers + batch-analyze handler.

**Current status:** Working. **Found during this inspection:** the
single-file `POST /api/analyze` endpoint that still exists in
`main.py` has NO caller anywhere in this file - the Custom Email page
only calls `POST /api/analyze/batch`, even for a single selected
file. `/api/analyze` (singular) is currently backend-only dead code
from the frontend's perspective (still reachable directly via
Swagger/curl).

============================================================
## static/styles.css
============================================================
**Purpose:** All styling - CSS custom-property-based theme system (6
presets: soc-dark, midnight-blue, graphite-dark, professional-light,
azure-light, neutral-light, plus a JS-resolved "system" option), plus
component styles for every view.

**Current status:** Working. **Found during this inspection: minor
dead CSS.** The `.theme-menu` ruleset (an absolute-positioned dropdown
popup, originally for a top-bar theme picker) has no corresponding
element in the current `index.html` - the theme picker was moved into
the Settings page as a plain grid (`.theme-grid`), which reuses the
`.theme-menu-group`/`.theme-menu-label` class names (still active) but
not the `.theme-menu` dropdown-positioning class itself (now unused).

============================================================
## backend/app/models/*.pkl (4 files)
============================================================
**Purpose:** Pre-trained scikit-learn artifacts:
`phishing_model.pkl` + `phishing_vectorizer.pkl` (binary phishing/safe
classifier), `multithreat_model.pkl` + `multithreat_vectorizer.pkl`
(multi-class: none/phishing/prompt_attack/spam/suspicious).

**Loaded by:** `ml_classifier.py` via `joblib.load`, once at import
time.

**Current status:** Working, verified loadable and usable for
inference in this environment (scikit-learn 1.8.0 here vs. whatever
version they were originally trained with - a
`InconsistentVersionWarning` prints on load but predictions still
succeed).

============================================================
## backend/app/threat_intel/data/phishtank.json, spamhaus_drop.txt
============================================================
**Purpose:** The local threat-intelligence feed data files (see
`phishtank_local.py`/`spamhaus.py` above).

**Current status:** Present, loadable, indexed successfully in
testing. `phishtank.json` is a static snapshot (~17MB) - refreshed
only by manually running `feed_updater.py`, never automatically.

============================================================
## Top-level project files
============================================================

**requirements.txt** - Lists: `fastapi`, `uvicorn[standard]`,
`python-multipart` (for file uploads), `pydantic>=2`, `joblib`,
`scikit-learn`, `pandas` (listed but not directly imported anywhere
found by this inspection - possibly a transitive dependency of
scikit-learn tooling, or leftover from an earlier data-prep script),
`google-auth`, `google-auth-oauthlib`, `google-api-python-client`,
`msal`, `requests`, `itsdangerous`, `yara-python`.

**.env.example** - Documents `SESSION_SECRET_KEY`, `GOOGLE_CLIENT_ID`,
`GOOGLE_CLIENT_SECRET`, `GOOGLE_REDIRECT_URI`, `MICROSOFT_CLIENT_ID`,
`MICROSOFT_CLIENT_SECRET`, `MICROSOFT_TENANT_ID`,
`MICROSOFT_REDIRECT_URI`. Does NOT document `SESSION_COOKIE_SECURE`
(read by `session.py` - see that entry above).

**.gitignore** - Excludes `.env`, `venv/`, `__pycache__/`, `*.pyc`,
`credentials.json`, `token.json`.

**README.md, ARCHITECTURE.md, PROJECT_CONTEXT.md, MERGE_LOG.md** -
Prior-session project documentation (architecture narrative, merge
decisions/history, known limitations as of each prior pass). Not
duplicated here; this `docs/` set is a fresh, code-verified pass
specifically intended to stand alone without needing those files or
the earlier conversation, per this task's instructions. Where this
`docs/` set and those files could appear to disagree, this `docs/`
set reflects direct inspection of the current code and should be
treated as authoritative for CURRENT state; the older files retain
historical value (why decisions were made) but are not re-verified
here line-by-line.

============================================================
## Files/directories explicitly out of scope (not application code)
============================================================
`__pycache__/` directories (compiled bytecode, regenerated
automatically, git-ignored). No `.venv/`, `node_modules/`, or test
suite directory exists in the current workspace - there is currently
no automated test suite (`tests/`) in this project.
