# API_FLOW.md

Every route defined in `backend/app/main.py`, traced from source.
"Frontend caller" is verified by grepping `static/app.js` for the
exact path, not assumed.

---
### `GET /health`
**Purpose:** Liveness check. **Auth:** None. **Input:** None.
**Output:** `{"status": "ok"}`. **Frontend caller:** None found.
**Failure cases:** None possible (no logic beyond the literal return).

---
### `GET /auth/google/login`
**Purpose:** Start the Google OAuth flow. **Auth:** None (this route
creates the session). **Input:** None. **Output:** 503 if
`google_oauth.is_configured()` is false; otherwise a 302 redirect to
Google's consent screen with the session cookie set.
**Frontend caller:** `window.location.href = "/auth/google/login"`
(top-bar "Connect Gmail" button and the Settings page's identical
button). **Provider dependency:** None yet (pre-provider-creation).
**Failure cases:** 503 (not configured).

---
### `GET /auth/google/callback`
**Purpose:** Complete the Google OAuth flow. **Auth:** Relies on the
`state` param matching a pending entry (CSRF check), not a session
cookie. **Input:** `state`, `code` (query params, sent by Google).
**Output:** 302 redirect to `/` on success; 400 on invalid/expired
state. **Frontend caller:** None directly - this is Google's redirect
target, never called by `app.js`. **Provider dependency:** Creates a
`GmailProvider` to call `get_current_user()` before storing the
session. **Failure cases:** HTTP 400 (`ValueError` from
`exchange_code_for_credentials`, e.g. replayed/unknown state).

---
### `GET /auth/google/status`
**Purpose:** Report whether this session has a connected Gmail
account. **Auth:** Reads session if present; never errors if absent.
**Input:** None (cookie only). **Output:** `{"connected": bool,
"email"?: str}`. **Frontend caller:**
`refreshConnectionStatus()` (called on every page load and after
logout). **Failure cases:** None (always 200).

---
### `POST /auth/google/logout`
**Purpose:** Disconnect Gmail from this session. **Auth:** None
required (a no-op if not connected). **Input:** None. **Output:**
`{"connected": false}`. **Frontend caller:** `doLogout()`, called by
both the top-bar Logout button and the Settings page's Logout button.
**Failure cases:** None (always 200).

---
### `GET /auth/microsoft/login` / `GET /auth/microsoft/callback` / `GET /auth/microsoft/status` / `POST /auth/microsoft/logout`
Structurally identical to the Google routes above, substituting MSAL
for `google-auth-oauthlib`. See AUTH_FLOW.md for full detail.
**Frontend callers:** "Connect Microsoft" buttons (top bar and
Settings) call `/auth/microsoft/login`; `refreshConnectionStatus()`
calls `/auth/microsoft/status`; `doLogout()` calls
`/auth/microsoft/logout`.

---
### `GET /api/emails`
**Purpose:** List one page of inbox metadata (cheap - no bodies, no
attachments fetched). **Auth:** Requires a connected provider (401 if
not connected, via `_get_provider`). **Input (query params):**
`provider` (`google`|`microsoft`, regex-validated), `page_size`
(int, must be in `{5,10,20,50,100}` or 400), `page_token` (optional,
opaque provider-native cursor). **Output:** `{"provider", "messages":
[{"message_id","thread_id","sender","recipient","subject","date",
"snippet","has_attachments","provider"}], "next_page_token",
"page_size"}`. **Frontend caller:** `loadEmailPage()`. **Provider
dependency:** `provider.list_messages()` then, concurrently,
`provider.get_message_summary()` per item. **Failure cases:** 400
(bad page_size), 401 (not connected); a per-message summary fetch
failure does NOT fail the whole request - that message's entry is
replaced with `{"sender": "(failed to load)", ..., "error": str(exc)}`
(see `fetch_one` in `main.py`).

---
### `POST /api/scan`
**Purpose:** Start a bounded-concurrency background scan of N
messages from the current page's provider. **Auth:** Requires a
session (401) and a connected provider (401 via `_get_provider`).
**Input (query params):** `provider`, `count` (must be in
`{5,10,20,50,100}` or 400). **Output:** `{"scan_id": str,
"requested": int}` - returned immediately; the actual scan runs as a
background `asyncio.Task`. **Frontend caller:** the Scan Inbox button
handler. **Provider dependency:** `collect_message_ids()` (offloaded
to executor) calls `list_messages()` in a loop; `run_scan()` then
calls `get_message()` per id. **Failure cases:** 400 (bad count), 401
(no session / not connected). Per-message failures inside the scan do
NOT surface here - they show up later via `GET /api/scan/{scan_id}`.

---
### `GET /api/scan/{scan_id}`
**Purpose:** Poll scan progress/results. **Auth:** Requires a session
that OWNS this `scan_id` (`STORE.get_scan` returns `None` for a
different session's scan id, treated as 404). **Input:** `scan_id`
(path param). **Output:** `{"scan_id","status","requested","analyzed",
"failed","skipped","progress":"done/total","results":[...]}`.
**Frontend caller:** `pollScan()`, called every 700ms via
`setInterval` while a scan is active. **Failure cases:** 401 (no
session), 404 (unknown scan_id OR a scan_id belonging to a different
session - these two cases are indistinguishable in the response,
which is the correct behavior for not leaking scan existence across
sessions).

---
### `POST /api/analyze`
**Purpose:** Analyze one uploaded `.eml`/`.txt` file, no auth
required. **Auth:** None. **Input:** multipart file field `file`.
**Output:** The full analysis result dict (same shape as one scan
result). **Frontend caller: NONE FOUND** - `static/app.js` never
calls this exact path; the Custom Email page uses
`/api/analyze/batch` exclusively, even for a single file. This route
is currently reachable only via Swagger UI or a direct HTTP client.
**Failure cases:** 413 (>25MB), 400 (wrong extension).

---
### `POST /api/analyze/batch`
**Purpose:** Analyze up to 10 uploaded `.eml`/`.txt` files in one
request. **Auth:** None. **Input:** multipart field `files` (list,
max 10 - a request with more is rejected with 400 for the WHOLE
batch before processing any file). **Output:** `{"requested",
"analyzed","failed","skipped":0,"results":[...]}` - each result has
`source_filename` added; a too-large or wrong-extension file within
an otherwise-valid batch produces a `status: "analysis_failed"` entry
for just that file, not a whole-request failure (this is a
per-file, in-loop check, not the same as the 10-file limit which IS
whole-request). **Frontend caller:** the Custom Email page's "Analyze
All" button. **Failure cases:** 400 only if MORE than 10 files are
submitted; per-file size/extension problems are reported inside the
200 response body, not as HTTP errors.

---
### `GET /api/analysis/{provider}/{account_id}/{message_id}`
**Purpose:** Look up one previously-scanned result by its exact
storage key. **Auth:** Requires a session (401). **Input:** three
path params. **Output:** the stored result dict, or 404 if not found
for this session. **Frontend caller: NONE FOUND** (verified by grep -
`app.js` never calls this path). **Known inconsistency:** results are
stored with `provider` = the `MailProvider.name` value (`"gmail"` or
`"microsoft"`), but every other route in this file uses `"google"`
for the same provider - a caller of this route for a Gmail result
would need to pass `"gmail"` in the URL, not `"google"`, to ever get
a hit. Currently latent since nothing calls this route.

---
### `GET /api/scans/history`
**Purpose:** Up to the last 70 HIGH/CRITICAL results this session has
produced, plus a daily suspicious-count trend. **Auth:** Requires a
session (401). **Input:** None. **Output:** `{"count","requested_max":70,
"items":[{"message_id","date","sender","subject","risk"}],"trend":
[{"date","total_suspicious","critical","distinct_senders"}]}`.
**Frontend caller:** `loadScansView()` (Scans page). **Data source:**
`STORE.list_results(session_id=...)`, filtered/sorted in `main.py` -
purely computed from real stored results, nothing fabricated; an
empty session returns `count: 0, items: [], trend: []`.

---
### `GET /api/scans/bad-sources`
**Purpose:** Recurring suspicious sender domains, ranked by count.
**Auth:** Requires a session (401). **Output:** `{"sources":[{"domain",
"suspicious_count","critical_count","reasons":[...max 5],"note"}]}` -
`note` is only `"Repeated suspicious activity from this source"` when
`suspicious_count > 1`, otherwise empty string (deliberately avoids
implying a pattern from a single data point). **Frontend caller:**
`loadScansView()`.

---
### `GET /api/threat-intel/summary`
**Purpose:** Aggregate PhishTank/Spamhaus/local-heuristic match
counts across this session's results, plus each local feed file's
last-modified timestamp as a proxy for "last update" (there is no
separate feed-update-tracking database). **Auth:** Requires a session
(401). **Output:** `{"sources":[{"name","matches","indicators_checked",
"last_feed_update","status"}, ...]}` for exactly 3 sources: "PhishTank
(local feed)", "Spamhaus DROP (local feed)", "Local heuristics".
**Frontend caller:** `loadIntelView()` (Threat Intelligence page).

---
### `GET /api/reports/summary`
**Purpose:** Session-wide totals: risk-level breakdown, top domains/
senders/threat-categories/attachment-extensions, and SPF/DKIM/DMARC
failure counts. **Auth:** Requires a session (401). **Output:**
`{"total_analyzed","risk_breakdown":{"LOW","MEDIUM","HIGH","CRITICAL",
"UNKNOWN"},"top_domains","top_senders","top_categories",
"top_attachment_types","auth_failures"}`. **Frontend caller:**
`loadReportsView()` (Reports page).

---
### `GET /api/cases`
**Purpose:** Group this session's HIGH/CRITICAL results by sender
domain into a lightweight "campaign" view. **Auth:** Requires a
session (401). **Output:** `{"cases":[{"case_id":"CASE-0001",...
"domain","first_seen","last_seen","message_count","distinct_senders",
"distinct_ips","threat_categories","highest_risk"}]}`, sorted by
message count descending. **Frontend caller:** `loadCasesView()`
(Cases page).

---
### `GET /`
**Purpose:** Serve the dashboard's `index.html`. **Auth:** None.
**Output:** `FileResponse("static/index.html")`. **Frontend caller:**
the browser's initial navigation, and every OAuth callback's final
redirect target.

---
### `/assets/*` (mounted, not a hand-written route)
`app.mount("/assets", StaticFiles(directory="static"), name="assets")`
- serves `static/app.js` and `static/styles.css` (and anything else
placed in `static/`) as static files.

---
## Provider-name string used in each route (verified from source)
Every route above that takes a `provider` value uses the strings
`"google"` / `"microsoft"` via the `pattern="^(google|microsoft)$"`
Query validator - EXCEPT the stored-result provider field, which is
`"gmail"` / `"microsoft"` (the `MailProvider.name` class attribute).
See the inconsistency notes above and in SYSTEM_ARCHITECTURE.md.

## Summary table

| Method | Path | Auth required | Frontend caller |
|---|---|---|---|
| GET | /health | No | None |
| GET | /auth/google/login | No | Yes |
| GET | /auth/google/callback | No (state-validated) | No (OAuth redirect target) |
| GET | /auth/google/status | No | Yes |
| POST | /auth/google/logout | No | Yes |
| GET | /auth/microsoft/login | No | Yes |
| GET | /auth/microsoft/callback | No (state-validated) | No (OAuth redirect target) |
| GET | /auth/microsoft/status | No | Yes |
| POST | /auth/microsoft/logout | No | Yes |
| GET | /api/emails | Yes (401) | Yes |
| POST | /api/scan | Yes (401) | Yes |
| GET | /api/scan/{scan_id} | Yes (401/404) | Yes |
| POST | /api/analyze | No | **No** |
| POST | /api/analyze/batch | No | Yes |
| GET | /api/analysis/{provider}/{account_id}/{message_id} | Yes (401) | **No** |
| GET | /api/scans/history | Yes (401) | Yes |
| GET | /api/scans/bad-sources | Yes (401) | Yes |
| GET | /api/threat-intel/summary | Yes (401) | Yes |
| GET | /api/reports/summary | Yes (401) | Yes |
| GET | /api/cases | Yes (401) | Yes |
| GET | / | No | (browser navigation) |
