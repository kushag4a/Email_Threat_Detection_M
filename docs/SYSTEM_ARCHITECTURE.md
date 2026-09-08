# SYSTEM_ARCHITECTURE.md

This document describes the CURRENT, VERIFIED state of the
ValorProtects codebase as it exists in this workspace right now. It
does not describe intended, planned, or discussed-but-unbuilt
functionality except where explicitly marked "Future".

## A. Product purpose

ValorProtects is a hackathon-stage email security analysis platform.
A user connects a Gmail or Microsoft mailbox (or uploads raw `.eml`
files with no account connection at all), the application retrieves
messages, runs each one through a fixed analysis pipeline (header/
authentication checks, conditional attachment security scanning,
AI/ML classification, local threat-intelligence lookups, IP
geolocation, and a composite risk engine), and displays the result in
a browser dashboard.

## B. Current runtime architecture

One process, one language, one framework:

```
Browser (static/index.html + static/app.js + static/styles.css)
        |  fetch() calls, credentials: "include"
        v
FastAPI app (backend/app/main.py), served by Uvicorn
        |
        +-- serves the dashboard itself (GET "/", StaticFiles at /assets)
        +-- OAuth routes (Google, Microsoft)
        +-- mailbox/scan/analysis API routes
        v
In-process Python modules (providers, parser, analysis pipeline,
risk engine, in-memory session/result stores)
```

There is no separate frontend build step, no Node.js process, no
database, and no cache server in the current implementation. The
dashboard's HTML/CSS/JS files are plain static files served directly
by FastAPI's `StaticFiles` mount.

## C. Major layers

1. **Mail Provider Layer** - `backend/app/providers/` - one class per
   provider (`GmailProvider`, `MicrosoftGraphProvider`), both
   implementing the `MailProvider` abstract base
   (`backend/app/providers/base.py`).
2. **OAuth Authentication** - `backend/app/auth/` - `google_oauth.py`,
   `microsoft_oauth.py` (build authorization URLs, exchange codes),
   and `session.py` (signed-cookie session store).
3. **Email Parser** - `backend/app/services/email_parser.py` - the
   only code that turns provider-specific data into the canonical
   `NormalizedEmail` object.
4. **Analysis pipeline** - `backend/app/services/analysis_service.py`
   is the single orchestrator. It calls, in order: attachment
   analysis, header/auth analysis, AI/ML classification, threat
   intelligence, geolocation, and the risk engine.
5. **Attachment Security Engine** -
   `backend/app/services/attachment_analysis.py`, which itself calls
   `backend/app/services/file_type_detector.py` (magic bytes) and
   `backend/app/security/yara/scanner.py` (YARA).
6. **Threat Intelligence Engine** - `backend/app/threat_intel/`
   (PhishTank local feed, Spamhaus DROP local feed, local heuristics).
7. **Storage** - `backend/app/services/store.py` (analysis results +
   scan progress) and `backend/app/auth/session.py`
   (`SESSION_STORE`) - both plain in-process Python dicts.
8. **SOC Dashboard** - `static/index.html` + `static/app.js` +
   `static/styles.css`.

## D. Current components (by responsibility)

| Responsibility | Canonical file | Notes |
|---|---|---|
| Email parsing | `backend/app/services/email_parser.py` | Only parser in the codebase; no duplicates exist currently. |
| Analysis orchestration | `backend/app/services/analysis_service.py` | Only orchestrator. |
| Risk scoring | `backend/app/services/risk_engine.py` | Only risk engine. |
| Threat intelligence | `backend/app/threat_intel/aggregator.py` | Combines `phishtank_local.py`, `spamhaus.py`, `local_engine.py`. |
| Geolocation | `backend/app/services/geolocation.py` | Only geolocation implementation. |
| YARA scanning | `backend/app/security/yara/scanner.py` | Only YARA wrapper. |
| Magic-byte detection | `backend/app/services/file_type_detector.py` | Only file-type detector. |
| Header/auth analysis | `backend/app/forensic/m1_header_analyzer.py` | Only implementation. |
| AI/ML classification | `backend/app/services/ml_classifier.py` | Wraps the 4 `.pkl` model/vectorizer files plus `threat_classifier.py`'s keyword rules. |

See FILE_BY_FILE_GUIDE.md for full detail and for files that are
NOT part of any active call path (dead/legacy).

## E. Data flow

See DATA_FLOW.md for the full trace. Summary:

```
Browser -> FastAPI route -> MailProvider -> raw provider data
   -> email_parser -> NormalizedEmail -> analysis_service
   -> attachment_analysis (+ file_type_detector + yara.scanner)
   -> m1_header_analyzer -> ml_classifier -> threat_intel.aggregator
   -> geolocation -> risk_engine -> result dict
   -> store.py (session-scoped) -> JSON response -> app.js -> DOM
```

## F. Provider architecture

`MailProvider` (abstract, `backend/app/providers/base.py`) defines:
`get_current_user()`, `list_messages()`, `get_message()`,
`get_message_summary()`, `disconnect()`.

Two concrete implementations exist and are both wired into
`backend/app/main.py`'s `_get_provider()` helper:
- `GmailProvider` (`name = "gmail"`) - uses `googleapiclient` against
  the Gmail API v1, native `nextPageToken` pagination.
- `MicrosoftGraphProvider` (`name = "microsoft"`) - uses `requests`
  against Microsoft Graph v1.0 REST endpoints directly (no Graph SDK),
  native `@odata.nextLink` pagination.

Both return `NormalizedEmail` from `get_message()` and `MessageSummary`
from `get_message_summary()` - the rest of the application never
branches on provider identity except to display it.

**Naming inconsistency found during inspection** (not fixed, per this
task's "document, don't change" instruction): the OAuth/query-param
provider identifier used throughout `main.py`'s routes and by the
frontend is the string `"google"`, but `GmailProvider.name` (used when
saving results into `store.py`) is the string `"gmail"`. This means
`GET /api/analysis/{provider}/{account_id}/{message_id}` would need
`"gmail"` in its path to ever find a Gmail-sourced result, not
`"google"` as used everywhere else. See API_FLOW.md and
CURRENT_STATE_SUMMARY.md for the practical impact (this endpoint has
no frontend caller, so the inconsistency is currently latent).

## G. Security analysis architecture

See DATA_FLOW.md section 6 and the dedicated attachment-yara-flow
diagram. Short version: attachment analysis runs first and is
genuinely conditional (skipped entirely, including YARA, when there
are no attachments); a high-severity attachment finding can force a
deeper AI-side rule-based scan; a YARA high/medium match forces a
risk-score floor in the final risk engine so it cannot be diluted by
a low AI score.

## H. Frontend architecture

Single HTML page (`static/index.html`) with 8 `<section class="view">`
blocks, only one visible at a time (`.view.active`), toggled by
`static/app.js`'s `switchView()` function keyed off `data-view`
attributes on the sidebar `<li>` items. No frontend framework, no
build step, no bundler - one plain `<script>` tag loading
`static/app.js` as an IIFE. See FRONTEND_FLOW.md for full detail.

## I. Storage / session architecture

Two independent in-process Python dictionaries, both defined at
module import time and never persisted to disk:
- `backend/app/auth/session.py::SESSION_STORE` - `session_id ->
  {"google": {...}, "microsoft": {...}}` (OAuth credentials/tokens).
- `backend/app/services/store.py::ResultStore` (singleton instance
  `STORE`) - analysis results keyed by `(session_id, provider,
  account_id, message_id)`, and scan progress keyed by `scan_id`.

The session cookie (`eta_session`) carries only a signed, random
session id (via `itsdangerous.URLSafeSerializer`), never a token or
secret. See AUTH_FLOW.md and SECURITY_MODEL.md.

## J. Current limitations

See CURRENT_STATE_SUMMARY.md for the full, itemized list. Highlights:
in-memory-only storage (wiped on restart); `yara-python` was not
installed in the environment this project was developed in, so YARA
scanning currently always reports `scanned: false` with a reason,
by design, rather than faking a result; Microsoft OAuth has never
been exercised against a real Azure app registration; the
`"google"`/`"gmail"` provider-name inconsistency noted above; the
internal API response still uses `m1`/`m2`/`m3`/`m4` dict keys rather
than fully renamed functional names (the dashboard labels them
functionally regardless).

## K. Future architecture ideas (NOT current - proposed only)

These items are documented elsewhere in this repository
(`ARCHITECTURE.md`, `PROJECT_CONTEXT.md`) as explicitly deferred and
are NOT implemented in the current codebase:
- A Node.js API gateway in front of FastAPI (response caching,
  WebSocket/streaming events, rate limiting).
- Redis or another external cache/session store in place of the
  in-process dicts.
- PostgreSQL or another persistent database in place of the in-memory
  `ResultStore`.
- Organization/personal mail-action policies (quarantine, allow/block
  lists, content-policy rules).
- A GitHub-Releases-based update checker.
- Enterprise pre-delivery mail-gateway integration (the current
  system only ever analyzes mail *after* it has already been
  delivered to the mailbox, via the provider's read API).

## Current execution command

```
pip install -r requirements.txt
cp .env.example .env      # fill in OAuth credentials to test login; optional for .eml upload testing
uvicorn backend.app.main:app --reload --port 8000
```

Verified: `backend/app/main.py` defines a module-level `app = FastAPI(...)`
object, so `backend.app.main:app` is the correct Uvicorn target. The
module also `app.mount("/assets", StaticFiles(directory="static"))` -
this is a relative path, so **Uvicorn must be started from the project
root** (the directory containing `static/`, `backend/`,
`requirements.txt`), not from inside `backend/`.

**Dashboard URL:** `http://localhost:8000`

**Swagger/OpenAPI URL:** `http://localhost:8000/docs` (auto-generated
by FastAPI; not a hand-written file in this project).
