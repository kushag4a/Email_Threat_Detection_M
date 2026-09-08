# DEMO_FLOW.md

Every step below is checked against the actual current code. Steps
that cannot be verified as working in this environment (no network
access, no real OAuth credentials) are explicitly marked
**NOT CURRENTLY VERIFIED** rather than assumed to work.

## Prerequisites
```
pip install -r requirements.txt
cp .env.example .env
uvicorn backend.app.main:app --reload --port 8000
```
Must be run from the project root (the directory containing
`static/`, `backend/`, `requirements.txt`) - `main.py` mounts
`StaticFiles(directory="static")`, a path relative to the current
working directory.

## Path A: No OAuth configured (works today, zero setup)

1. Open `http://localhost:8000`. **CURRENT** - `GET /` serves
   `static/index.html`.
2. The Dashboard shows "No mailbox connected" and Connect Gmail/
   Connect Microsoft buttons. **CURRENT** - `renderConnectionStatus()`
   renders this state when both `/auth/*/status` calls return
   `connected: false`.
3. Click sidebar "Custom Email". **CURRENT** - `switchView("custom-email")`.
4. Drag a `.eml` file onto the dropzone, or click "Browse files".
   **CURRENT** - `addFiles()`/drag-drop handlers, up to 10 files.
5. Click "Analyze All". **CURRENT** - calls `POST /api/analyze/batch`,
   which runs the full pipeline (attachment analysis -> header/auth ->
   AI -> threat intel -> geolocation -> risk) with no OAuth required.
6. Per-file results appear in the table with a risk badge; a summary
   line shows "N uploaded - N analyzed - N failed - N skipped".
   **CURRENT.**

This path was directly exercised during development with synthetic
`.eml` content (a legitimate-newsletter-style message and a
phishing-style message with a malicious attachment) - see
MERGE_LOG.md for the exact test transcripts and results (LOW/7 for
the legitimate case, CRITICAL/100 and HIGH/65 for the malicious
cases).

## Path B: Gmail OAuth (requires real Google Cloud credentials)

1. Set `GOOGLE_CLIENT_ID`, `GOOGLE_CLIENT_SECRET`,
   `GOOGLE_REDIRECT_URI` in `.env` (see README.md for the Google Cloud
   Console setup steps) and restart the server.
2. Click "Connect Gmail". **CURRENT (code path), NOT CURRENTLY
   VERIFIED end-to-end** - this environment has no outbound network
   access, so the actual redirect to Google's consent screen has
   never completed here.
3. Approve access on Google's consent screen. **NOT CURRENTLY
   VERIFIED** (same reason).
4. Redirected back to the dashboard automatically, already showing
   "Gmail - your@email.com" with the inbox loaded - no second login
   click, no manual refresh. **CURRENT (code path)** - the OAuth
   callback redirects to `/`, and `app.js`'s
   `refreshConnectionStatus()` runs unconditionally on every page
   load, which is what makes this automatic. **NOT CURRENTLY
   VERIFIED end-to-end** for the same network-access reason.
5. Choose a page size (5/10/20/50/100). **CURRENT** -
   `page-size-select` triggers `loadEmailPage(null, 0)`.
6. Use Previous/Next to move between pages. **CURRENT** - backed by
   provider-native pagination tokens (Gmail `nextPageToken`).
7. Click "Scan Inbox". **CURRENT (code path)** - `POST /api/scan`
   then polling. **NOT CURRENTLY VERIFIED against a real inbox** in
   this environment.
8. Progress bar shows "Scanning X / Y". **CURRENT** - `pollScan()`
   updates from `GET /api/scan/{scan_id}` every 700ms.
9. Click a suspicious result row to open the detail panel. **CURRENT.**
10. Detail panel shows, in this order (verified against
    `openDetailPanel()`'s actual HTML construction): Email information,
    Risk (badge + score + reasons), Authentication (SPF/DKIM/DMARC),
    Header/Routing (origin IP, Reply-To/Return-Path mismatch flags),
    Attachment Security (per-attachment flags + YARA status/matches,
    or "No attachments" if none), AI/Body Analysis (phishing
    probability, top classification, whether the deeper scan ran and
    whether an attachment forced it), Geolocation/source
    infrastructure, Threat intelligence (PhishTank/Spamhaus per
    indicator), Evidence sources. **CURRENT.**
11. Open the "Scans" sidebar item to see accumulated high-risk
    history and a trend chart from this session's scans. **CURRENT**
    (only has data once at least one scan has run in this session).
12. Open "Threat Intelligence" to see PhishTank/Spamhaus/local-
    heuristic match counts. **CURRENT.**
13. Open "Settings" to change the theme (Light/Dark/System, 6
    presets). **CURRENT** - persisted in `localStorage`, applied via
    a `data-theme` HTML attribute.

## Path C: Microsoft OAuth

Structurally identical to Path B, substituting "Connect Microsoft"
and the `/auth/microsoft/*` routes. **Every step here is CURRENT as
code but NOT CURRENTLY VERIFIED** - no Microsoft Graph app
registration or credentials were available during development.

## What this demo does NOT show (because it isn't built)

- Organization/Personal mail-action policies (quarantine, block
  lists, content rules) - no UI or endpoint exists.
- A YARA match producing a real, non-mocked `HIGH`/`CRITICAL` result
  from live scanning - `yara-python` is not installed in the
  reference development environment, so every real run currently
  shows `yara: {"scanned": false, ...}` for every attachment. The
  floor-rule/forced-scan logic downstream of a YARA match was verified
  by directly mocking the scanner's return value (see MERGE_LOG.md),
  not by a live YARA match.
- An Updates/version-checker page.
- A Terms & Conditions modal.
- Exporting/downloading a report.
