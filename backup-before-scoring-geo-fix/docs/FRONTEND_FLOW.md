# FRONTEND_FLOW.md

Traced from `static/index.html` and `static/app.js` directly (859
lines of JS, 277 lines of HTML at time of writing).

## Structure

`index.html` defines a fixed shell (sidebar + top bar + toast
container + main content area + slide-over detail panel) and 8
`<section class="view" data-view-id="...">` blocks:
`dashboard`, `scans`, `intel`, `cases`, `reports`, `custom-email`,
`settings`. There is no `data-view-id="inbox"` element - "Inbox" in
the sidebar is a JS-level alias for `dashboard` (see `switchView()`).
Only one `.view` has the `active` class at a time; `app.js` toggles
this via `classList.toggle("active", ...)`. There is no client-side
router/URL change - navigating between pages does not change the
browser URL.

One script tag: `<script src="/assets/app.js"></script>`, loaded as a
plain IIFE (`(function () { "use strict"; ... })();`) - no module
system, no bundler, no framework.

## Global state (the `state` object in `app.js`)

```js
{
  provider: null,              // "google" | "microsoft" | null
  accountEmail: null,
  pageSize: 5,
  pageTokenStack: [null],      // history of page tokens, for Previous
  currentPageIndex: 0,
  nextPageToken: null,
  currentMessageIds: [],
  scanId: null,
  scanPollHandle: null,        // setInterval handle
  resultsByMessageId: {},      // message_id -> result dict (or a
                                // synthetic {status:"unscanned"} entry
                                // populated from /api/emails metadata)
  batchFiles: [],              // File objects staged for Custom Email
}
```

## Authentication-state refresh (page load lifecycle)

```
Script loads (IIFE runs top to bottom)
  -> initTheme()                       [reads localStorage, applies data-theme]
  -> wires every button/nav-item click handler
  -> LAST LINE OF THE FILE: refreshConnectionStatus()
       -> Promise.all([GET /auth/google/status, GET /auth/microsoft/status])
            (each wrapped in .catch(() => ({connected:false})) so one
             endpoint failing doesn't break the other)
       -> sets state.provider/state.accountEmail based on whichever
          responded connected:true (Google checked first)
       -> renderConnectionStatus()
            -> if connected: shows "{Gmail|Microsoft} - {email}",
               hides connect buttons, shows Logout, enables Scan
               button, hides the "No mailbox connected" prompt,
               and calls loadEmailPage(null, 0) immediately
            -> if not connected: inverse of the above
       -> renderSettingsAccountArea()   [keeps Settings page in sync
                                         even if it isn't currently visible]
```

This same `refreshConnectionStatus()` runs on EVERY page load,
including the full-page redirect FastAPI sends back to `/` after a
successful OAuth callback - this is what makes "one login is enough"
true: there is no separate "did we just come back from OAuth?"
detection, the normal page-load status check already picks up the
newly-connected session.

## Sidebar routing (`switchView`)

```js
const VIEW_LOADERS = {
  scans: loadScansView,
  intel: loadIntelView,
  cases: loadCasesView,
  reports: loadReportsView,
  settings: loadSettingsView,
};
```
Every `.nav-item` has a click listener calling
`switchView(item.getAttribute("data-view"))`, which (a) toggles the
`active` class on the clicked nav item, (b) toggles `.view.active` to
the matching `data-view-id` (mapping `"inbox"` -> `"dashboard"`), and
(c) calls that view's loader function if one exists in
`VIEW_LOADERS` (Dashboard/Inbox and Custom Email have no loader
entry - their content is either always up to date via
`renderConnectionStatus()`/`loadEmailPage()`, or is purely
client-side state for Custom Email).

## Page-by-page: implementation, data source, endpoint, limitations

### Dashboard (also "Inbox")
**Implementation:** Real. Summary cards (LOW/MEDIUM/HIGH/CRITICAL
counts), page-size selector, Scan Inbox button, Previous/Next
pagination, scan progress bar, and the email table.
**Data source:** `GET /api/emails` for the table rows before any
scan (real sender/subject/date from provider metadata); scan results
merge in via `POST /api/scan` + polling `GET /api/scan/{id}`.
**Limitations:** No inbox folder other than INBOX is selectable; no
search/filter within the table.

### Scans
**Implementation:** Real. Three panels: a CSS-bar "trend" chart
(`.trend-bar` elements sized by `total_suspicious / maxVal`), a table
of up to 70 previous HIGH/CRITICAL results, and a list of recurring
suspicious source domains.
**Data source:** `GET /api/scans/history`, `GET /api/scans/bad-sources`.
**Limitations:** Trend chart is a simple set of CSS divs, not a charting
library; only shows data accumulated in the CURRENT session
(in-memory store) - restarting the server or starting a new session
loses all history.

### Threat Intelligence
**Implementation:** Real. One card per source (PhishTank, Spamhaus
DROP, Local heuristics) showing match count, indicators checked, and
status/last-feed-update.
**Data source:** `GET /api/threat-intel/summary`.
**Limitations:** "Last feed update" is the local data FILE's
last-modified timestamp, not a record of when a lookup last actually
ran or when the feed was last refreshed against the real PhishTank
service.

### Cases
**Implementation:** Real. One card per domain with 2+ HIGH/CRITICAL
messages (implicitly - the grouping itself doesn't filter by count,
but a "case" with 1 message is still shown as a case), showing
message/sender/IP counts, categories, and date range.
**Data source:** `GET /api/cases`.
**Limitations:** Grouping key is sender domain only - no clustering
by shared IP, subject similarity, or attachment hash. This is
explicitly described in the code as "a lightweight, real 'campaign'
view - not a full case-management system" (see `main.py` comment).

### Reports
**Implementation:** Real. Overview counts, top domains/senders/
categories/attachment-types, and auth-failure counts.
**Data source:** `GET /api/reports/summary`.
**Limitations:** No date-range filtering, no export/download
functionality (mentioned as a "nice to have" in project docs but not
implemented - no button or endpoint for it exists in this codebase).

### Custom Email
**Implementation:** Real. Drag-and-drop zone + browse button, staged
file list (removable individually), "Analyze All" button, per-file
result table, and a summary line.
**Data source:** `POST /api/analyze/batch` only (verified: the
frontend never calls the single-file `POST /api/analyze` endpoint,
even for one selected file).
**Limitations:** Hard cap of 10 files per batch (`MAX_BATCH_FILES` in
JS, matching the backend's `MAX_FILES`); results from this page are
NOT saved to the session's result store (`STORE`), so they never
appear in Scans/Cases/Reports/Threat Intelligence - confirmed by
tracing `analyze_eml_upload()`, which never calls `STORE.save_result`.

### Settings
**Implementation:** Partial by design. "Appearance" (theme grid, real
and functional), "Accounts" (shows connected account + Logout, or
Connect buttons - real, calls the same endpoints as the top bar), and
"About" (static text). **No** organization/personal policy pages,
Updates/version-checker, or Terms & Conditions modal exist in this
codebase - the About section's own text says so, though that text is
itself now slightly stale regarding YARA (see FILE_BY_FILE_GUIDE.md's
`index.html` entry).

## Mapping every major UI action to its backend call

| UI action | Function | Backend call(s) |
|---|---|---|
| Page load | `refreshConnectionStatus` | `GET /auth/google/status`, `GET /auth/microsoft/status` |
| Click "Connect Gmail" | (inline handler) | Navigates to `/auth/google/login` (full page navigation, not fetch) |
| Click "Connect Microsoft" | (inline handler) | Navigates to `/auth/microsoft/login` |
| Click "Logout" | `doLogout` | `POST /auth/{provider}/logout`, then full client-state reset |
| Click refresh icon | (inline handler) | `loadEmailPage(null, 0)` if connected, else `refreshConnectionStatus()` |
| Change page-size dropdown | (inline handler) | `loadEmailPage(null, 0)` |
| Click Previous/Next | (inline handlers) | `loadEmailPage(token, index)` |
| Click "Scan Inbox" | (inline handler) | `POST /api/scan`, then `pollScan()` -> `GET /api/scan/{id}` every 700ms |
| Click a scanned table row | `openDetailPanel` | None (renders from already-fetched `state.resultsByMessageId`) |
| Click sidebar "Scans" | `switchView` -> `loadScansView` | `GET /api/scans/history`, `GET /api/scans/bad-sources` |
| Click sidebar "Threat Intelligence" | `switchView` -> `loadIntelView` | `GET /api/threat-intel/summary` |
| Click sidebar "Cases" | `switchView` -> `loadCasesView` | `GET /api/cases` |
| Click sidebar "Reports" | `switchView` -> `loadReportsView` | `GET /api/reports/summary` |
| Click sidebar "Settings" | `switchView` -> `loadSettingsView` | None directly (re-renders from existing `state`) |
| Click a theme option | (inline handler) | None (pure client-side, `localStorage` + `data-theme` attribute) |
| Drag/drop or browse files (Custom Email) | `addFiles` | None (client-side staging only) |
| Click "Analyze All" | (inline handler) | `POST /api/analyze/batch` |

## Error / loading states (verified from code)

- `apiGet`/`apiPost` both distinguish a network-level failure
  (`fetch()` itself throwing) from a non-2xx HTTP response, and both
  paths end up calling `showToast(...)` somewhere up the call chain -
  no `alert()` calls exist anywhere in the current `app.js`.
- `showToast(message, kind)` creates a `<div class="toast toast--{error|info}">`
  in `#toast-container`, auto-removed after 6 seconds.
- The Scan button is disabled while a scan is in flight and
  re-enabled in both the success path (`scan.status === "complete"`)
  and the polling-failure path (`catch` block clears the interval and
  re-enables the button) - verified there is no code path that leaves
  it permanently disabled after a failure.
- Logout is implemented as "best-effort": if the `POST
  /auth/{provider}/logout` call itself fails, `doLogout()` still
  proceeds to clear all client-side state (with a toast explaining
  the request failed) rather than leaving the UI stuck in a
  "connected" state.

## Known frontend/backend mismatches found during this inspection
See FILE_BY_FILE_GUIDE.md and API_FLOW.md for full detail:
1. `POST /api/analyze` (singular) has no caller.
2. `GET /api/analysis/{provider}/{account_id}/{message_id}` has no
   caller, and would need `"gmail"` rather than `"google"` in its URL
   to ever succeed for a Gmail result.
3. The Settings -> About text's claim that YARA "is not implemented
   in this build" is stale relative to the actual backend code.
