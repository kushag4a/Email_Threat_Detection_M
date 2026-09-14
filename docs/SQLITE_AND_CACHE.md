# SQLite Persistence & Mailbox Cache

This document describes what's actually implemented, not an aspirational
design. It covers `backend/app/services/db.py`,
`backend/app/services/mailbox_cache.py`, `backend/app/services/store.py`,
and the parts of `backend/app/main.py` that call into them.

## Why SQLite was added

Two independent problems needed a persistent store:

1. **Mailbox listing was hitting Gmail/Graph on every page view**, including
   re-visiting a page you'd already seen. At `page_size=100`, listing plus
   per-message metadata fetches is expensive against Gmail's per-minute
   quota (`Total Query Cost` / `Units per minute per user`) - a few page
   views back and forth was enough to trip `403 rateLimitExceeded`.
2. **Scan results were only ever in memory** (`ResultStore`), so a server
   restart lost everything, and there was no way to avoid re-fetching and
   re-analyzing a message you'd already scanned in a previous session.

SQLite is a single-file, zero-setup persistent store that fits both needs
without adding a network dependency (Postgres/Redis) for what is currently
a single-process, single-machine app.

## Database location

`backend/app/services/db.py::default_db_path()` resolves to
`<project_root>/data/valorprotects.sqlite3` by default (creating the `data/`
directory if needed), or the path in `VALORPROTECTS_DB_PATH` if that env var
is set. Tests use `db_path=":memory:"` (SQLite's private in-memory mode) so
they never touch the real file and never share state with each other or
with a running server.

## Tables

Defined in `db.py`'s schema string, created with `CREATE TABLE IF NOT
EXISTS` on first connection (no separate migration step - safe to run
against an existing database, and safe to delete the file entirely to start
fresh):

| Table | Purpose |
|---|---|
| `accounts` | One row per `(provider, account_id)` seen; `last_seen_at` - bookkeeping only, not currently used for any policy decision. |
| `messages` | Per-message **summary** metadata: `message_id`, `thread_id`, `sender`, `recipient`, `subject`, `date`, `snippet`, `has_attachments`, `fetched_at`. Keyed by `(provider, account_id, message_id)` - identity is always this triple, never a page token (see "Page-token limitations" below). |
| `page_cache` | One row per `(provider, account_id, page_size, page_token)`: the ordered list of `message_ids` that page produced, its `next_page_token`, and `fetched_at`. Indexed on `fetched_at` for the freshness check described below. |
| `analysis_results` | The full JSON verdict for a `(session_id, provider, account_id, message_id)` scan - what lets a re-scan of the same message reuse a prior result instead of re-fetching and re-analyzing (see `scan_service.py::process_one`). |
| `scans` / `scan_results` | Scan progress (`requested`/`analyzed`/`failed`/`skipped`) and per-message results for a given `scan_id`, scoped to the `session_id` that created it. |

## What is persisted

- Message **summary** metadata (sender/subject/date/snippet/has_attachments)
  for any message that has appeared in a listed page.
- Page listings (which message IDs are on a given page, and that page's
  `next_page_token`).
- Full analysis verdicts (risk score, level, reasons, per-module evidence)
  for every message that has been scanned.
- Scan progress/results, scoped by session.

## What is NOT persisted

- **Full raw email bodies, headers, or attachments.** `mailbox_cache.py`'s
  own module docstring is explicit about this: it "never talks to
  Gmail/Graph directly" and only ever stores plain summary dicts. Scanning
  a message still requires a raw fetch from the provider (see "Scan-result
  persistence" below for the one case where that's avoided) - there is no
  local copy of message content beyond the short `snippet` field Gmail/Graph
  itself returns in listing metadata.
- OAuth tokens, credentials, or session secrets - those live in the
  existing in-memory `SESSION_STORE`/cookie mechanism, untouched by this
  work.
- Anything from a session that never made a listing or scan request.

## RAM cache (acceleration layer)

`MailboxCache` keeps a small `BoundedCache` (LRU, size-capped) in front of
SQLite for both pages and individual messages. This is purely an
accelerator:

- A RAM miss always falls through to SQLite before being reported as a
  miss to the caller.
- The RAM layer can be cleared or dropped at any time (e.g. process
  restart) without losing data - SQLite is the actual source of truth.
- It has its own optional TTL (`ram_ttl_seconds`, unused by the
  production singleton, which passes `None` = no RAM-layer expiry) that is
  **separate** from the page-freshness TTL described below - the RAM TTL
  would just mean "stop trusting the RAM copy, re-read SQLite," not "this
  page is stale, go back to Gmail."

## Page cache keys

Every page-cache and prefetch/refresh operation is keyed on the 4-tuple:

```
(provider, account_id, page_size, page_token)
```

- `provider` is canonicalized (`"gmail"` -> `"google"`) before use, so the
  legacy alias can never split one account's cache in two.
- `page_token=None` (the first page) is stored under the sentinel `""`,
  since SQLite treats every `NULL` primary-key value as distinct from
  every other `NULL` - without this, page 1 would never hit its own cache.
- `page_size` is part of the key, so switching between `5 -> 10 -> 100`
  for the same account never reuses or invalidates another page size's
  entries - each is independent.
- Changing `account_id` or `provider` never touches another account's or
  provider's rows - enforced by them being literal columns in the primary
  key, not just an in-memory convention.

## Page-token limitations

A Gmail/Graph page token is a **transport cursor**, not a permanent record
identity. The same token value is not guaranteed to mean the same thing
forever if the underlying mailbox changes shape between the moment a page
was first fetched and a later revalidation. This cache treats a page
purely as "what messages did navigating here produce, and when" - the
actual stable identity for anything long-lived (a scanned message, its
verdict) is always `(provider, account_id, message_id)`, never a page
token. This is also why a page whose cached message rows have since been
swept by retention is treated as a full cache **miss**, not a page with
holes in it - see `_hydrate_page()`.

## Freshness policy (TTL)

**Problem this solves:** without any revalidation, a cached page would be
served forever - confirmed live: a user watched Gmail show new mail from
12/11 Sept while ValorProtects kept serving a page cached from 9/10 Sept,
because nothing ever re-checked the provider once a page was cached once.

**Policy:** every page cache row's `fetched_at` column records the exact
wall-clock time (Unix epoch seconds) at which `save_page()` wrote it - i.e.
the moment the underlying provider fetch that produced it actually
completed. This is never application startup time, login time, or analysis
time; those events never call `save_page()`.

A page is **fresh** if `now - fetched_at <= VALORPROTECTS_MAILBOX_CACHE_TTL_SECONDS`
(default `3600`, i.e. 1 hour; override via that env var - not hard-coded).
`page_token=None` (the first inbox page) is not special-cased away from
this - it goes stale and gets revalidated exactly like every other page.

- **Fresh:** `/api/emails` returns the cached page immediately. No
  provider call.
- **Stale or missing:** exactly one caller refreshes the provider (see
  "Single-flight" below); everyone else joins that refresh instead of
  independently calling the provider.
- **Refresh succeeds:** `save_page()` overwrites the row with the new
  message list and a fresh `fetched_at` - both change together, atomically,
  in the same SQL statement.
- **Refresh fails:** `save_page()` is never called, so `fetched_at` is
  **not** touched - the page remains exactly as stale as it was, and the
  very next request will correctly see it as still stale (not falsely
  "refreshed") and try again, subject to the failure cooldown below. The
  old (stale) page is returned as a fallback rather than turning a
  transient provider error into a hard failure for something the user
  could otherwise still see - this is logged as a warning
  (`"mailbox refresh failed ... serving stale cached page as fallback"`) so
  it's visible in server logs, not silently hidden. If there is no cached
  copy at all (a true first-time miss that also failed), the error
  propagates - there is nothing safe to fall back to.

`MailboxCache.get_page()`'s existing return contract is unchanged by this
feature - it still returns whatever is cached, stale or not, with no
freshness filtering built in. Freshness is a deliberately separate,
explicit check (`is_page_fresh()` / `get_page_age_seconds()`), so a caller
that specifically wants the stale copy as a fallback (see above) can still
get it, and every pre-existing caller/test that doesn't know about
freshness at all keeps working unchanged.

## Single-flight / in-flight deduplication

This existed before the freshness feature (originally just for background
prefetching of the *next* page) and has been extended to cover the
foreground `/api/emails` path too, since that's where the real live quota
storm came from.

- `try_start_prefetch(...)` claims a key for exactly one refresh. A second
  caller for the same key gets `False` while the first is in flight.
- `finish_prefetch(..., failed=False)` releases the claim with no penalty
  (the default - unchanged from before this feature).
- `finish_prefetch(..., failed=True, cooldown_seconds=60)` releases the
  claim **and** starts a cooldown window during which the same key cannot
  be re-claimed at all, even though nothing is "in flight" anymore - see
  "Gmail quota protection" below.
- `wait_for_in_flight_refresh(...)` lets a caller that **lost** the race
  block until the winner finishes (success or failure), then re-read the
  cache - this is what makes 50 concurrent foreground requests for the
  same stale page collapse into exactly 1 provider call instead of 50: 49
  callers wait, then all read the same freshly-written row.

None of this uses a single global lock. The lock (`self._prefetch_lock`) is
only ever held briefly to look up or mutate a small dict keyed by the same
4-tuple as everything else - waiting on one key's event never blocks a
different account, provider, page size, or page token's refresh.

## Provider/account isolation

Every cache key, prefetch claim, cooldown, and freshness check is scoped by
the full `(provider, account_id, page_size, page_token)` tuple - there is
no code path that reads or writes across that boundary.
`TestAccountAndProviderIsolation` and the freshness suite's
`test_different_accounts_go_stale_independently` /
`test_different_providers_go_stale_independently` exercise this directly.

## Retention

Handled separately in `backend/app/services/retention.py` /
`tests/test_retention.py` (not modified by this work) - periodically sweeps
old rows out of `messages`/`page_cache`/`analysis_results` past a
configured age. Retention and the freshness TTL described above are
different mechanisms solving different problems: retention decides when
data is deleted outright; freshness decides when a still-present row is
too old to *serve without revalidating*. A page can be stale long before
retention would ever consider deleting it.

## Scan-result persistence

`analysis_results` lets `scan_service.py::process_one` reuse a prior
verdict for `(session_id, provider, account_id, message_id)` without a new
raw fetch or re-analysis, if one already exists and wasn't itself a
failure. This is the one place a "cache hit" avoids the *scan* path's raw
message fetch (distinct from the *listing* path's freshness TTL above) -
emails are immutable once received, so a complete prior verdict stays
correct indefinitely; there is no separate TTL on this table today.

## Account isolation (scans)

`ResultStore` (in `store.py`) scopes every scan and result lookup by
`session_id` in addition to `(provider, account_id, message_id)` - a scan
created by one session can never be read back by a different session,
regardless of which mailbox it touched.

## Background prefetch

`main.py::_maybe_prefetch_next_page` opportunistically warms the *next*
page (the one `next_page_token` points at) after a listing request, using
the same `try_start_prefetch(..., max_age_seconds=MAILBOX_CACHE_TTL_SECONDS)`
/ `finish_prefetch(..., failed=...)` machinery as the foreground path. This
means the same freshness and cooldown rules apply to it automatically:

- fresh -> no provider call
- stale + already in-flight -> the prefetch call is skipped (another
  prefetch or a foreground refresh is already handling it)
- stale + in a failure cooldown -> skipped, no retry until the cooldown
  elapses
- stale + nothing in flight -> exactly one background refresh

There is no periodic/polling loop anywhere in this path - prefetch only
ever runs as a direct reaction to a real `/api/emails` request that just
learned a `next_page_token`.

## Gmail quota protection

Two mechanisms combine to prevent the quota storm that was observed live
(repeated `403 rateLimitExceeded` / `Total Query Cost` errors from
back-to-back identical page-token requests):

1. **Single-flight** (above) collapses N concurrent requests for the same
   key into 1 provider call, whether the trigger is "never cached" or
   "aged past the TTL."
2. **Failure cooldown** (`finish_prefetch(failed=True)`) means that even
   a single caller retrying the same page repeatedly (e.g. a user clicking
   back and forth) cannot re-trigger a provider call for that exact page
   more than once per cooldown window (default 60s, matching Gmail's
   "Units per minute per user" quota window), regardless of how many
   `/api/emails` requests arrive in that window.

The freshness feature does not reintroduce this problem: going stale is
not "every caller fetches independently" - it is "one caller fetches, the
rest wait," exactly like a cold cache miss always worked.

## Privacy considerations

- `data/valorprotects.sqlite3` contains real, potentially sensitive mailbox
  metadata (sender addresses, subjects, message snippets) and analysis
  verdicts for whichever real account has been connected during testing.
  **Do not commit this file to a shared or public repository** - it is
  real user data, not a fixture. It is not covered by `.gitignore` by
  default in every checkout; verify before committing.
- No message body content, attachment content, or OAuth
  tokens/credentials are ever written to this database - see "What is NOT
  persisted" above.
- Deleting `data/valorprotects.sqlite3` (with the server stopped) is a
  safe way to fully reset all cached/persisted state; the schema
  recreates itself on next startup.

## Restart behavior

- SQLite content (`messages`, `page_cache`, `analysis_results`, `scans`,
  `scan_results`, `accounts`) survives a process restart - it's a real
  file on disk.
- The RAM layer (`BoundedCache`) does not - it starts empty, and the very
  next request for anything falls through to SQLite, which is exactly the
  designed behavior (RAM is acceleration, never the only copy).
- In-flight prefetch/refresh tracking (`_prefetching`, `_refresh_events`)
  and failure cooldowns (`_failed_until`) are also in-process only and
  reset on restart - if the process restarts mid-refresh, there is nothing
  to clean up; the next request for that page just starts a fresh refresh
  (or serves the SQLite copy if it's still fresh).
- `analysis_results`/scan history are not cleared by session logout -
  they're keyed by session_id, so a new login gets a new session_id and
  effectively starts with no visible history, without deleting the old
  session's data outright (retention.py handles eventual cleanup by age).

## End-to-end flow

```
GET /api/emails (provider, page_size, page_token)
        |
        v
is_page_fresh(max_age_seconds=TTL) -- reads page_cache.fetched_at
        |
   +----+----+
   |         |
 fresh     stale / missing
   |         |
   v         v
get_page()   try_start_prefetch(max_age_seconds=TTL)
RAM/SQLite       |
   |        +----+----+
   v        |         |
return    won        lost
to        |         |
caller    v         v
      mail_provider   wait_for_in_flight_refresh()
      .list_messages()   (join the winner)
      + per-message         |
        summaries           v
          |            get_page() again - now
    +-----+-----+       reflects the winner's fresh
    |           |       page (or still-stale copy
  success     failure   if the winner failed)
    |           |
    v           v
  save_page(  finish_prefetch(
   new content,  failed=True, cooldown)
   fresh          -> serve stale copy as
   fetched_at)       fallback if one exists,
  finish_prefetch(    else propagate the error
   success)
    |           |
    +-----+-----+
          |
          v
  response to caller: {messages, next_page_token}
          |
          v
  _maybe_prefetch_next_page() - same fresh/stale/
  cooldown logic, applied to next_page_token,
  off the request path (PREFETCH_POOL)
```
