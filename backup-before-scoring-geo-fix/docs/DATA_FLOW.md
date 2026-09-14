# DATA_FLOW.md

Traced directly from source (see FILE_BY_FILE_GUIDE.md for per-file
detail). All statements below are CURRENT unless marked otherwise.

## Top-level flow

```
USER (browser)
  v
static/app.js  (fetch calls, credentials: "include")
  v
backend/app/main.py  (FastAPI route)
  v
Auth / Provider layer (backend/app/auth/*, backend/app/providers/*)
  v
Email retrieval (MailProvider.get_message / get_message_summary)
  v
Email normalization (backend/app/services/email_parser.py -> NormalizedEmail)
  v
Security analysis (backend/app/services/analysis_service.py)
  v
Final result dict
  v
backend/app/services/store.py (session-scoped cache)
  v
JSON response
  v
static/app.js renders into the DOM
```

## Stage-by-stage (Gmail path, CURRENT)

```
GET /auth/google/login
  -> google_oauth.build_authorization_url(session_id)
  -> 302 redirect to Google's consent screen

GET /auth/google/callback?code&state
  -> google_oauth.exchange_code_for_credentials(state, full_url)
  -> GmailProvider(credentials)
  -> provider.get_current_user()   [Gmail API: users().getProfile()]
  -> SESSION_STORE[session_id]["google"] = {credentials, email}
  -> 302 redirect to "/"

GET /api/emails?provider=google&page_size=N[&page_token=...]
  -> _get_provider(request, "google") -> GmailProvider
  -> provider.list_messages(page_size, page_token)
       [Gmail API: users().messages().list(labelIds=["INBOX"])]
  -> for each item, concurrently (ThreadPoolExecutor, main.py):
       provider.get_message_summary(message_id)
         [Gmail API: users().messages().get(format="metadata",
          metadataHeaders=["From","To","Subject","Date"])]
  -> MessageSummary.to_dict() per message
  -> JSON: {provider, messages: [...], next_page_token, page_size}

POST /api/scan?provider=google&count=N
  -> collect_message_ids() [run_in_executor] -> repeated list_messages() calls
     until N ids collected or pages exhausted
  -> STORE.create_scan(session_id, requested=len(ids))
  -> asyncio.create_task(run_scan(...))          <- returns immediately
  -> run_scan (backend/app/services/scan_service.py):
       asyncio.Semaphore(5) bounds concurrency
       per message_id, in parallel up to 5 at once:
         provider.get_message(message_id)  [run_in_executor]
           [Gmail API: users().messages().get(format="raw")]
           -> base64 decode -> email_parser.parse_rfc822_bytes(...)
           -> NormalizedEmail
         analysis_service.analyze_email_safe(email)  [run_in_executor]
           -> see "Security analysis" stage below
         STORE.append_scan_result(scan_id, result)
         STORE.save_result(session_id, provider="gmail", account_id, message_id, result)
         STORE.update_scan(scan_id, analyzed=+1 or failed=+1)
       STORE.update_scan(scan_id, status="complete")

GET /api/scan/{scan_id}   [polled every 700ms by app.js]
  -> STORE.get_scan(scan_id, session_id)  [None if not owned by this session]
  -> JSON: {status, requested, analyzed, failed, skipped, progress, results}
```

The Microsoft path is structurally identical from `POST /api/scan`
onward; only `list_messages`/`get_message`/`get_message_summary`
differ (Graph REST calls instead of Gmail API calls - see
FILE_BY_FILE_GUIDE.md's `microsoft_provider.py` entry). **This path
has never been executed against a real Microsoft tenant in this
environment (UNTESTED)** - documented as such throughout.

## The ".eml upload" path (CURRENT, no OAuth needed)

```
POST /api/analyze  (single file, currently unused by the frontend - see API_FLOW.md)
  or
POST /api/analyze/batch  (up to 10 files, used by the Custom Email page)
  -> file bytes read
  -> loop.run_in_executor(None, analyze_eml_upload, content)
       -> email_parser.parse_rfc822_bytes(content, provider="upload", message_id="uploaded-file")
       -> analyze_email_safe(email)
  -> JSON result (single dict, or {requested, analyzed, failed, skipped, results} for batch)
```

Note: results from the upload path are NOT written to
`backend/app/services/store.py` - they are returned directly in the
HTTP response and never appear in the Scans/Cases/Reports/Threat
Intelligence pages (those pages only read `STORE.list_results()`,
which the upload path never populates). This is a real, current
behavior, not a bug per se, but worth knowing: uploaded-file results
are ephemeral to that one request/response.

## Security analysis stage, expanded (CURRENT - the single orchestrator)

This is `backend/app/services/analysis_service.py::analyze_normalized_email`,
traced top-to-bottom exactly as written:

```
NormalizedEmail
  v
(1) attachment_analysis.analyze_attachments([a.model_dump() for a in email.attachments])
      - if email.attachments is empty: returns immediately,
        {"scanned": False, "reason": "No attachments", "items": [],
         "has_high_severity": False, "high_severity_filenames": []}
        WITHOUT calling file_type_detector or the YARA scanner at all.
      - if non-empty, PER ATTACHMENT:
          category = extension-based (executable_or_script / macro_enabled_document
                     / archive / document / image / unknown)
          disguised-double-extension check (e.g. invoice.pdf.exe)
          file_type_detector.detect_file_type(content_bytes)   <- magic bytes
          file_type_detector.check_extension_mismatch(extension, detected_category)
          yara_scanner.scan_bytes(content_bytes)                <- YARA
      timer.mark("attachments")
  v
(2) m1_adapter.prepare_m1_input(email) -> m1_header_analyzer.analyze_email(...)
      -> {"spf","dkim","dmarc","origin_ip"}
    _header_analysis(email) -> {"reply_to_mismatch","return_path_mismatch"}
      (compares real addresses via email.utils.parseaddr, not raw header strings)
    timer.mark("m1")
  v
(3) ml_classifier.build_analysis_text(email) -> one string
    ml_classifier.classify_email(text, force_rule_based=attachment_result["has_high_severity"])
      -> phishing_model.predict_proba(...) , multithreat_model.predict_proba(...)
      -> if phishing_probability >= 0.40 OR force_rule_based:
           threat_classifier.detect_threats(text)   <- rule-based keyword scan
      -> {"safe_probability","phishing_probability","threat_categories",
          "rule_based_threats","top_classification","forensics_triggered",
          "forensics_forced_by_attachment"}
    timer.mark("m2")
  v
(4) ips = [m1_result["origin_ip"]] if present else []
    threat_intel.aggregator.analyze_threat_intelligence(ips, email.urls)
      -> phishtank_local.check_url() per URL   (local JSON feed lookup)
      -> spamhaus.check_ip() per IP            (local CIDR list lookup)
      -> local_engine.analyze_url()/analyze_ip() per indicator
      -> {"phishtank":[...], "spamhaus":[...], "local_heuristics":[...]}
    timer.mark("m3")
  v
(5) geolocation.get_ip_geolocation(ip) per ip in ips
      -> checked against _GEO_CACHE first (1hr TTL)
      -> else HTTPS GET to ipapi.co, or an honest failure state
    timer.mark("m4")
  v
(6) risk_engine.calculate_risk(m1=m1_result, m2=m2_result, m3=m3_result,
                                header_analysis=..., attachment_analysis=attachment_result)
      -> additive scoring (see FILE_BY_FILE_GUIDE.md for the full weight table)
      -> EXPLICIT FLOOR: if any attachment has a high/medium YARA match,
         score = max(score, 65)  regardless of body/AI score
      -> {"score","level","reasons","contributing_modules"}
    timer.mark("risk")
    timer.log(message_id)   <- writes the per-stage timing line to the
                               "email_threat_platform.analysis" logger
  v
Final dict: {message_id, provider, account_id, email, header_analysis,
             m1, m2, m3, m4, urls, attachments_present, attachments,
             attachment_analysis, risk, evidence_sources, status,
             error, analyzed_at}
```

`analyze_email_safe` wraps the above in a `try/except Exception` -
any failure produces `{"status": "analysis_failed", "error": str(exc),
"risk": {"score":0,"level":"UNKNOWN",...}}` instead of raising, which
is what lets a batch scan continue past one bad message.

## Result storage and retrieval (CURRENT)

Every scan result is saved via
`STORE.save_result(session_id=session_id, provider=provider.name,
account_id=result.get("account_id",""), message_id=message_id,
result=result)` - note `provider.name` here is `"gmail"` or
`"microsoft"` (the `MailProvider` subclass attribute), NOT `"google"`
(the OAuth/query-param string). See SYSTEM_ARCHITECTURE.md's
provider-naming note. The Scans/Cases/Reports/Threat-Intelligence
endpoints all call `STORE.list_results(session_id=session_id)` with
no `provider` filter, so this inconsistency does not affect them; it
only matters for the unused `GET /api/analysis/{provider}/...` route.

## Performance-relevant caching/singletons (CURRENT, verified)

| What | Where | Loaded | Verified behavior |
|---|---|---|---|
| ML models + vectorizers | `ml_classifier.py` | Once, at module import | Confirmed: real `.pkl` files load and `predict_proba` works in this environment |
| PhishTank feed | `phishtank_local.py::_load()` | Once, lazily on first `check_url()` call | Confirmed via timing test: ~0.7s first call, ~0.0003s every call after in the same process |
| Spamhaus DROP list | `spamhaus.py::_load_drop_networks()` | Once, lazily on first `check_ip()` call | Same lazy-singleton pattern, not separately re-timed but structurally identical |
| YARA compiled rules | `security/yara/scanner.py::_get_compiled_rules()` | Once, lazily on first `scan_bytes()` call, only if `yara-python` is importable | Currently never compiles in this environment (see LEGACY/UNTESTED notes) |
| IP geolocation results | `geolocation.py::_GEO_CACHE` | Per distinct IP, 1-hour TTL | Confirmed via direct test: second call for the same IP is a cache hit (0.0s) |

## What happens during a 100-email scan (CURRENT, traced from code)

1. `POST /api/scan?provider=google&count=100` triggers
   `collect_message_ids()` (offloaded to executor) which calls
   `list_messages()` in a loop, at most `page_size=100` per Gmail API
   call, until 100 ids are collected or pages run out.
2. `run_scan()` processes all 100 ids with a hard concurrency cap of
   5 (`asyncio.Semaphore(MAX_CONCURRENT_ANALYSES=5)` in
   `scan_service.py`) - so at most 5 `get_message()` + `analyze_email_safe()`
   pairs run at once, not 100 simultaneously.
3. Each of the 100 emails independently runs the full attachment ->
   header -> AI -> threat-intel -> geolocation -> risk pipeline
   described above.
4. ML models, PhishTank/Spamhaus feeds, and YARA rules are each
   loaded/compiled at most once across the entire batch (see caching
   table above) - not once per email.
5. Geolocation calls for a repeated origin IP across many of the 100
   messages hit the in-process cache after the first lookup.
6. If any single message's `get_message()` or `analyze_email_safe()`
   raises, that message is recorded as `status: "analysis_failed"`
   and the other 99 continue - `asyncio.gather()` over all 100
   `process_one()` coroutines does not cancel siblings on one
   exception, because each `process_one()` catches its own exceptions
   internally (see `scan_service.py`).
7. Progress is visible immediately via `GET /api/scan/{scan_id}`
   polling, since `STORE.update_scan()` is called after every single
   message completes, not just at the end.
