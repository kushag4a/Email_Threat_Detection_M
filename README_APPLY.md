# ValorProtects Scoring + Geolocation Fix Patch

Apply these files to the current ValorProtects project, preserving the existing project directory structure.

## What this patch fixes

1. M2 `rule_based_threats` are always computed and now contribute to risk independently of AI phishing probability.
2. Local heuristic aggregation uses the strongest observed indicator rather than averaging strong evidence away.
3. High-confidence signals get explicit contributions:
   - `brand_lookalike_domain` +30
   - `uri_userinfo_obfuscation` +20
   - `redirector_with_nested_destination` +18
4. Adds the eight-message synthetic phishing regression suite.
5. Replaces `ipapi.co` with IPinfo in `geolocation.py` using `IPINFO_TOKEN`.
6. Reserved/private/test-net IPs are not sent to the external geolocation provider.
7. Emails with no origin IP are marked `geo_status=not_applicable` instead of staying permanently `pending`.
8. The detail panel refreshes the persisted analysis result before rendering, preventing a stale `m4`/geo snapshot from remaining visible after background enrichment.
9. Adds focused IPinfo/geolocation regression tests.

## Required environment variable

Set this in the local `.env` (never commit the real `.env`):

`IPINFO_TOKEN=...`

## Windows verification

From the real project:

```powershell
.\.venv\Scripts\python.exe -m compileall backend tests static -q
.\.venv\Scripts\python.exe -m pytest tests\test_phishing_eml_suite.py -q
.\.venv\Scripts\python.exe -m pytest -q
```

The final command must be run in the real Windows `.venv` because this sandbox lacks the Google API dependencies required by the Gmail tests.

## Important

Do not copy any runtime database (`data/valorprotects.sqlite3`), `.env`, credentials, tokens, or logs from a working machine into source control or the patch.
