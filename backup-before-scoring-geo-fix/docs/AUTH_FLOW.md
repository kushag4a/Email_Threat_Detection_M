# AUTH_FLOW.md

Traced from `backend/app/main.py`, `backend/app/auth/session.py`,
`backend/app/auth/google_oauth.py`, `backend/app/auth/microsoft_oauth.py`.
No real credentials or tokens are shown anywhere below - only
placeholders and the actual variable/field names used in code.

## Google OAuth - CURRENT implementation, UNTESTED against a real Google Cloud client

### Routes (all in `backend/app/main.py`)
- `GET /auth/google/login`
- `GET /auth/google/callback`
- `GET /auth/google/status`
- `POST /auth/google/logout`

### Step-by-step (from source)

```
Browser: GET /auth/google/login
  |
  v
main.py::google_login(request)
  - if not google_oauth.is_configured(): raise HTTP 503
    (is_configured() checks GOOGLE_CLIENT_ID, GOOGLE_CLIENT_SECRET,
     GOOGLE_REDIRECT_URI are all non-empty)
  - redirect = RedirectResponse("about:blank")   [placeholder URL]
  - session_id = get_or_create_session(request, redirect)
      -> if no valid "eta_session" cookie is present/valid, generates
         secrets.token_urlsafe(32), stores SESSION_STORE[session_id] = {},
         and calls redirect.set_cookie("eta_session", signed_value,
         httponly=True, samesite="lax", secure=COOKIE_SECURE, max_age=28800)
      -> the cookie is set directly on the `redirect` response object
         that will actually be returned (a documented fix for an
         earlier version that set the cookie on a throwaway Response
         and then tried to copy headers across)
  - auth_url = google_oauth.build_authorization_url(session_id)
      -> builds a google_auth_oauthlib.flow.Flow from an inline
         client_config dict (client_id, client_secret, Google's fixed
         auth_uri/token_uri, redirect_uri - all from env vars)
      -> generates a random `state = secrets.token_urlsafe(24)`
      -> _PENDING_STATE[state] = session_id   (in-process dict, CSRF binding)
      -> flow.authorization_url(access_type="offline",
                                 include_granted_scopes="true",
                                 prompt="consent", state=state)
  - redirect.headers["location"] = auth_url
  - return redirect   (302 to Google's consent screen, with the
                       eta_session cookie now set in the response)
  |
  v
Browser -> Google's OAuth consent screen -> user approves
  |
  v
Google redirects browser to: GOOGLE_REDIRECT_URI?code=<AUTH_CODE>&state=<STATE>
  |
  v
Browser: GET /auth/google/callback?code=...&state=...
  |
  v
main.py::google_callback(request)
  - state = request.query_params.get("state", "")
  - session_id, credentials = google_oauth.exchange_code_for_credentials(
        state, str(request.url))
      -> session_id = _PENDING_STATE.pop(state, None)
         if None: raise ValueError -> HTTP 400 ("Unknown or expired
         OAuth state (possible CSRF attempt).")
      -> flow.fetch_token(authorization_response=full_callback_url)
         (this is the actual code-for-token exchange with Google;
          google-auth-oauthlib handles the token endpoint call)
      -> returns (session_id, flow.credentials)
         [credentials is a google.oauth2.credentials.Credentials
          object - holds access_token, refresh_token, token_uri,
          client_id, client_secret, scopes internally]
  - provider = GmailProvider(credentials)
  - email_address = provider.get_current_user()   [1 Gmail API call: getProfile]
  - SESSION_STORE.setdefault(session_id, {})["google"] =
        {"credentials": credentials, "email": email_address}
  - return RedirectResponse("/")
  |
  v
Browser -> GET / (full page load)
  |
  v
static/app.js runs on load -> refreshConnectionStatus()
  -> GET /auth/google/status  (see below) -> renders "Gmail - <email>"
     and calls loadEmailPage() automatically - NO second click needed.
```

### Status / Logout

```
GET /auth/google/status
  -> session = get_session_data(request)   [looks up SESSION_STORE by cookie]
  -> if session.get("google"): {"connected": true, "email": "..."}
  -> else: {"connected": false}

POST /auth/google/logout
  -> clear_provider(request, "google")
       -> del SESSION_STORE[session_id]["google"]  (if present)
  -> {"connected": false}
```

### CSRF / state protection
`_PENDING_STATE` (module-level dict in `google_oauth.py`) maps a
random `state` string to the `session_id` that initiated the flow.
The callback pops and validates this mapping - an attacker-supplied
or replayed `state` that isn't in the dict raises `ValueError`,
which `main.py` converts to HTTP 400. There is no separate PKCE code
verifier in this implementation - the flow uses `client_secret`-based
confidential-client authentication (a real client secret is
required and read from `GOOGLE_CLIENT_SECRET`).

### Token storage
`credentials` (the whole `google.oauth2.credentials.Credentials`
object, including refresh token) is stored **only** in the in-process
`SESSION_STORE` dict, keyed by `session_id`. It is never sent to the
browser, never put in a cookie, never logged.

### Not implemented / not observed in this codebase
- No explicit token-refresh code path is written in this project;
  `googleapiclient.discovery.build(credentials=credentials)` combined
  with `google-auth`'s transport layer handles refresh automatically
  when the underlying library detects an expired token, PROVIDED the
  `Credentials` object has a `refresh_token` - this is library
  behavior, not custom code in this repo.
- No explicit "keep me signed in" duration option exists in the UI or
  backend.

## Microsoft OAuth - CURRENT implementation, UNTESTED against a real Azure tenant

### Routes (all in `backend/app/main.py`)
- `GET /auth/microsoft/login`
- `GET /auth/microsoft/callback`
- `GET /auth/microsoft/status`
- `POST /auth/microsoft/logout`

### Step-by-step (from source)

```
Browser: GET /auth/microsoft/login
  -> microsoft_login(request)
     - is_configured() checks MICROSOFT_CLIENT_ID, MICROSOFT_CLIENT_SECRET,
       MICROSOFT_REDIRECT_URI (MICROSOFT_TENANT_ID defaults to "common")
     - same cookie-on-actual-response pattern as Google
     - auth_url = microsoft_oauth.build_authorization_url(session_id)
         -> msal.ConfidentialClientApplication(client_id, authority=
            f"https://login.microsoftonline.com/{tenant_id}",
            client_credential=client_secret)
         -> state = secrets.token_urlsafe(24); _PENDING_STATE[state] = session_id
         -> app.get_authorization_request_url(GRAPH_SCOPES,
            redirect_uri=..., state=state)
     - redirect to that URL

Browser -> Microsoft consent screen -> user approves
  -> redirect to MICROSOFT_REDIRECT_URI?code=...&state=...

GET /auth/microsoft/callback?code=...&state=...
  -> microsoft_callback(request)
     - session_id, token_result = microsoft_oauth.exchange_code_for_token(state, code)
         -> pop/validate _PENDING_STATE[state] (same CSRF pattern as Google)
         -> app.acquire_token_by_authorization_code(code, scopes=GRAPH_SCOPES,
            redirect_uri=...)
         -> if "access_token" not in result: raise ValueError -> HTTP 400
     - provider = MicrosoftGraphProvider(token_result["access_token"])
     - email_address = provider.get_current_user()   [1 Graph call: GET /me]
     - SESSION_STORE[session_id]["microsoft"] = {"access_token":...,
       "refresh_token": token_result.get("refresh_token"), "email":...}
     - redirect to "/"

GET /auth/microsoft/status  -> same pattern as Google, checks session["microsoft"]
POST /auth/microsoft/logout -> clear_provider(request, "microsoft")
```

### Scopes
`GRAPH_SCOPES = ["Mail.Read", "User.Read", "offline_access"]` -
delegated permissions only, defined in `microsoft_provider.py` and
imported by `microsoft_oauth.py`. No application/tenant-wide
permissions are requested anywhere in this codebase.

### Status: UNTESTED
No Microsoft Graph app registration or credentials were available in
the environment this project was built in. The code has been
reviewed and follows the documented MSAL confidential-client pattern,
but the actual browser-redirect-to-Microsoft round trip, the token
exchange, and a real `GET /me` call have never executed.

## Session / cookie mechanics (CURRENT, shared by both providers)

File: `backend/app/auth/session.py`.

- Cookie name: `eta_session` (constant `SESSION_COOKIE_NAME`).
- Cookie value: `itsdangerous.URLSafeSerializer(SECRET_KEY, salt="eta-session").dumps(session_id)`
  - i.e. a signed token wrapping a random session id, NOT the id
    itself in plaintext, NOT any credential.
- `SECRET_KEY` is read from `SESSION_SECRET_KEY` env var, defaulting
  to the literal string `"dev-only-insecure-secret-change-me"` if
  unset - a real deployment MUST set this.
- Cookie flags: `httponly=True` (JS on the page cannot read it),
  `samesite="lax"` (sent on top-level navigations like the OAuth
  redirect-back, not on cross-site subresource requests),
  `secure=COOKIE_SECURE` where `COOKIE_SECURE` reads
  `SESSION_COOKIE_SECURE` env var, default `False`.
- `max_age=28800` seconds (8 hours).
- Server-side: `SESSION_STORE: dict[str, dict]` - a plain
  module-level Python dict, `session_id -> {"google": {...}, "microsoft": {...}}`.
  Nothing is written to disk; restarting the process clears every
  session and every stored OAuth credential.

### Login/session state machine (as actually implemented)

```
[No cookie / invalid cookie]
        |
        | GET /auth/{provider}/login
        v
[New session_id created, cookie set, redirected to provider consent]
        |
        | user approves on provider's site
        v
[GET /auth/{provider}/callback - state validated, code exchanged]
        |
        v
[SESSION_STORE[session_id][provider] populated] --(redirect to "/")--> [Connected]
        |
        | frontend GET /auth/{provider}/status confirms connected:true
        v
[Connected] --loadEmailPage()--> [Mailbox listing works]
        |
        | POST /api/scan
        v
[Scanning] --GET /api/scan/{id} polling--> [Results available]
        |
        | POST /auth/{provider}/logout
        v
[SESSION_STORE[session_id][provider] deleted] -> [No cookie invalidation -
  the session_id itself still exists in SESSION_STORE as an empty/
  partial dict; only that one provider's credentials are removed]
```

**Note on "logout" semantics (verified from code):** `clear_provider()`
only deletes the one provider's key from
`SESSION_STORE[session_id]`; it does NOT delete the session cookie
itself or the `session_id` entry as a whole. If a user were connected
to both Google and Microsoft simultaneously (the UI does not
currently expose a way to do this - `state.provider` in `app.js` only
tracks one active provider at a time, whichever status check returns
`connected: true` first, Google checked before Microsoft), logging
out of one would not affect the other.

**Failure states actually implemented in code:**
- `AUTH_FAILED` -> HTTP 503 from `google_login`/`microsoft_login` if
  `is_configured()` is false (missing env vars); HTTP 400 from either
  callback if the OAuth exchange itself fails or state is invalid.
- `SESSION_EXPIRED` -> not a distinct state; an invalid/missing
  cookie simply results in `get_session_id()` returning `None`,
  which every protected route treats as "not logged in" (HTTP 401).
- `PROVIDER_ERROR` -> any exception from a Gmail/Graph API call
  during listing/scanning bubbles up as either a route-level
  exception (for `list_emails`/`start_scan`'s own calls) or, during a
  scan, is caught per-message inside `scan_service.py` and recorded
  as `status: "analysis_failed"` for that one message without
  affecting the rest of the batch.
- `SCAN_FAILED` -> not a whole-scan failure state; failures are
  always per-message (`analysis_failed`), never abort the entire scan.

## What is NOT shown in this document
No client secrets, access tokens, refresh tokens, session ids, or
signed cookie values appear above - only the field/variable names
that hold them and the environment variable names they're read from.
