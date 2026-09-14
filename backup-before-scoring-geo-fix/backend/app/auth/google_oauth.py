"""
Google OAuth - Authorization Code flow, server-side, per-session.

DESIGN DECISION (see MERGE_LOG.md): the original gmail_reader.py used
google_auth_oauthlib.flow.InstalledAppFlow with run_local_server(),
which pops open a local browser tab and writes one shared token.json
to disk. That's the right shape for a single-developer script, but it
is fundamentally single-user - it cannot give User A and User B their
own isolated tokens inside the same running server, which the project
spec requires. This module replaces it with the web Authorization
Code flow (google_auth_oauthlib.flow.Flow) while reusing everything
else from the original Gmail integration (scope, GmailProvider
parsing logic, gmail_pipeline's model text) unchanged.

Requires real Google Cloud OAuth client credentials to actually run:
GOOGLE_CLIENT_ID / GOOGLE_CLIENT_SECRET / GOOGLE_REDIRECT_URI in the
environment (see .env.example). Without them, /auth/google/login
returns a clear configuration error rather than pretending to work.
"""

from __future__ import annotations

import os
import secrets
# Local development only: OAuth callback uses http://localhost.
# Production must use HTTPS.
os.environ.setdefault("OAUTHLIB_INSECURE_TRANSPORT", "1")

from google.oauth2.credentials import Credentials
from google_auth_oauthlib.flow import Flow

from backend.app.providers.gmail_provider import GMAIL_SCOPES

CLIENT_ID = os.environ.get("GOOGLE_CLIENT_ID", "")
CLIENT_SECRET = os.environ.get("GOOGLE_CLIENT_SECRET", "")
REDIRECT_URI = os.environ.get("GOOGLE_REDIRECT_URI", "")

# state -> session_id, so the callback can tie the OAuth response back
# to the browser session that started it (CSRF protection).
_PENDING_STATE: dict[str, str] = {}


def is_configured() -> bool:
    return bool(CLIENT_ID and CLIENT_SECRET and REDIRECT_URI)


def _build_flow() -> Flow:
    client_config = {
        "web": {
            "client_id": CLIENT_ID,
            "client_secret": CLIENT_SECRET,
            "auth_uri": "https://accounts.google.com/o/oauth2/auth",
            "token_uri": "https://oauth2.googleapis.com/token",
            "redirect_uris": [REDIRECT_URI],
        }
    }

    return Flow.from_client_config(
        client_config,
        scopes=GMAIL_SCOPES,
        redirect_uri=REDIRECT_URI,
        autogenerate_code_verifier=False,
    )


def build_authorization_url(session_id: str) -> str:
    flow = _build_flow()
    state = secrets.token_urlsafe(24)
    _PENDING_STATE[state] = session_id

    auth_url, _ = flow.authorization_url(
        access_type="offline",
        include_granted_scopes="true",
        prompt="consent",
        state=state,
    )
    return auth_url


def exchange_code_for_credentials(state: str, authorization_response_url: str) -> tuple[str, Credentials]:
    """Returns (session_id, credentials). Raises ValueError on invalid/unknown state."""

    session_id = _PENDING_STATE.pop(state, None)
    if session_id is None:
        raise ValueError("Unknown or expired OAuth state (possible CSRF attempt).")

    flow = _build_flow()
    flow.fetch_token(authorization_response=authorization_response_url)

    return session_id, flow.credentials
