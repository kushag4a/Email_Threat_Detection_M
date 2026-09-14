"""
Microsoft identity platform - Authorization Code flow via MSAL,
delegated user permissions only (Mail.Read, User.Read).

Requires MICROSOFT_CLIENT_ID / MICROSOFT_CLIENT_SECRET /
MICROSOFT_TENANT_ID / MICROSOFT_REDIRECT_URI (see .env.example).
Use tenant "common" to support both personal Microsoft accounts and
work/school accounts; use a specific tenant id to restrict to one
organization.
"""

from __future__ import annotations

import os
import secrets

import msal

from backend.app.providers.microsoft_provider import GRAPH_SCOPES

CLIENT_ID = os.environ.get("MICROSOFT_CLIENT_ID", "")
CLIENT_SECRET = os.environ.get("MICROSOFT_CLIENT_SECRET", "")
TENANT_ID = os.environ.get("MICROSOFT_TENANT_ID", "common")
REDIRECT_URI = os.environ.get("MICROSOFT_REDIRECT_URI", "")

_AUTHORITY = f"https://login.microsoftonline.com/{TENANT_ID}"

_PENDING_STATE: dict[str, str] = {}


def is_configured() -> bool:
    return bool(CLIENT_ID and CLIENT_SECRET and REDIRECT_URI)


def _build_app() -> msal.ConfidentialClientApplication:
    return msal.ConfidentialClientApplication(
        CLIENT_ID, authority=_AUTHORITY, client_credential=CLIENT_SECRET
    )


def build_authorization_url(session_id: str) -> str:
    app = _build_app()
    state = secrets.token_urlsafe(24)
    _PENDING_STATE[state] = session_id

    return app.get_authorization_request_url(
        GRAPH_SCOPES, redirect_uri=REDIRECT_URI, state=state
    )


def exchange_code_for_token(state: str, code: str) -> tuple[str, dict]:
    """Returns (session_id, token_result). Raises ValueError on bad state/exchange."""

    session_id = _PENDING_STATE.pop(state, None)
    if session_id is None:
        raise ValueError("Unknown or expired OAuth state (possible CSRF attempt).")

    app = _build_app()
    result = app.acquire_token_by_authorization_code(
        code, scopes=GRAPH_SCOPES, redirect_uri=REDIRECT_URI
    )

    if "access_token" not in result:
        raise ValueError(result.get("error_description", "Microsoft token exchange failed"))

    return session_id, result
