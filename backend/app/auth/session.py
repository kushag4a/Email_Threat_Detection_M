"""
Server-side session handling.

DEMO LIMITATION (documented, not hidden): sessions and OAuth tokens
live in an in-memory process dict. This is fine for a hackathon demo
but is wiped on restart and does not scale past one process. For
production, replace SESSION_STORE with a persistent, encrypted store
(e.g. Redis or an encrypted SQLite table) keyed the same way.

The cookie itself only ever carries a signed, random session id -
never a token, never a client secret, and it is set HttpOnly +
SameSite=Lax so frontend JS can't read it and it isn't sent
cross-site.
"""

from __future__ import annotations

import os
import secrets

from itsdangerous import BadSignature, URLSafeSerializer

from fastapi import Request, Response

SESSION_COOKIE_NAME = "eta_session"

_SECRET_KEY = os.environ.get("SESSION_SECRET_KEY", "dev-only-insecure-secret-change-me")
_serializer = URLSafeSerializer(_SECRET_KEY, salt="eta-session")

# BUG FIX (see MERGE_LOG.md): this was hardcoded to secure=True, which
# some browsers silently refuse to store on a plain http://localhost
# origin (Secure cookies require an actual secure context in Firefox;
# Chrome is more lenient but not guaranteed). The visible symptom was
# "session doesn't stick, user has to log in twice / reload". Default
# to False for local development; set SESSION_COOKIE_SECURE=true once
# actually deployed behind HTTPS.
COOKIE_SECURE = os.environ.get("SESSION_COOKIE_SECURE", "false").lower() == "true"

# session_id -> {
#   "google": {"credentials": Credentials, "email": str},
#   "microsoft": {"access_token": str, "refresh_token": str, "email": str},
# }
SESSION_STORE: dict[str, dict] = {}


def _new_session_id() -> str:
    return secrets.token_urlsafe(32)


def get_or_create_session(request: Request, response: Response) -> str:
    raw_cookie = request.cookies.get(SESSION_COOKIE_NAME)

    if raw_cookie:
        try:
            session_id = _serializer.loads(raw_cookie)
            if session_id in SESSION_STORE:
                return session_id
        except BadSignature:
            pass

    session_id = _new_session_id()
    SESSION_STORE[session_id] = {}

    signed = _serializer.dumps(session_id)
    response.set_cookie(
        SESSION_COOKIE_NAME,
        signed,
        httponly=True,
        samesite="lax",
        secure=COOKIE_SECURE,
        max_age=60 * 60 * 8,
    )

    return session_id


def get_session_id(request: Request) -> str | None:
    raw_cookie = request.cookies.get(SESSION_COOKIE_NAME)
    if not raw_cookie:
        return None

    try:
        session_id = _serializer.loads(raw_cookie)
    except BadSignature:
        return None

    return session_id if session_id in SESSION_STORE else None


def get_session_data(request: Request) -> dict:
    session_id = get_session_id(request)
    if session_id is None:
        return {}
    return SESSION_STORE.get(session_id, {})


def clear_provider(request: Request, provider: str) -> None:
    session_id = get_session_id(request)
    if session_id and provider in SESSION_STORE.get(session_id, {}):
        del SESSION_STORE[session_id][provider]
