"""
Route-level regression tests: static asset routing (logo/favicon 404s),
/auth/status, the canonical-origin login redirect, and the two new
dashboard endpoints.

The app is driven through a tiny hand-rolled ASGI call helper rather than
fastapi.testclient, so no extra dependency (httpx) is required - same
spirit as the other tests, which avoid TestClient.
"""
from __future__ import annotations

import asyncio
import json
import uuid
from pathlib import Path

import pytest

from backend.app import main as app_main
from backend.app.auth import google_oauth, session as session_mod
from backend.app.services.store import STORE

STATIC = Path(app_main.STATIC_DIR)


def _call(path: str, *, cookie: str | None = None, query: str = "", method: str = "GET",
          host: str = "localhost:8000"):
    """Return (status, headers_dict, body_bytes) from the real ASGI app."""
    headers = [(b"host", host.encode())]
    if cookie:
        headers.append((b"cookie", f"{session_mod.SESSION_COOKIE_NAME}={cookie}".encode()))
    scope = {
        "type": "http", "asgi": {"version": "3.0"}, "http_version": "1.1", "method": method,
        "scheme": "http", "path": path, "raw_path": path.encode(), "query_string": query.encode(),
        "headers": headers, "server": ("localhost", 8000), "client": ("127.0.0.1", 50000),
        "root_path": "",
    }
    sent: list[dict] = []

    async def receive():
        return {"type": "http.request", "body": b"", "more_body": False}

    async def send(message):
        sent.append(message)

    asyncio.run(app_main.app(scope, receive, send))
    start = next(m for m in sent if m["type"] == "http.response.start")
    body = b"".join(m.get("body", b"") for m in sent if m["type"] == "http.response.body")
    hdrs = {k.decode().lower(): v.decode() for k, v in start["headers"]}
    return start["status"], hdrs, body


def _new_session(**providers) -> tuple[str, str]:
    """Create a real signed session cookie backed by SESSION_STORE."""
    sid = session_mod._new_session_id()
    session_mod.SESSION_STORE[sid] = dict(providers)
    return sid, session_mod._serializer.dumps(sid)


class TestStaticAssetRouting:
    @pytest.mark.parametrize("name", ["valor-logo-full.png", "valor-logo-mini.png"])
    def test_logo_urls_used_by_the_page_resolve(self, name):
        # The exact URLs that used to 404.
        status, headers, body = _call(f"/assets/{name}")
        assert status == 200
        assert headers["content-type"].startswith("image/png")
        assert body[:8] == b"\x89PNG\r\n\x1a\n"

    def test_logo_files_still_exist_where_they_were(self):
        assert (STATIC / "assets" / "valor-logo-full.png").is_file()
        assert (STATIC / "assets" / "valor-logo-mini.png").is_file()

    @pytest.mark.parametrize("name", ["styles.css", "app.js", "icons.js", "vp-links.js", "default-avatar.svg"])
    def test_existing_and_new_assets_still_served(self, name):
        status, _, body = _call(f"/assets/{name}")
        assert status == 200 and body

    def test_missing_asset_is_still_404(self):
        assert _call("/assets/does-not-exist.png")[0] == 404

    def test_favicon_is_served(self):
        status, headers, body = _call("/favicon.ico")
        assert status == 200 and headers["content-type"].startswith("image/png") and body

    def test_index_served_and_references_resolvable_assets(self):
        status, _, body = _call("/")
        assert status == 200
        html = body.decode()
        for ref in ("/assets/valor-logo-full.png", "/assets/valor-logo-mini.png", "/assets/vp-links.js"):
            assert ref in html
            assert _call(ref)[0] == 200


class TestAuthStatus:
    def test_anonymous(self):
        status, _, body = _call("/auth/status")
        data = json.loads(body)
        assert status == 200
        assert data["connected"] is False and data["active_provider"] is None
        assert data["google"]["connected"] is False and data["microsoft"]["connected"] is False
        assert isinstance(data["google"]["configured"], bool)

    def test_google_session_is_recognised_in_one_request(self):
        _, cookie = _new_session(google={"credentials": object(), "email": "me@gmail.com"})
        data = json.loads(_call("/auth/status", cookie=cookie)[2])
        assert data["connected"] is True and data["active_provider"] == "google"
        assert data["google"]["email"] == "me@gmail.com"

    def test_microsoft_session(self):
        _, cookie = _new_session(microsoft={"access_token": "t", "email": "me@outlook.com"})
        data = json.loads(_call("/auth/status", cookie=cookie)[2])
        assert data["active_provider"] == "microsoft" and data["microsoft"]["email"] == "me@outlook.com"

    def test_status_never_leaks_credentials(self):
        _, cookie = _new_session(google={"credentials": "SECRET-TOKEN", "email": "me@gmail.com"})
        assert b"SECRET-TOKEN" not in _call("/auth/status", cookie=cookie)[2]

    def test_legacy_per_provider_status_unchanged(self):
        _, cookie = _new_session(google={"credentials": object(), "email": "me@gmail.com"})
        assert json.loads(_call("/auth/google/status", cookie=cookie)[2]) == {"connected": True, "email": "me@gmail.com"}
        assert json.loads(_call("/auth/microsoft/status", cookie=cookie)[2]) == {"connected": False}


class TestCanonicalLoginOrigin:
    """Cookie host must equal callback host, or login 'works' but looks signed out."""

    def _request(self, host: str, query: str = ""):
        from starlette.requests import Request
        scope = {"type": "http", "method": "GET", "scheme": "http", "path": "/auth/google/login",
                 "query_string": query.encode(), "headers": [(b"host", host.encode())],
                 "server": ("x", 8000), "client": ("127.0.0.1", 1)}
        return Request(scope)

    def test_same_origin_proceeds(self):
        r = self._request("localhost:8000")
        assert app_main._canonical_login_redirect(r, "http://localhost:8000/auth/google/callback", "/auth/google/login") is None

    def test_different_host_bounces_to_registered_origin(self):
        r = self._request("127.0.0.1:8000")
        resp = app_main._canonical_login_redirect(r, "http://localhost:8000/auth/google/callback", "/auth/google/login")
        assert resp is not None and resp.status_code in (302, 307)
        assert resp.headers["location"] == "http://localhost:8000/auth/google/login?_canon=1"

    def test_marker_prevents_redirect_loops(self):
        r = self._request("127.0.0.1:8000", "_canon=1")
        assert app_main._canonical_login_redirect(r, "http://localhost:8000/x", "/auth/google/login") is None

    def test_unparseable_redirect_uri_is_ignored(self):
        r = self._request("127.0.0.1:8000")
        assert app_main._canonical_login_redirect(r, "", "/auth/google/login") is None

    def test_login_route_bounces_when_configured(self, monkeypatch):
        monkeypatch.setattr(google_oauth, "CLIENT_ID", "id")
        monkeypatch.setattr(google_oauth, "CLIENT_SECRET", "secret")
        monkeypatch.setattr(google_oauth, "REDIRECT_URI", "http://localhost:8000/auth/google/callback")
        status, headers, _ = _call("/auth/google/login", host="127.0.0.1:8000")
        assert status in (302, 307)
        assert headers["location"] == "http://localhost:8000/auth/google/login?_canon=1"


class TestDashboardEndpoints:
    def _seed(self):
        sid, cookie = _new_session()
        for i, (level, types) in enumerate([("LOW", []), ("MEDIUM", ["Authentication Spoofing"]),
                                             ("HIGH", ["Credential Phishing"])]):
            mid = f"dash-{uuid.uuid4().hex[:6]}-{i}"
            STORE.save_result(session_id=sid, provider="google", account_id="me@gmail.com", message_id=mid, result={
                "message_id": mid, "provider": "google", "account_id": "me@gmail.com", "status": "analyzed",
                "analyzed_at": "2026-10-05T09:00:00Z",
                "email": {"sender": "a@x.com", "subject": "s", "date": "Sun, 04 Oct 2026 17:13:31 +0000"},
                "risk": {"level": level, "score": 50}, "threat_types": types,
                "m3": {"phishtank": [], "spamhaus": [], "local_heuristics": [
                    {"indicator": "http://a.example/", "indicator_type": "url", "flags": ["very_long_url"], "local_score": 10}]},
            })
        return cookie

    def test_require_a_session(self):
        assert _call("/api/dashboard/risk-trend")[0] == 401
        assert _call("/api/dashboard/threat-vectors")[0] == 401

    def test_risk_trend_uses_all_classified_mail(self):
        cookie = self._seed()
        for period in ("day", "week", "month"):
            status, _, body = _call("/api/dashboard/risk-trend", cookie=cookie, query=f"period={period}")
            data = json.loads(body)
            assert status == 200 and data["period_type"] == period
            assert data["analyzed_total"] == 3  # includes the LOW (safe) message the geo trend never saw
            assert set(data["buckets"][0]) >= {"safe", "medium", "high", "critical", "total", "label"}

    def test_risk_trend_rejects_bad_period(self):
        cookie = self._seed()
        assert _call("/api/dashboard/risk-trend", cookie=cookie, query="period=year")[0] == 422

    def test_threat_vectors_categories_and_sources(self):
        cookie = self._seed()
        data = json.loads(_call("/api/dashboard/threat-vectors", cookie=cookie)[2])
        assert {v["name"] for v in data["vectors"]} == {"Authentication Spoofing", "Credential Phishing"}
        assert [s["key"] for s in data["sources"]] == ["phishtank", "spamhaus", "local_heuristics"]
        assert all("PhishTank" not in v["name"] for v in data["vectors"])

    def test_geo_trend_endpoint_still_exists_unchanged(self):
        cookie = self._seed()
        assert _call("/api/threat-geo/trend", cookie=cookie, query="period=day")[0] == 200
