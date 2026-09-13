"""Focused tests for the IPinfo-backed geolocation provider."""
from __future__ import annotations

from unittest.mock import MagicMock, patch

import backend.app.services.geolocation as geolocation


def test_non_global_ip_is_not_sent_to_ipinfo(monkeypatch):
    geolocation._CACHE.clear()
    calls = []

    def fake_get(*args, **kwargs):
        calls.append((args, kwargs))
        raise AssertionError("IPinfo must not be called for a reserved IP")

    monkeypatch.setattr(geolocation.requests, "get", fake_get)
    result = geolocation.get_ip_geolocation("198.51.100.44")

    assert "not globally routable" in result["country"]
    assert calls == []


def test_public_ip_uses_ipinfo(monkeypatch):
    geolocation._CACHE.clear()
    monkeypatch.setattr(geolocation, "IPINFO_TOKEN", "test-token")

    response = MagicMock()
    response.status_code = 200
    response.raise_for_status.return_value = None
    response.json.return_value = {
        "ip": "8.8.8.8",
        "city": "Mountain View",
        "region": "California",
        "country": "US",
        "org": "AS15169 Google LLC",
    }

    with patch.object(geolocation.requests, "get", return_value=response) as get:
        result = geolocation.get_ip_geolocation("8.8.8.8")

    assert result == {
        "ip": "8.8.8.8",
        "country": "US",
        "region": "California",
        "city": "Mountain View",
        "organization": "AS15169 Google LLC",
    }
    get.assert_called_once_with(
        "https://ipinfo.io/8.8.8.8/json",
        params={"token": "test-token"},
        timeout=geolocation.REQUEST_TIMEOUT_SECONDS,
    )


def test_public_ip_result_is_cached(monkeypatch):
    geolocation._CACHE.clear()
    monkeypatch.setattr(geolocation, "IPINFO_TOKEN", "test-token")

    response = MagicMock()
    response.raise_for_status.return_value = None
    response.json.return_value = {
        "country": "US",
        "region": "California",
        "city": "Mountain View",
        "org": "Google LLC",
    }

    with patch.object(geolocation.requests, "get", return_value=response) as get:
        first = geolocation.get_ip_geolocation("8.8.8.8")
        second = geolocation.get_ip_geolocation("8.8.8.8")

    assert first == second
    get.assert_called_once()
