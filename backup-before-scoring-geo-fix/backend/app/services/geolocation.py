"""
IP geolocation service.

Provider: IPinfo
Endpoint:
    https://ipinfo.io/<IP>/json?token=<TOKEN>

Returns the same dictionary shape expected by geo_enrichment.py:
    {
        "ip": "...",
        "country": "...",
        "region": "...",
        "city": "...",
        "organization": "..."
    }
"""

from __future__ import annotations

import ipaddress
import os
import threading
import time
from typing import Any

import requests


# -------------------------------------------------------------------
# Configuration
# -------------------------------------------------------------------

IPINFO_TOKEN = os.getenv("IPINFO_TOKEN", "").strip()

CACHE_TTL_SECONDS = 3600
REQUEST_TIMEOUT_SECONDS = 10

_CACHE: dict[str, tuple[float, dict[str, Any]]] = {}
_CACHE_LOCK = threading.Lock()


# -------------------------------------------------------------------
# Helpers
# -------------------------------------------------------------------

def _not_applicable(ip: str, reason: str) -> dict[str, Any]:
    return {
        "ip": ip,
        "country": reason,
        "region": "N/A",
        "city": "N/A",
        "organization": "N/A",
    }


def _validate_public_ip(ip: str) -> None:
    """
    Raise ValueError when the supplied IP is invalid or not globally
    routable.
    """
    try:
        address = ipaddress.ip_address(ip)
    except ValueError as exc:
        raise ValueError(f"Invalid IP address: {ip}") from exc

    if not address.is_global:
        raise ValueError(f"IP is not globally routable: {ip}")


# -------------------------------------------------------------------
# Actual provider lookup
# -------------------------------------------------------------------

def _lookup_ip_geolocation(ip: str) -> dict[str, Any]:
    if not ip:
        return _not_applicable(ip, "N/A")

    try:
        _validate_public_ip(ip)
    except ValueError as exc:
        return _not_applicable(ip, str(exc))

    if not IPINFO_TOKEN:
        raise RuntimeError(
            "IPINFO_TOKEN is not configured. "
            "Add IPINFO_TOKEN to your .env file."
        )

    url = f"https://ipinfo.io/{ip}/json"

    try:
        response = requests.get(
            url,
            params={"token": IPINFO_TOKEN},
            timeout=REQUEST_TIMEOUT_SECONDS,
        )

        print(f"[GEO] {ip} -> HTTP {response.status_code}")

        response.raise_for_status()

        data = response.json()

    except requests.RequestException as exc:
        print(f"[GEO] Network/API error for {ip}: {exc}")
        raise RuntimeError(
            f"IPinfo lookup failed for {ip}: {exc}"
        ) from exc

    except ValueError as exc:
        print(f"[GEO] Invalid JSON returned for {ip}: {exc}")
        raise RuntimeError(
            f"IPinfo returned invalid JSON for {ip}"
        ) from exc

    # IPinfo can return an error body even when the request reached it.
    if "error" in data:
        error = data.get("error") or {}
        message = (
            error.get("message")
            if isinstance(error, dict)
            else str(error)
        )

        raise RuntimeError(
            f"IPinfo rejected lookup for {ip}: {message}"
        )

    # Legacy IPinfo response format:
    # city, region, country, org
    return {
        "ip": ip,
        "country": data.get("country", "Unknown"),
        "region": data.get("region", "Unknown"),
        "city": data.get("city", "Unknown"),
        "organization": data.get("org", "Unknown"),
    }


# -------------------------------------------------------------------
# Public function used by geo_enrichment.py
# -------------------------------------------------------------------

def get_ip_geolocation(ip: str) -> dict[str, Any]:
    """
    Public API used by geo_enrichment.py.

    Successful and failed lookups are cached for a short period so
    repeated scans of the same IP do not repeatedly hit the provider.
    """

    now = time.time()

    with _CACHE_LOCK:
        cached = _CACHE.get(ip)

        if cached:
            timestamp, result = cached

            if now - timestamp < CACHE_TTL_SECONDS:
                return result

            # Expired entry
            del _CACHE[ip]

    result = _lookup_ip_geolocation(ip)

    with _CACHE_LOCK:
        _CACHE[ip] = (now, result)

    return result


# -------------------------------------------------------------------
# Optional manual test
# -------------------------------------------------------------------

if __name__ == "__main__":
    test_ip = "8.8.8.8"

    try:
        print(get_ip_geolocation(test_ip))
    except Exception as exc:
        print(f"Test failed: {exc}")