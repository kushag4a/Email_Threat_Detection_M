"""
IP geolocation service.

Provider: IPinfo
Endpoint:
    https://ipinfo.io/<IP>/json?token=<TOKEN>

Returns the normalized dictionary consumed by geo_enrichment.py:
    {
        "ip": "...",
        "country": "...",
        "region": "...",
        "city": "...",
        "organization": "..."
    }

The service performs only infrastructure geolocation. It never treats
geography as proof of maliciousness and never changes the primary risk
verdict.
"""

from __future__ import annotations

import ipaddress
import os
import threading
import time
from typing import Any

import requests

IPINFO_TOKEN = os.getenv("IPINFO_TOKEN", "").strip()

CACHE_TTL_SECONDS = 3600
REQUEST_TIMEOUT_SECONDS = 10

_CACHE: dict[str, tuple[float, dict[str, Any]]] = {}
_CACHE_LOCK = threading.Lock()


def is_globally_routable_ip(ip: str) -> bool:
    """Return True only for syntactically valid globally routable IPs."""
    try:
        return ipaddress.ip_address(ip).is_global
    except ValueError:
        return False


def _not_applicable(ip: str, reason: str) -> dict[str, Any]:
    return {
        "ip": ip,
        "country": reason,
        "region": "N/A",
        "city": "N/A",
        "organization": "N/A",
    }


def _validate_public_ip(ip: str) -> None:
    try:
        address = ipaddress.ip_address(ip)
    except ValueError as exc:
        raise ValueError(f"Invalid IP address: {ip}") from exc

    if not address.is_global:
        raise ValueError(f"IP is not globally routable: {ip}")


def _lookup_ip_geolocation(ip: str) -> dict[str, Any]:
    if not ip:
        return _not_applicable(ip, "No origin IP available")

    try:
        _validate_public_ip(ip)
    except ValueError as exc:
        return _not_applicable(ip, str(exc))

    if not IPINFO_TOKEN:
        raise RuntimeError(
            "IPINFO_TOKEN is not configured. Add IPINFO_TOKEN to the .env file."
        )

    url = f"https://ipinfo.io/{ip}/json"

    try:
        response = requests.get(
            url,
            params={"token": IPINFO_TOKEN},
            timeout=REQUEST_TIMEOUT_SECONDS,
        )
        response.raise_for_status()
        data = response.json()
    except requests.RequestException as exc:
        raise RuntimeError(f"IPinfo lookup failed for {ip}: {exc}") from exc
    except ValueError as exc:
        raise RuntimeError(f"IPinfo returned invalid JSON for {ip}") from exc

    if "error" in data:
        error = data.get("error") or {}
        message = error.get("message") if isinstance(error, dict) else str(error)
        raise RuntimeError(f"IPinfo rejected lookup for {ip}: {message}")

    return {
        "ip": ip,
        "country": data.get("country", "Unknown"),
        "region": data.get("region", "Unknown"),
        "city": data.get("city", "Unknown"),
        "organization": data.get("org", "Unknown"),
    }


def get_ip_geolocation(ip: str) -> dict[str, Any]:
    """
    Lookup a public IP through IPinfo with a one-hour in-process cache.

    Non-global/invalid IPs never reach the provider and are returned as
    'not applicable' data so callers can preserve an accurate geo_status.
    """
    now = time.time()

    with _CACHE_LOCK:
        cached = _CACHE.get(ip)
        if cached and now - cached[0] < CACHE_TTL_SECONDS:
            return cached[1]
        if cached:
            del _CACHE[ip]

    result = _lookup_ip_geolocation(ip)

    with _CACHE_LOCK:
        _CACHE[ip] = (now, result)

    return result
