import ipaddress
import time

import requests

# Simple in-process TTL cache. A 100-message scan very often has many
# messages sharing the same origin infrastructure (same relay,
# newsletter platform, etc.) - without this, every single one of
# those messages would trigger its own ~5s network round trip.
_GEO_CACHE: dict[str, tuple[float, dict]] = {}
_GEO_CACHE_TTL_SECONDS = 60 * 60  # 1 hour


def get_ip_geolocation(ip: str) -> dict:
    """
    Best-effort infrastructure lookup for a public IP.

    Never invents a location. Private/invalid IPs and lookup failures
    are reported as such rather than silently defaulted. Results are
    cached in-process for _GEO_CACHE_TTL_SECONDS so a batch scan never
    pays the network round trip more than once per distinct IP.
    """

    if not ip:
        return {
            "ip": ip,
            "country": "N/A",
            "region": "N/A",
            "city": "N/A",
            "organization": "N/A",
        }

    cached = _GEO_CACHE.get(ip)
    if cached and (time.time() - cached[0]) < _GEO_CACHE_TTL_SECONDS:
        return cached[1]

    result = _lookup_ip_geolocation(ip)
    _GEO_CACHE[ip] = (time.time(), result)
    return result


def _lookup_ip_geolocation(ip: str) -> dict:
    if not ip:
        return {
            "ip": ip,
            "country": "N/A",
            "region": "N/A",
            "city": "N/A",
            "organization": "N/A",
        }

    try:
        if not ipaddress.ip_address(ip).is_global:
            return {
                "ip": ip,
                "country": "Not applicable (private/reserved IP)",
                "region": "N/A",
                "city": "N/A",
                "organization": "N/A",
            }
    except ValueError:
        return {
            "ip": ip,
            "country": "Invalid IP",
            "region": "N/A",
            "city": "N/A",
            "organization": "N/A",
        }

    url = f"https://ipapi.co/{ip}/json/"

    try:
        response = requests.get(url, timeout=5)
        data = response.json()

        if data.get("error"):
            raise ValueError(data.get("reason", "lookup error"))

        return {
            "ip": ip,
            "country": data.get("country_name", "Unknown"),
            "region": data.get("region", "Unknown"),
            "city": data.get("city", "Unknown"),
            "organization": data.get("org", "Unknown"),
        }

    except Exception:
        return {
            "ip": ip,
            "country": "Lookup failed",
            "region": "Lookup failed",
            "city": "Lookup failed",
            "organization": "Lookup failed",
        }
