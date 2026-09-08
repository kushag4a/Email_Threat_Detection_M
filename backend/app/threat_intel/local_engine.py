import ipaddress
from urllib.parse import urlparse

SUSPICIOUS_URL_WORDS = {
    "login",
    "verify",
    "verification",
    "password",
    "reset",
    "secure",
    "account",
    "payment",
    "invoice",
    "update",
    "confirm",
}


def analyze_ip(ip: str) -> dict:
    flags = []

    try:
        address = ipaddress.ip_address(ip)
    except ValueError:
        return {
            "source": "local_heuristics",
            "indicator": ip,
            "indicator_type": "ip",
            "flags": ["invalid_ip"],
            "local_score": 15,
        }

    if address.is_private:
        flags.append("private_ip")
    if address.is_loopback:
        flags.append("loopback_ip")
    if address.is_link_local:
        flags.append("link_local_ip")
    if address.is_reserved:
        flags.append("reserved_ip")

    return {
        "source": "local_heuristics",
        "indicator": ip,
        "indicator_type": "ip",
        "flags": flags,
        "local_score": 0,
    }


def analyze_url(url: str) -> dict:
    flags = []
    score = 0

    try:
        parsed = urlparse(url)
        hostname = parsed.hostname or ""

        if not hostname:
            flags.append("missing_hostname")
            score += 25

        if "@" in url:
            flags.append("userinfo_in_url")
            score += 20

        if len(url) > 200:
            flags.append("very_long_url")
            score += 10

        if hostname.startswith("xn--") or ".xn--" in hostname:
            flags.append("punycode_domain")
            score += 20

        text = f"{hostname}{parsed.path}".lower()
        hits = [word for word in SUSPICIOUS_URL_WORDS if word in text]

        if hits:
            flags.append("suspicious_action_keywords")
            score += min(20, len(hits) * 5)

        if parsed.port and parsed.port not in {80, 443}:
            flags.append("unusual_port")
            score += 10

    except ValueError:
        flags.append("invalid_url")
        score += 25

    return {
        "source": "local_heuristics",
        "indicator": url,
        "indicator_type": "url",
        "flags": flags,
        "local_score": min(score, 100),
    }
