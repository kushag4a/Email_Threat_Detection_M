from urllib.parse import urlsplit, urlunsplit


def normalize_url(url: str) -> str:
    """
    Normalize a URL for threat-intelligence comparison.

    - Lowercase scheme and hostname
    - Remove fragment
    - Remove trailing slash from the path
    """

    url = url.strip()

    try:
        parsed = urlsplit(url)

        scheme = parsed.scheme.lower()
        hostname = (parsed.hostname or "").lower()

        netloc = hostname

        if parsed.port:
            netloc = f"{hostname}:{parsed.port}"

        path = parsed.path.rstrip("/")

        return urlunsplit(
            (scheme, netloc, path, parsed.query, "")
        ).lower()

    except ValueError:
        return url.lower().rstrip("/")
