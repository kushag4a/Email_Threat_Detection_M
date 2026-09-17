import re


def _as_list(value):
    # Convert a value into a list.
    if value is None:
        return []

    if isinstance(value, list):
        return value

    return [value]


def _extract_auth_result(
    authentication_results: list[str],
    mechanism: str
) -> str:
    """
    Extract SPF, DKIM or DMARC result from Authentication-Results.

    Example:
        spf=pass
        dkim=pass
        dmarc=fail
    """

    pattern = re.compile(
        rf"\b{mechanism}\s*=\s*"
        r"(pass|fail|softfail|neutral|none|temperror|permerror)\b",
        re.IGNORECASE
    )

    for result in authentication_results:
        match = pattern.search(result)

        if match:
            return match.group(1).lower()

    return "unknown"


def _extract_ip_from_received(
    received_header: str
) -> str | None:
#    Extract an IPv4 address from a Received header.

    ipv4_pattern = re.compile(
        r"\b(?:\d{1,3}\.){3}\d{1,3}\b"
    )

    match = ipv4_pattern.search(received_header)

    if match:
        return match.group(0)

    return None


def _extract_origin_ip(
    received_headers: list[str]
) -> str | None:
    """
    Extract an IP candidate from the Received chain.

    Received headers are normally newest-first, so we inspect
    them in reverse order to look at older hops first.

    This is only a probable infrastructure/source IP candidate,
    not proof of the attacker's physical location.
    """

    for header in reversed(received_headers):

        ip = _extract_ip_from_received(header)

        if ip:
            return ip

    return None


def analyze_email(email_data: dict) -> dict:
    """
    M1 - Email Header & Authentication Analysis

    Expected input:

    {
        "sender": "...",
        "reply_to": "...",
        "return_path": "...",
        "received_headers": [...],
        "received_spf": [...],
        "authentication_results": [...],
        "body": "...",
        "urls": [...],
        "attachments": [...]
    }
    """


    # Get normalized M5 → M1 data
    authentication_results = _as_list(
        email_data.get("authentication_results")
    )

    received_headers = _as_list(
        email_data.get("received_headers")
    )

    received_spf = _as_list(
        email_data.get("received_spf")
    )


    # SPF
    spf = _extract_auth_result(
        authentication_results,
        "spf"
    )

    # Fallback to Received-SPF
    if spf == "unknown":
        spf = _extract_auth_result(
            received_spf,
            "spf"
        )


    # DKIM
    dkim = _extract_auth_result(
        authentication_results,
        "dkim"
    )


    # DMARC
    dmarc = _extract_auth_result(
        authentication_results,
        "dmarc"
    )

    # Origin IP candidate
    origin_ip = _extract_origin_ip(
        received_headers
    )

    # Final M1 result
    return {
        "spf": spf,
        "dkim": dkim,
        "dmarc": dmarc,
        "origin_ip": origin_ip
    }