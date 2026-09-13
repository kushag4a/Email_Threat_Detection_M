import ipaddress
import re
from urllib.parse import parse_qs, unquote, urlparse

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

# Well-known ESP (Email Service Provider) and marketing infrastructure
# hostnames whose tracking/redirect URLs routinely contain suspicious
# keywords like "verify", "confirm", "account", "update" but are NOT
# credential-harvesting or phishing.  We do NOT whitelist the *sender*
# — we exempt the URL *host* from keyword heuristic scoring only.
# All other checks (PhishTank listing, Spamhaus, IP heuristics, actual
# spoofing detection) still apply.
_KNOWN_ESP_HOSTS = {
    # Pinterest
    "post.pinterest.com", "trk.pinterest.com",
    # Google
    "notifications.google.com", "accounts.google.com",
    "mail-ads.google.com",
    # Microsoft
    "login.microsoftonline.com", "account.microsoft.com",
    # Marketing / email infrastructure
    "mandrillapp.com", "sendgrid.net", "mailchimp.com",
    "list-manage.com", "email.mailgun.com",
    "amazonses.com", "email.amazonaws.com",
    "constantcontact.com", "campaign-archive.com",
    "sailthru.com", "exacttarget.com",
    "mailerlite.com", "sendinblue.com", "brevo.com",
    "hubspot.com", "hubspotemail.net",
    "intercom-mail.com", "intercom.com",
    "postmarkapp.com", "sparkpostmail.com",
    # Social platforms
    "t.co", "lnkd.in", "facebook.com", "instagram.com",
    "twitter.com", "x.com", "reddit.com",
    "email.example.com",
}

# Partial hostname patterns for ESP infrastructure detection (suffix match,
# e.g. "em123.sendgrid.net" endswith ".sendgrid.net").
_ESP_HOST_PATTERNS = [
    ".mailchimp.com", ".sendgrid.net", ".mandrillapp.com",
    ".list-manage.com", ".hubspot.com", ".hubspotemail.net",
    ".sailthru.com", ".exacttarget.com", ".amazonaws.com",
    ".google.com", ".pinterest.com", ".microsoft.com",
    ".constantcontact.com", ".brevo.com", ".mailerlite.com",
    ".postmarkapp.com", ".sparkpostmail.com",
]

# NOTE (RC5, see DIAGNOSTIC_EVIDENCE.md / CHANGES.md): this set used to
# also contain bare-word "prefix" entries - "click.mail.", "links.",
# "unsubscribe.", "tracking.", "click." - with a comment claiming they
# were matched as partial/prefix patterns "below". They were not:
# `_is_known_esp_host` only ever checked exact equality against this
# set and suffix (`.endswith`) matching against `_ESP_HOST_PATTERNS`.
# Proven directly - `_is_known_esp_host("click.mail.example.com")`
# returned False even with those entries present, so they were dead
# code with no effect on scoring.
#
# They were deliberately NOT "fixed" by wiring them up as real
# `startswith` prefix matches. Section 13 of the stabilization spec is
# explicit: do not build a broad whitelist that suppresses malicious
# URLs on legitimate platforms. Generic single-word prefixes like
# "click." or "tracking." would match any attacker-registered hostname
# of the form "click.evil-domain.com" or "tracking.phish-site.net" and
# exempt it from keyword scoring - a real false-negative risk, not a
# false-positive fix. Removing the dead entries (this change) is
# strictly safer than making them functional. If per-ESP tracking
# subdomains need covering, add them as fully-qualified entries under
# specific known ESP domains (as already done for Mailchimp, SendGrid,
# etc. via `_ESP_HOST_PATTERNS`), never as bare generic prefixes.
def _is_known_esp_host(hostname: str) -> bool:
    """Check if a hostname belongs to known ESP infrastructure."""
    hostname = hostname.lower()
    if hostname in _KNOWN_ESP_HOSTS:
        return True
    for pattern in _ESP_HOST_PATTERNS:
        if hostname.endswith(pattern):
            return True
    return False


# ── Brand-lookalike / homoglyph detection ──────────────────────────
#
# Deliberately a small, curated list of frequently-impersonated
# identity/financial/productivity brands - not a general "known good"
# allowlist (that lives in _KNOWN_ESP_HOSTS above and is unrelated).
# For each brand we record the brand's OWN real domains so a hostname
# that genuinely belongs to the brand is never flagged as mimicking
# itself.
_PROTECTED_BRANDS: dict[str, set[str]] = {
    "google": {"google.com", "gmail.com", "googlemail.com"},
    "microsoft": {"microsoft.com", "microsoftonline.com", "live.com", "outlook.com", "office.com", "office365.com"},
    "apple": {"apple.com", "icloud.com"},
    "paypal": {"paypal.com"},
    "amazon": {"amazon.com", "amazon.in", "amazon.co.uk"},
    "facebook": {"facebook.com", "fb.com"},
    "instagram": {"instagram.com"},
    "netflix": {"netflix.com"},
    "linkedin": {"linkedin.com"},
    "dropbox": {"dropbox.com"},
    "docusign": {"docusign.com", "docusign.net"},
    "chase": {"chase.com"},
    "wellsfargo": {"wellsfargo.com"},
    "bankofamerica": {"bankofamerica.com"},
    "whatsapp": {"whatsapp.com"},
}

# Cheap, explicit leetspeak/homoglyph substitution table. This is not
# meant to be exhaustive - it only needs to catch the common ASCII
# digit-for-letter substitutions ("goog1e", "arnaz0n") that real
# lookalike-domain campaigns actually use.
_LEET_TABLE = str.maketrans({
    "0": "o", "1": "l", "3": "e", "4": "a", "5": "s", "7": "t",
    "$": "s", "!": "i", "@": "a",
})

_TOKEN_SPLIT_RE = re.compile(r"[.\-_]")


def _decode_idn_host(hostname: str) -> str:
    """Best-effort punycode -> Unicode decode, for homoglyph comparison.
    Falls back to the original hostname on any failure - this is a
    detection aid, never something that can raise or hide data."""
    if "xn--" not in hostname:
        return hostname
    try:
        return hostname.encode("ascii").decode("idna")
    except Exception:
        return hostname


def _levenshtein_at_most(a: str, b: str, limit: int) -> bool:
    """True if edit distance between a and b is <= limit. Short-circuits
    via length difference before doing the full DP pass."""
    if abs(len(a) - len(b)) > limit:
        return False
    m, n = len(a), len(b)
    prev = list(range(n + 1))
    for i in range(1, m + 1):
        curr = [i] + [0] * n
        for j in range(1, n + 1):
            cost = 0 if a[i - 1] == b[j - 1] else 1
            curr[j] = min(prev[j] + 1, curr[j - 1] + 1, prev[j - 1] + cost)
        prev = curr
    return prev[n] <= limit


def detect_brand_lookalike(hostname: str) -> dict | None:
    """
    Detect a hostname that is impersonating one of _PROTECTED_BRANDS via
    punycode/homoglyphs, leetspeak substitution, or a close-edit-distance
    misspelling, WITHOUT actually being that brand's real domain.

    Token-boundary matching: brand names are compared against whole
    dot/hyphen/underscore-delimited labels (e.g. "goog1e" in
    "goog1e-security.test"), not as a raw substring of the hostname -
    so a legitimate hostname that merely contains a brand name as part
    of an unrelated word ("mygoogleanalyticsclone.test") is not
    penalized as aggressively as an attacker who staged the brand name
    as its own token.

    Returns None when the hostname is legitimate or no brand is
    matched; otherwise a small dict describing the match.
    """
    if not hostname:
        return None
    host = hostname.lower().rstrip(".")

    # If the hostname genuinely belongs to the brand (exact or
    # subdomain), it is never a lookalike of itself.
    for real_domains in _PROTECTED_BRANDS.values():
        if any(host == d or host.endswith("." + d) for d in real_domains):
            return None

    decoded = _decode_idn_host(host)
    leet = host.translate(_LEET_TABLE)
    decoded_leet = decoded.translate(_LEET_TABLE)

    candidates = {host, decoded, leet, decoded_leet}

    for brand in _PROTECTED_BRANDS:
        for candidate in candidates:
            for label in _TOKEN_SPLIT_RE.split(candidate):
                if not label:
                    continue
                if label == brand:
                    return {"brand": brand, "matched_label": label}
                if len(label) >= 5 and _levenshtein_at_most(label, brand, 2):
                    return {"brand": brand, "matched_label": label}
    return None


# ── Nested redirect destination decoding ───────────────────────────
#
# Attackers frequently route a phishing link through a first-hop
# "redirector" URL (their own domain, or a compromised one) that
# carries the real destination in a query parameter, so the visibly
# displayed link never shows the real phishing host. This does not
# try to be a general-purpose URL shortener resolver - it only decodes
# an already-visible nested destination embedded in the URL itself, it
# never makes a network request.
_REDIRECT_PARAM_NAMES = {
    "url", "u", "r", "next", "redirect", "redirect_uri", "redirect_url",
    "return", "returnurl", "return_to", "continue", "dest", "destination",
    "target", "out", "forward", "goto", "redir", "link", "to",
}


def _extract_nested_destination(url: str) -> str | None:
    """Return the first http(s) URL found decoded out of a known
    redirect-style query parameter, or None if there isn't one."""
    try:
        parsed = urlparse(url)
    except ValueError:
        return None
    if not parsed.query:
        return None
    try:
        params = parse_qs(parsed.query)
    except ValueError:
        return None
    for name in _REDIRECT_PARAM_NAMES:
        values = params.get(name)
        if not values:
            continue
        candidate = unquote(values[0]).strip()
        if candidate.lower().startswith(("http://", "https://")):
            return candidate
    return None


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


def analyze_url(url: str, _nested_depth: int = 0) -> dict:
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
            # Explicit, higher-confidence flag for the risk engine: an
            # "@" before the real host is a classic obfuscation trick
            # (the part before "@" is discarded as URL userinfo and
            # never actually visited), distinct from a merely unusual
            # URL. Same trigger condition as userinfo_in_url above -
            # kept as a separate flag name so the risk engine can give
            # it its own explicit, documented contribution without
            # changing what userinfo_in_url means to existing callers.
            flags.append("uri_userinfo_obfuscation")
            score += 20

        lookalike = detect_brand_lookalike(hostname)
        if lookalike:
            flags.append("brand_lookalike_domain")
            score += 30

        # Only decode one hop of nested-destination redirect, and only
        # from the outermost call - a redirector's nested destination
        # is examined once, not recursively chained indefinitely.
        if _nested_depth == 0:
            nested = _extract_nested_destination(url)
            if nested:
                nested_result = analyze_url(nested, _nested_depth=1)

                # Legitimate ESP/marketing redirectors routinely wrap a
                # destination URL in parameters such as `url=` or `next=`.
                # The outer redirect pattern alone is therefore NOT enough
                # to call the message suspicious when the outer host is a
                # known ESP and the nested destination itself is benign.
                # Only retain the high-confidence redirect signal in that
                # case when the nested destination independently contains a
                # strong phishing indicator.
                nested_strong_flags = {
                    "brand_lookalike_domain",
                    "uri_userinfo_obfuscation",
                    "punycode_domain",
                    "ip_as_hostname",
                    "missing_hostname",
                    "suspicious_action_keywords",
                }
                nested_is_strong = bool(
                    nested_strong_flags.intersection(nested_result["flags"])
                )

                if (
                    not _is_known_esp_host(hostname)
                    or nested_is_strong
                ):
                    flags.append("redirector_with_nested_destination")
                    score += 20
                    if nested_result["flags"]:
                        flags.append("nested_destination_suspicious")
                        score += min(nested_result["local_score"] // 2, 20)

        if len(url) > 200:
            flags.append("very_long_url")
            score += 10

        if hostname.startswith("xn--") or ".xn--" in hostname:
            flags.append("punycode_domain")
            score += 20

        # Check for suspicious keywords BUT exempt known ESP hosts.
        # Tracking URLs from Pinterest, Google, Mailchimp etc. routinely
        # contain words like "verify", "account", "confirm" in their
        # path/query parameters.  Scoring those as suspicious would
        # create false positives on every marketing email.
        if not _is_known_esp_host(hostname):
            text = f"{hostname}{parsed.path}".lower()
            hits = [word for word in SUSPICIOUS_URL_WORDS if word in text]

            if hits:
                flags.append("suspicious_action_keywords")
                score += min(20, len(hits) * 5)

        if parsed.port and parsed.port not in {80, 443}:
            flags.append("unusual_port")
            score += 10

        # Detect IP-based URLs (common in phishing, rare in legitimate email)
        try:
            ipaddress.ip_address(hostname)
            flags.append("ip_as_hostname")
            score += 15
        except ValueError:
            pass

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
