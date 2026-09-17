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
