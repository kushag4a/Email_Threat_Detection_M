from backend.app.threat_intel.phishtank_local import check_url as check_phishtank
from backend.app.threat_intel.spamhaus import check_ip as check_spamhaus
from backend.app.threat_intel import local_engine


def analyze_threat_intelligence(ips: list[str], urls: list[str]) -> dict:
    """
    Core M3: local heuristics + local threat-intelligence feeds.

    No end-user API keys are required. Optional organization-managed
    external enrichment (VirusTotal, AbuseIPDB, etc.) can be layered
    on later without changing this contract; it is intentionally not
    included in the hackathon build.
    """

    phishtank_results = [check_phishtank(url) for url in urls]
    spamhaus_results = [check_spamhaus(ip) for ip in ips]

    local_heuristics = [local_engine.analyze_url(url) for url in urls]
    local_heuristics += [local_engine.analyze_ip(ip) for ip in ips]

    return {
        "phishtank": phishtank_results,
        "spamhaus": spamhaus_results,
        "local_heuristics": local_heuristics,
    }
