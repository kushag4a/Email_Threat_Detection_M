"""
Operator/maintenance utility to refresh the local PhishTank feed.

This is NOT called on the request path — core detection must keep
working even if this has never been run or the network is
unavailable. Run manually or on a schedule you control:

    python -m backend.app.threat_intel.feed_updater
"""

import json
from pathlib import Path

import requests

DATA_DIR = Path(__file__).parent / "data"
PHISHTANK_URL = "https://data.phishtank.com/data/online-valid.json"


def update_phishtank() -> int:
    response = requests.get(
        PHISHTANK_URL,
        headers={"User-Agent": "EmailThreatDetection/1.0"},
        timeout=30,
    )
    response.raise_for_status()

    data = response.json()

    output = DATA_DIR / "phishtank.json"
    with output.open("w", encoding="utf-8") as file:
        json.dump(data, file)

    return len(data)


if __name__ == "__main__":
    count = update_phishtank()
    print(f"Updated local PhishTank feed: {count} records.")
