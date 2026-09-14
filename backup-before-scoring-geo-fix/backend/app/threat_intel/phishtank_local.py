import json
from pathlib import Path

from backend.app.services.url_normalizer import normalize_url

DATA_FILE = Path(__file__).parent / "data" / "phishtank.json"

_cache: list[dict] | None = None
_index: dict[str, dict] | None = None


def _load() -> dict[str, dict]:
    """Load PhishTank's local feed once and index it by normalized URL."""

    global _cache, _index

    if _index is not None:
        return _index

    if not DATA_FILE.exists():
        _cache = []
        _index = {}
        return _index

    with DATA_FILE.open("r", encoding="utf-8") as file:
        _cache = json.load(file)

    _index = {}
    for record in _cache:
        url = record.get("url")
        if url:
            _index[normalize_url(url)] = record

    return _index


def check_url(url: str) -> dict:
    normalized = normalize_url(url)
    index = _load()
    record = index.get(normalized)

    if record:
        return {
            "source": "phishtank",
            "url": url,
            "listed": True,
            "verified": record.get("verified"),
            "online": record.get("online"),
            "target": record.get("target"),
            "risk": "high",
        }

    return {
        "source": "phishtank",
        "url": url,
        "listed": False,
        "verified": None,
        "online": None,
        "target": None,
        "risk": "unknown",
    }
