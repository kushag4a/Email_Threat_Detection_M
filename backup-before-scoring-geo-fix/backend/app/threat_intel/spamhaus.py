import ipaddress
from pathlib import Path

DATA_FILE = Path(__file__).parent / "data" / "spamhaus_drop.txt"

_networks: list | None = None


def _load_drop_networks() -> list:
    global _networks

    if _networks is not None:
        return _networks

    _networks = []

    if not DATA_FILE.exists():
        return _networks

    with DATA_FILE.open("r", encoding="utf-8") as file:
        for line in file:
            line = line.strip()

            if not line or line.startswith(";"):
                continue

            network_text = line.split(";")[0].strip()

            try:
                _networks.append(ipaddress.ip_network(network_text, strict=False))
            except ValueError:
                continue

    return _networks


def check_ip(ip: str) -> dict:
    try:
        address = ipaddress.ip_address(ip)
    except ValueError:
        return {
            "source": "spamhaus_drop",
            "ip": ip,
            "listed": False,
            "network": None,
            "risk": "unknown",
        }

    for network in _load_drop_networks():
        if address in network:
            return {
                "source": "spamhaus_drop",
                "ip": ip,
                "listed": True,
                "network": str(network),
                "risk": "high",
            }

    return {
        "source": "spamhaus_drop",
        "ip": ip,
        "listed": False,
        "network": None,
        "risk": "unknown",
    }
