from urllib.parse import urlparse


def extract_domains(urls: list[str]) -> list[str]:
    domains = []

    for url in urls:
        try:
            hostname = urlparse(url).hostname
        except ValueError:
            continue

        if hostname:
            hostname = hostname.lower()

            if hostname not in domains:
                domains.append(hostname)

    return domains
