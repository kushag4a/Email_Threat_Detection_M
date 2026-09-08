import re

URL_PATTERN = re.compile(
    r"https?://[^\s<>\"']+",
    re.IGNORECASE
)


def extract_urls(text: str) -> list[str]:
    if not text:
        return []

    urls = URL_PATTERN.findall(text)

    # Remove duplicates while preserving order
    return list(dict.fromkeys(urls))
