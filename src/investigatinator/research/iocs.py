"""Local IOC extraction helpers for public research articles."""

from __future__ import annotations

import ipaddress
import re
from collections import defaultdict
from typing import Any

IPV4_PATTERN = re.compile(r"\b(?:\d{1,3}\.){3}\d{1,3}\b")
CVE_PATTERN = re.compile(r"\bCVE-\d{4}-\d{4,}\b", re.IGNORECASE)
HASH_PATTERN = re.compile(r"\b[a-fA-F0-9]{32}\b|\b[a-fA-F0-9]{40}\b|\b[a-fA-F0-9]{64}\b")
URL_PATTERN = re.compile(r"\bhttps?://[^\s<>'\"()]+", re.IGNORECASE)
DOMAIN_PATTERN = re.compile(
    r"\b(?:[a-zA-Z0-9-]{1,63}\.)+[a-zA-Z]{2,63}\b",
    re.IGNORECASE,
)
MAX_ITEMS_PER_TYPE = 50
MAX_CONTEXTS_PER_IOC = 3


def extract_iocs(text: str) -> dict[str, Any]:
    """Extract normalized IOCs from article text."""
    normalized_text = normalize_defanged_text(text)
    grouped: dict[str, dict[str, list[str]]] = {
        "ips": defaultdict(list),
        "domains": defaultdict(list),
        "urls": defaultdict(list),
        "hashes": defaultdict(list),
        "cves": defaultdict(list),
    }

    _collect_matches(grouped["ips"], normalized_text, IPV4_PATTERN, _normalize_ip)
    _collect_matches(grouped["urls"], normalized_text, URL_PATTERN, _normalize_url)
    _collect_matches(grouped["hashes"], normalized_text, HASH_PATTERN, _normalize_hash)
    _collect_matches(grouped["cves"], normalized_text, CVE_PATTERN, _normalize_cve)
    _collect_matches(grouped["domains"], normalized_text, DOMAIN_PATTERN, _normalize_domain)

    return {ioc_type: _ioc_items(values) for ioc_type, values in grouped.items()}


def normalize_defanged_text(text: str) -> str:
    """Normalize common defanged IOC markers for local extraction."""
    return (
        text.replace("hxxps://", "https://")
        .replace("hxxp://", "http://")
        .replace("HXXPS://", "https://")
        .replace("HXXP://", "http://")
        .replace("[.]", ".")
        .replace("(.)", ".")
        .replace("{.}", ".")
        .replace("[:]", ":")
    )


def _collect_matches(
    values: dict[str, list[str]],
    text: str,
    pattern: re.Pattern[str],
    normalize,
) -> None:
    for match in pattern.finditer(text):
        value = normalize(match.group(0))
        if value is None:
            continue
        contexts = values[value]
        if len(contexts) < MAX_CONTEXTS_PER_IOC:
            contexts.append(_context(text, match.start(), match.end()))


def _normalize_ip(value: str) -> str | None:
    try:
        return str(ipaddress.ip_address(value))
    except ValueError:
        return None


def _normalize_url(value: str) -> str | None:
    return value.rstrip(".,;:!?)]}")


def _normalize_hash(value: str) -> str | None:
    return value.lower()


def _normalize_cve(value: str) -> str | None:
    return value.upper()


def _normalize_domain(value: str) -> str | None:
    domain = value.lower().rstrip(".,;:!?)]}")
    return domain


def _ioc_items(values: dict[str, list[str]]) -> list[dict[str, Any]]:
    return [
        {"value": value, "contexts": contexts}
        for value, contexts in sorted(values.items())[:MAX_ITEMS_PER_TYPE]
    ]


def _context(text: str, start: int, end: int) -> str:
    context_start = max(start - 90, 0)
    context_end = min(end + 90, len(text))
    return " ".join(text[context_start:context_end].split())
