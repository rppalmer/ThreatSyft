"""Local IOC extraction from arbitrary untrusted text. No network."""

from __future__ import annotations

import ipaddress
import re
from collections import defaultdict
from typing import Any

from threatsyft.core import error_response, success_response

TOOL_NAME = "extract_iocs"
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
    """Extract typed IOC candidates from arbitrary text.

    ``iocs`` carries values only, so a caller can iterate it and feed the values
    straight to an enrichment tool. The surrounding source text is untrusted and
    is kept apart under ``untrusted_context``, keyed by IOC value, never merged
    into a server-authored field. A caller can drop that key entirely without
    losing any indicator.

    ``ioc_counts`` is how many distinct indicators of each type the text
    contains, counted before the per-type cap is applied, and ``returned_counts``
    is how many came back. They differ exactly for the types named in
    ``truncated``. This is the same distinction ``search`` draws between
    ``match_count`` and ``returned``, and it matters more here: this is the
    front of the extract-then-enrich pipeline, so a long report quietly losing
    its last indicators would lose them from everything downstream.
    """
    query = {"text_length": len(text)}
    if not text.strip():
        return error_response(TOOL_NAME, query, "invalid_input", "Text to scan is required.")

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

    iocs: dict[str, list[dict[str, str]]] = {}
    found_counts: dict[str, int] = {}
    untrusted_context: dict[str, list[str]] = {}
    for ioc_type, values in grouped.items():
        # Sorted so the retained set is deterministic rather than depending on
        # where in the text each indicator happened to appear.
        retained = sorted(values.items())[:MAX_ITEMS_PER_TYPE]
        iocs[ioc_type] = [{"value": value} for value, _ in retained]
        found_counts[ioc_type] = len(values)
        untrusted_context.update(retained)

    truncated = [
        ioc_type for ioc_type, total in found_counts.items() if total > len(iocs[ioc_type])
    ]

    return success_response(
        TOOL_NAME,
        query,
        {
            "iocs": iocs,
            "ioc_counts": found_counts,
            "returned_counts": {ioc_type: len(items) for ioc_type, items in iocs.items()},
            "truncated": truncated,
            "max_items_per_type": MAX_ITEMS_PER_TYPE,
            "untrusted_context": untrusted_context,
        },
    )


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


def _context(text: str, start: int, end: int) -> str:
    context_start = max(start - 90, 0)
    context_end = min(end + 90, len(text))
    return " ".join(text[context_start:context_end].split())
