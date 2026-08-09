"""Local CISA Known Exploited Vulnerabilities lookup tools."""

from __future__ import annotations

import json
import re
from dataclasses import dataclass
from pathlib import Path
from typing import Any

from threatsyft.config import get_cisa_kev_path, knowledge_update_command
from threatsyft.core import (
    InputValidationError,
    error_response,
    success_response,
)
from threatsyft.knowledge.attack import KnowledgeLoadError
from threatsyft.knowledge.cve import normalize_cve_id
from threatsyft.knowledge.snapshot_cache import load_cached

CVE_ID_PATTERN = re.compile(r"^CVE-\d{4}-\d{4,}$", re.IGNORECASE)


@dataclass(frozen=True)
class KevEntry:
    """Compact CISA KEV vulnerability metadata."""

    cve_id: str
    vendor_project: str | None
    product: str | None
    vulnerability_name: str | None
    date_added: str | None
    short_description: str | None
    required_action: str | None
    due_date: str | None
    known_ransomware_campaign_use: str | None
    notes: str | None
    cwes: list[str]


@dataclass(frozen=True)
class KevCatalog:
    """Parsed CISA KEV catalog and indexes."""

    path: Path
    title: str | None
    catalog_version: str | None
    date_released: str | None
    count: int
    vulnerabilities_by_cve: dict[str, KevEntry]


def kev_lookup(cve_id: str) -> dict[str, Any]:
    """Look up one CVE in the local CISA KEV catalog."""
    query = {"cve_id": cve_id}

    try:
        normalized_cve = normalize_cve_id(cve_id)
        catalog = load_kev_catalog()
    except InputValidationError as exc:
        return error_response("kev_lookup", query, "invalid_input", str(exc))
    except KnowledgeLoadError as exc:
        return exc.to_response("kev_lookup", query)

    query["cve_id"] = normalized_cve
    entry = catalog.vulnerabilities_by_cve.get(normalized_cve)
    if entry is None:
        return error_response(
            "kev_lookup",
            query,
            "not_found",
            f"{normalized_cve} was not found in the local CISA KEV catalog.",
            {"snapshot_path": str(catalog.path)},
        )

    return success_response(
        "kev_lookup",
        query,
        {
            "in_kev": True,
            "vulnerability": _entry_data(entry),
            "catalog": _catalog_metadata(catalog),
            "snapshot_path": str(catalog.path),
        },
    )


def kev_search(query: str, limit: int = 10) -> dict[str, Any]:
    """Search the local CISA KEV catalog."""
    response_query: dict[str, Any] = {"query": query, "limit": limit}

    try:
        normalized_query = _normalize_search_query(query)
        normalized_limit = _normalize_limit(limit)
        catalog = load_kev_catalog()
    except InputValidationError as exc:
        return error_response("kev_search", response_query, "invalid_input", str(exc))
    except KnowledgeLoadError as exc:
        return exc.to_response("kev_search", response_query)

    response_query["query"] = normalized_query
    response_query["limit"] = normalized_limit
    match_count, matches = _search_entries(catalog, normalized_query, normalized_limit)

    return success_response(
        "kev_search",
        response_query,
        {
            "query": normalized_query,
            "limit": normalized_limit,
            "match_count": match_count,
            "returned": len(matches),
            "matches": matches,
            "catalog": _catalog_metadata(catalog),
            "snapshot_path": str(catalog.path),
        },
    )


_KEV_CACHE: dict[str, tuple[float, KevCatalog]] = {}


def load_kev_catalog(path: Path | None = None) -> KevCatalog:
    """Load the local CISA KEV catalog, reusing an unchanged parse."""
    snapshot_path = path or get_cisa_kev_path()
    return load_cached(_KEV_CACHE, snapshot_path, lambda: _load_kev_catalog(snapshot_path))


def _load_kev_catalog(snapshot_path: Path) -> KevCatalog:
    try:
        raw_text = snapshot_path.read_text(encoding="utf-8")
    except FileNotFoundError as exc:
        raise KnowledgeLoadError(
            "not_found",
            "CISA KEV catalog snapshot was not found.",
            {
                "snapshot_path": str(snapshot_path),
                "setup_command": knowledge_update_command("kev"),
            },
        ) from exc
    except OSError as exc:
        raise KnowledgeLoadError(
            "upstream_error",
            "CISA KEV catalog snapshot could not be read.",
            {"snapshot_path": str(snapshot_path), "reason": str(exc)},
        ) from exc

    try:
        payload = json.loads(raw_text)
    except json.JSONDecodeError as exc:
        raise KnowledgeLoadError(
            "parse_error",
            "CISA KEV catalog snapshot is not valid JSON.",
            {"snapshot_path": str(snapshot_path), "reason": str(exc)},
        ) from exc

    if not isinstance(payload, dict) or not isinstance(payload.get("vulnerabilities"), list):
        raise KnowledgeLoadError(
            "parse_error",
            "CISA KEV catalog snapshot must contain a vulnerabilities list.",
            {"snapshot_path": str(snapshot_path)},
        )

    entries: dict[str, KevEntry] = {}
    for item in payload["vulnerabilities"]:
        if not isinstance(item, dict):
            continue
        entry = _parse_entry(item)
        if entry is not None:
            entries[entry.cve_id] = entry

    return KevCatalog(
        path=snapshot_path,
        title=_clean_optional_string(payload.get("title")),
        catalog_version=_clean_optional_string(payload.get("catalogVersion")),
        date_released=_clean_optional_string(payload.get("dateReleased")),
        count=len(entries),
        vulnerabilities_by_cve=entries,
    )


def _parse_entry(item: dict[str, Any]) -> KevEntry | None:
    cve_id = _clean_optional_string(item.get("cveID"))
    if cve_id is None or CVE_ID_PATTERN.fullmatch(cve_id) is None:
        return None

    return KevEntry(
        cve_id=cve_id.upper(),
        vendor_project=_clean_optional_string(item.get("vendorProject")),
        product=_clean_optional_string(item.get("product")),
        vulnerability_name=_clean_optional_string(item.get("vulnerabilityName")),
        date_added=_clean_optional_string(item.get("dateAdded")),
        short_description=_clean_optional_string(item.get("shortDescription")),
        required_action=_clean_optional_string(item.get("requiredAction")),
        due_date=_clean_optional_string(item.get("dueDate")),
        known_ransomware_campaign_use=_clean_optional_string(
            item.get("knownRansomwareCampaignUse")
        ),
        notes=_clean_optional_string(item.get("notes")),
        cwes=_string_list(item.get("cwes")),
    )


def _search_entries(
    catalog: KevCatalog,
    query: str,
    limit: int,
) -> tuple[int, list[dict[str, Any]]]:
    """Return the total number of matches and the limited slice of them."""
    query_lower = query.lower()
    scored: list[tuple[int, KevEntry]] = []

    for entry in catalog.vulnerabilities_by_cve.values():
        score = _score_entry(entry, query_lower)
        if score > 0:
            scored.append((score, entry))

    scored.sort(key=lambda item: (-item[0], item[1].cve_id))
    return len(scored), [
        {
            **_entry_data(entry),
            "score": score,
            "matched_context": _matched_context(entry, query_lower),
        }
        for score, entry in scored[:limit]
    ]


def _score_entry(entry: KevEntry, query: str) -> int:
    score = 0
    if entry.cve_id.lower() == query:
        score += 100
    elif query in entry.cve_id.lower():
        score += 80

    for field_value in [
        entry.vendor_project,
        entry.product,
        entry.vulnerability_name,
        entry.short_description,
        entry.required_action,
        entry.notes,
        " ".join(entry.cwes),
    ]:
        if field_value and query in field_value.lower():
            score += 20

    return score


def _matched_context(entry: KevEntry, query: str) -> str | None:
    for value in [
        entry.cve_id,
        entry.vulnerability_name,
        entry.short_description,
        entry.required_action,
        entry.notes,
        entry.vendor_project,
        entry.product,
    ]:
        if not value:
            continue
        index = value.lower().find(query)
        if index < 0:
            continue
        start = max(index - 80, 0)
        end = min(index + len(query) + 80, len(value))
        prefix = "..." if start > 0 else ""
        suffix = "..." if end < len(value) else ""
        return f"{prefix}{value[start:end].strip()}{suffix}"
    return None


def _entry_data(entry: KevEntry) -> dict[str, Any]:
    return {
        "cve_id": entry.cve_id,
        "vendor_project": entry.vendor_project,
        "product": entry.product,
        "vulnerability_name": entry.vulnerability_name,
        "date_added": entry.date_added,
        "short_description": entry.short_description,
        "required_action": entry.required_action,
        "due_date": entry.due_date,
        "known_ransomware_campaign_use": entry.known_ransomware_campaign_use,
        "notes": entry.notes,
        "cwes": entry.cwes,
        "source": "CISA Known Exploited Vulnerabilities Catalog",
        "source_url": "https://www.cisa.gov/known-exploited-vulnerabilities-catalog",
    }


def _catalog_metadata(catalog: KevCatalog) -> dict[str, Any]:
    return {
        "title": catalog.title,
        "catalog_version": catalog.catalog_version,
        "date_released": catalog.date_released,
        "count": catalog.count,
    }


def _normalize_search_query(value: str) -> str:
    query = " ".join(value.strip().split())
    if not query:
        raise InputValidationError("Search query must not be empty.")
    return query


def _normalize_limit(value: int) -> int:
    if isinstance(value, bool) or not isinstance(value, int):
        raise InputValidationError("Limit must be an integer between 1 and 25.")
    if value < 1 or value > 25:
        raise InputValidationError("Limit must be between 1 and 25.")
    return value


def _string_list(value: object) -> list[str]:
    if not isinstance(value, list):
        return []
    return sorted({item.strip() for item in value if isinstance(item, str) and item.strip()})


def _clean_optional_string(value: object) -> str | None:
    if not isinstance(value, str):
        return None
    cleaned = value.strip()
    return cleaned or None
