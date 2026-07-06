"""Local LOLBAS lookup tools for defensive living-off-the-land context."""

from __future__ import annotations

import json
import re
from dataclasses import dataclass
from pathlib import Path
from typing import Any

from threatsyft.config import get_lolbas_path, knowledge_update_command
from threatsyft.core import (
    InputValidationError,
    error_response,
    success_response,
)
from threatsyft.knowledge.attack import KnowledgeLoadError
from threatsyft.knowledge.snapshot_cache import load_cached


@dataclass(frozen=True)
class LolbasEntry:
    """Compact LOLBAS entry metadata."""

    name: str
    description: str | None
    author: str | None
    created: str | None
    categories: list[str]
    usecases: list[str]
    privileges: list[str]
    operating_systems: list[str]
    mitre_ids: list[str]
    paths: list[str]
    detections: list[dict[str, str]]
    resources: list[str]
    url: str | None
    command_count: int


@dataclass(frozen=True)
class LolbasCatalog:
    """Parsed LOLBAS catalog and simple indexes."""

    path: Path
    count: int
    entries_by_name: dict[str, LolbasEntry]


def lolbas_lookup(name: str) -> dict[str, Any]:
    """Look up one LOLBAS entry by executable/script name."""
    query = {"name": name}

    try:
        normalized_name = _normalize_name(name)
        catalog = load_lolbas_catalog()
    except InputValidationError as exc:
        return error_response("lolbas_lookup", query, "invalid_input", str(exc))
    except KnowledgeLoadError as exc:
        return exc.to_response("lolbas_lookup", query)

    query["name"] = normalized_name
    entry = catalog.entries_by_name.get(normalized_name.casefold())
    if entry is None:
        return error_response(
            "lolbas_lookup",
            query,
            "not_found",
            f"{normalized_name} was not found in the local LOLBAS catalog.",
            {"snapshot_path": str(catalog.path)},
        )

    return success_response(
        "lolbas_lookup",
        query,
        {
            "entry": _entry_data(entry),
            "catalog": _catalog_metadata(catalog),
            "snapshot_path": str(catalog.path),
        },
    )


def lolbas_search(query: str, limit: int = 10) -> dict[str, Any]:
    """Search local LOLBAS entries."""
    response_query: dict[str, Any] = {"query": query, "limit": limit}

    try:
        normalized_query = _normalize_search_query(query)
        normalized_limit = _normalize_limit(limit)
        catalog = load_lolbas_catalog()
    except InputValidationError as exc:
        return error_response("lolbas_search", response_query, "invalid_input", str(exc))
    except KnowledgeLoadError as exc:
        return exc.to_response("lolbas_search", response_query)

    response_query["query"] = normalized_query
    response_query["limit"] = normalized_limit
    matches = _search_entries(catalog, normalized_query, normalized_limit)

    return success_response(
        "lolbas_search",
        response_query,
        {
            "query": normalized_query,
            "limit": normalized_limit,
            "match_count": len(matches),
            "matches": matches,
            "catalog": _catalog_metadata(catalog),
            "snapshot_path": str(catalog.path),
        },
    )


_LOLBAS_CACHE: dict[str, tuple[float, LolbasCatalog]] = {}


def load_lolbas_catalog(path: Path | None = None) -> LolbasCatalog:
    """Load the local LOLBAS JSON catalog, reusing an unchanged parse."""
    snapshot_path = path or get_lolbas_path()
    return load_cached(_LOLBAS_CACHE, snapshot_path, lambda: _load_lolbas_catalog(snapshot_path))


def _load_lolbas_catalog(snapshot_path: Path) -> LolbasCatalog:
    try:
        raw_text = snapshot_path.read_text(encoding="utf-8")
    except FileNotFoundError as exc:
        raise KnowledgeLoadError(
            "not_found",
            "LOLBAS catalog snapshot was not found.",
            {
                "snapshot_path": str(snapshot_path),
                "setup_command": knowledge_update_command("lolbas"),
            },
        ) from exc
    except OSError as exc:
        raise KnowledgeLoadError(
            "upstream_error",
            "LOLBAS catalog snapshot could not be read.",
            {"snapshot_path": str(snapshot_path), "reason": str(exc)},
        ) from exc

    try:
        payload = json.loads(raw_text)
    except json.JSONDecodeError as exc:
        raise KnowledgeLoadError(
            "parse_error",
            "LOLBAS catalog snapshot is not valid JSON.",
            {"snapshot_path": str(snapshot_path), "reason": str(exc)},
        ) from exc

    if not isinstance(payload, list):
        raise KnowledgeLoadError(
            "parse_error",
            "LOLBAS catalog snapshot must be a JSON list.",
            {"snapshot_path": str(snapshot_path)},
        )

    entries: dict[str, LolbasEntry] = {}
    for item in payload:
        if not isinstance(item, dict):
            continue
        entry = _parse_entry(item)
        if entry is not None:
            entries[entry.name.casefold()] = entry

    return LolbasCatalog(path=snapshot_path, count=len(entries), entries_by_name=entries)


def _parse_entry(item: dict[str, Any]) -> LolbasEntry | None:
    name = _clean_optional_string(item.get("Name"))
    if name is None:
        return None

    commands = item.get("Commands")
    command_items = commands if isinstance(commands, list) else []
    return LolbasEntry(
        name=name,
        description=_clean_optional_string(item.get("Description")),
        author=_clean_optional_string(item.get("Author")),
        created=_clean_optional_string(item.get("Created")),
        categories=_command_field_values(command_items, "Category"),
        usecases=_command_field_values(command_items, "Usecase"),
        privileges=_command_field_values(command_items, "Privileges"),
        operating_systems=_command_field_values(command_items, "OperatingSystem"),
        mitre_ids=_command_field_values(command_items, "MitreID"),
        paths=_path_values(item.get("Full_Path")),
        detections=_detection_values(item.get("Detection")),
        resources=_resource_values(item.get("Resources")),
        url=_clean_optional_string(item.get("url")),
        command_count=len([command for command in command_items if isinstance(command, dict)]),
    )


def _search_entries(catalog: LolbasCatalog, query: str, limit: int) -> list[dict[str, Any]]:
    query_lower = query.lower()
    scored: list[tuple[int, LolbasEntry]] = []

    for entry in catalog.entries_by_name.values():
        score = _score_entry(entry, query_lower)
        if score > 0:
            scored.append((score, entry))

    scored.sort(key=lambda item: (-item[0], item[1].name.casefold()))
    return [
        {
            **_entry_summary(entry),
            "score": score,
            "matched_context": _matched_context(entry, query_lower),
        }
        for score, entry in scored[:limit]
    ]


def _score_entry(entry: LolbasEntry, query: str) -> int:
    score = 0
    name = entry.name.lower()
    if name == query:
        score += 100
    elif query in name:
        score += 80

    for values, weight in [
        ([entry.description], 25),
        (entry.categories, 20),
        (entry.mitre_ids, 20),
        (entry.usecases, 15),
        (entry.paths, 15),
        (entry.operating_systems, 10),
    ]:
        for value in values:
            if value and query in value.lower():
                score += weight
                break

    return score


def _matched_context(entry: LolbasEntry, query: str) -> str | None:
    for value in [
        entry.name,
        entry.description,
        *entry.categories,
        *entry.mitre_ids,
        *entry.usecases,
        *entry.paths,
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


def _entry_data(entry: LolbasEntry) -> dict[str, Any]:
    return {
        **_entry_summary(entry),
        "description": entry.description,
        "author": entry.author,
        "created": entry.created,
        "usecases": entry.usecases,
        "privileges": entry.privileges,
        "operating_systems": entry.operating_systems,
        "paths": entry.paths,
        "detections": entry.detections,
        "resources": entry.resources,
        "command_count": entry.command_count,
        "command_examples_omitted": True,
        "source": "LOLBAS",
    }


def _entry_summary(entry: LolbasEntry) -> dict[str, Any]:
    return {
        "name": entry.name,
        "categories": entry.categories,
        "mitre_ids": entry.mitre_ids,
        "url": entry.url,
    }


def _catalog_metadata(catalog: LolbasCatalog) -> dict[str, Any]:
    return {"count": catalog.count}


def _command_field_values(commands: list[Any], field_name: str) -> list[str]:
    values: list[str] = []
    for command in commands:
        if not isinstance(command, dict):
            continue
        raw_value = command.get(field_name)
        if not isinstance(raw_value, str):
            continue
        values.extend(_split_command_value(raw_value))
    return sorted(set(values), key=str.casefold)


def _split_command_value(value: str) -> list[str]:
    return [item.strip() for item in re.split(r",|;", value) if item.strip()]


def _path_values(value: object) -> list[str]:
    if not isinstance(value, list):
        return []
    paths: list[str] = []
    for item in value:
        if not isinstance(item, dict):
            continue
        path = _clean_optional_string(item.get("Path"))
        if path is not None:
            paths.append(path)
    return sorted(set(paths), key=str.casefold)


def _detection_values(value: object) -> list[dict[str, str]]:
    if not isinstance(value, list):
        return []
    detections: list[dict[str, str]] = []
    for item in value:
        if not isinstance(item, dict):
            continue
        for key, detection_value in item.items():
            if isinstance(key, str) and isinstance(detection_value, str):
                detections.append({"type": key, "value": detection_value})
    return detections


def _resource_values(value: object) -> list[str]:
    if not isinstance(value, list):
        return []
    resources: list[str] = []
    for item in value:
        if not isinstance(item, dict):
            continue
        link = _clean_optional_string(item.get("Link"))
        if link is not None:
            resources.append(link)
    return resources


def _normalize_name(value: str) -> str:
    name = value.strip()
    if not name:
        raise InputValidationError("LOLBAS name must not be empty.")
    return name


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


def _clean_optional_string(value: object) -> str | None:
    if not isinstance(value, str):
        return None
    cleaned = value.strip()
    return cleaned or None
