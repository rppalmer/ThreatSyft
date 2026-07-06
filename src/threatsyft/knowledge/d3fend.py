"""Local MITRE D3FEND lookup tools for defensive technique context."""

from __future__ import annotations

import json
import re
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any

from threatsyft.config import get_d3fend_path, knowledge_update_command
from threatsyft.core import (
    InputValidationError,
    error_response,
    success_response,
)
from threatsyft.knowledge.attack import KnowledgeLoadError
from threatsyft.knowledge.snapshot_cache import load_cached

D3FEND_ID_PATTERN = re.compile(r"^D3-[A-Z0-9-]+$", re.IGNORECASE)
ATTACK_ID_PATTERN = re.compile(r"^T\d{4}(?:\.\d{3})?$", re.IGNORECASE)


@dataclass
class D3FendTechnique:
    """Compact D3FEND defensive technique metadata."""

    d3fend_id: str
    name: str
    ontology_id: str
    definition: str | None
    synonyms: list[str]
    tactics: list[str] = field(default_factory=list)
    top_level_techniques: list[str] = field(default_factory=list)
    artifacts: list[str] = field(default_factory=list)
    related_attack_techniques: list[dict[str, str | None]] = field(default_factory=list)


@dataclass(frozen=True)
class D3FendTactic:
    """Compact D3FEND defensive tactic metadata."""

    name: str
    definition: str | None
    ontology_id: str


@dataclass(frozen=True)
class D3FendCatalog:
    """Parsed D3FEND snapshot and indexes."""

    path: Path
    techniques_by_id: dict[str, D3FendTechnique]
    techniques_by_name: dict[str, D3FendTechnique]
    tactics_by_name: dict[str, D3FendTactic]
    mappings: list[dict[str, str | None]]


def d3fend_lookup(defense_id_or_name: str) -> dict[str, Any]:
    """Look up one D3FEND defensive technique by ID or name."""
    query = {"defense_id_or_name": defense_id_or_name}

    try:
        lookup_value = _normalize_lookup_value(defense_id_or_name)
        catalog = load_d3fend_catalog()
    except InputValidationError as exc:
        return error_response("d3fend_lookup", query, "invalid_input", str(exc))
    except KnowledgeLoadError as exc:
        return exc.to_response("d3fend_lookup", query)

    technique = _find_technique(catalog, lookup_value)
    if technique is None:
        return error_response(
            "d3fend_lookup",
            query,
            "not_found",
            f"{lookup_value} was not found in the local D3FEND snapshot.",
            {"snapshot_path": str(catalog.path)},
        )

    query["defense_id_or_name"] = technique.d3fend_id
    return success_response(
        "d3fend_lookup",
        query,
        {
            "technique": _technique_data(technique),
            "snapshot_path": str(catalog.path),
        },
    )


def d3fend_search(query: str, limit: int = 10) -> dict[str, Any]:
    """Search local D3FEND defensive techniques."""
    response_query: dict[str, Any] = {"query": query, "limit": limit}

    try:
        normalized_query = _normalize_search_query(query)
        normalized_limit = _normalize_limit(limit)
        catalog = load_d3fend_catalog()
    except InputValidationError as exc:
        return error_response("d3fend_search", response_query, "invalid_input", str(exc))
    except KnowledgeLoadError as exc:
        return exc.to_response("d3fend_search", response_query)

    response_query["query"] = normalized_query
    response_query["limit"] = normalized_limit
    matches = _search_techniques(catalog, normalized_query, normalized_limit)

    return success_response(
        "d3fend_search",
        response_query,
        {
            "query": normalized_query,
            "limit": normalized_limit,
            "match_count": len(matches),
            "matches": matches,
            "snapshot_path": str(catalog.path),
        },
    )


def attack_defense_mapping(technique_id: str) -> dict[str, Any]:
    """Map one ATT&CK technique ID to related D3FEND defensive techniques."""
    query = {"technique_id": technique_id}

    try:
        normalized_id = _normalize_attack_id(technique_id)
        catalog = load_d3fend_catalog()
    except InputValidationError as exc:
        return error_response("attack_defense_mapping", query, "invalid_input", str(exc))
    except KnowledgeLoadError as exc:
        return exc.to_response("attack_defense_mapping", query)

    query["technique_id"] = normalized_id
    mappings = [
        mapping for mapping in catalog.mappings if mapping.get("attack_id") == normalized_id
    ]
    if not mappings:
        return error_response(
            "attack_defense_mapping",
            query,
            "not_found",
            f"No local D3FEND mappings were found for ATT&CK technique {normalized_id}.",
            {"snapshot_path": str(catalog.path)},
        )

    techniques = _mapped_defensive_techniques(catalog, mappings)
    return success_response(
        "attack_defense_mapping",
        query,
        {
            "attack_technique_id": normalized_id,
            "attack_technique_name": _first_present(mappings, "attack_name"),
            "defensive_technique_count": len(techniques),
            "defensive_techniques": techniques,
            "snapshot_path": str(catalog.path),
        },
    )


_D3FEND_CACHE: dict[str, tuple[float, D3FendCatalog]] = {}


def load_d3fend_catalog(path: Path | None = None) -> D3FendCatalog:
    """Load the local D3FEND combined JSON snapshot, reusing an unchanged parse."""
    snapshot_path = path or get_d3fend_path()
    return load_cached(_D3FEND_CACHE, snapshot_path, lambda: _load_d3fend_catalog(snapshot_path))


def _load_d3fend_catalog(snapshot_path: Path) -> D3FendCatalog:
    try:
        raw_text = snapshot_path.read_text(encoding="utf-8")
    except FileNotFoundError as exc:
        raise KnowledgeLoadError(
            "not_found",
            "D3FEND snapshot was not found.",
            {
                "snapshot_path": str(snapshot_path),
                "setup_command": knowledge_update_command("d3fend"),
            },
        ) from exc
    except OSError as exc:
        raise KnowledgeLoadError(
            "upstream_error",
            "D3FEND snapshot could not be read.",
            {"snapshot_path": str(snapshot_path), "reason": str(exc)},
        ) from exc

    try:
        payload = json.loads(raw_text)
    except json.JSONDecodeError as exc:
        raise KnowledgeLoadError(
            "parse_error",
            "D3FEND snapshot is not valid JSON.",
            {"snapshot_path": str(snapshot_path), "reason": str(exc)},
        ) from exc

    if not isinstance(payload, dict):
        raise KnowledgeLoadError(
            "parse_error",
            "D3FEND snapshot must be a JSON object.",
            {"snapshot_path": str(snapshot_path)},
        )

    techniques_payload = payload.get("techniques")
    tactics_payload = payload.get("tactics")
    mappings_payload = payload.get("mappings")
    if not all(isinstance(item, dict) for item in [techniques_payload, tactics_payload]):
        raise KnowledgeLoadError(
            "parse_error",
            "D3FEND snapshot must contain techniques and tactics objects.",
            {"snapshot_path": str(snapshot_path)},
        )
    if not isinstance(mappings_payload, dict):
        raise KnowledgeLoadError(
            "parse_error",
            "D3FEND snapshot must contain a mappings object.",
            {"snapshot_path": str(snapshot_path)},
        )

    return _parse_d3fend_snapshot(
        techniques_payload,
        tactics_payload,
        mappings_payload,
        snapshot_path,
    )


def _parse_d3fend_snapshot(
    techniques_payload: dict[str, Any],
    tactics_payload: dict[str, Any],
    mappings_payload: dict[str, Any],
    path: Path,
) -> D3FendCatalog:
    tactics_by_name = _parse_tactics(tactics_payload)
    techniques_by_id, techniques_by_name = _parse_techniques(techniques_payload)
    mappings = _parse_mappings(mappings_payload)
    _apply_mappings(techniques_by_name, mappings)

    return D3FendCatalog(
        path=path,
        techniques_by_id=techniques_by_id,
        techniques_by_name=techniques_by_name,
        tactics_by_name=tactics_by_name,
        mappings=mappings,
    )


def _parse_techniques(
    payload: dict[str, Any],
) -> tuple[dict[str, D3FendTechnique], dict[str, D3FendTechnique]]:
    graph = payload.get("@graph")
    if not isinstance(graph, list):
        return {}, {}

    by_id: dict[str, D3FendTechnique] = {}
    by_name: dict[str, D3FendTechnique] = {}
    for item in graph:
        if not isinstance(item, dict):
            continue
        d3fend_id = _clean_optional_string(item.get("d3f:d3fend-id"))
        name = _clean_optional_string(item.get("rdfs:label"))
        ontology_id = _clean_optional_string(item.get("@id"))
        if d3fend_id is None or name is None or ontology_id is None:
            continue
        technique = D3FendTechnique(
            d3fend_id=d3fend_id.upper(),
            name=name,
            ontology_id=ontology_id,
            definition=_clean_optional_string(item.get("d3f:definition")),
            synonyms=_string_values(item.get("d3f:synonym")),
        )
        by_id[technique.d3fend_id] = technique
        by_name[_slug(name)] = technique
        for synonym in technique.synonyms:
            by_name[_slug(synonym)] = technique

    return by_id, by_name


def _parse_tactics(payload: dict[str, Any]) -> dict[str, D3FendTactic]:
    graph = payload.get("@graph")
    if not isinstance(graph, list):
        return {}

    tactics: dict[str, D3FendTactic] = {}
    for item in graph:
        if not isinstance(item, dict):
            continue
        name = _clean_optional_string(item.get("rdfs:label"))
        ontology_id = _clean_optional_string(item.get("@id"))
        if name is None or ontology_id is None:
            continue
        tactic = D3FendTactic(
            name=name,
            definition=_clean_optional_string(item.get("d3f:definition")),
            ontology_id=ontology_id,
        )
        tactics[_slug(name)] = tactic
    return tactics


def _parse_mappings(payload: dict[str, Any]) -> list[dict[str, str | None]]:
    results = payload.get("results")
    bindings = results.get("bindings") if isinstance(results, dict) else None
    if not isinstance(bindings, list):
        return []

    mappings: list[dict[str, str | None]] = []
    seen: set[tuple[str | None, ...]] = set()
    for binding in bindings:
        if not isinstance(binding, dict):
            continue
        mapping = {
            "defense_name": _binding_value(binding, "def_tech_label"),
            "top_level_defense_name": _binding_value(binding, "top_def_tech_label"),
            "defense_tactic": _binding_value(binding, "def_tactic_label"),
            "defense_tactic_relation": _binding_value(binding, "def_tactic_rel_label"),
            "defense_artifact": _binding_value(binding, "def_artifact_label"),
            "defense_artifact_relation": _binding_value(binding, "def_artifact_rel_label"),
            "attack_id": _binding_value(binding, "off_tech_id"),
            "attack_name": _binding_value(binding, "off_tech_label"),
            "attack_tactic": _binding_value(binding, "off_tactic_label"),
            "attack_artifact": _binding_value(binding, "off_artifact_label"),
        }
        key = tuple(mapping.values())
        if mapping["defense_name"] is None or mapping["attack_id"] is None or key in seen:
            continue
        seen.add(key)
        mapping["attack_id"] = mapping["attack_id"].upper()
        mappings.append(mapping)
    return mappings


def _apply_mappings(
    techniques_by_name: dict[str, D3FendTechnique],
    mappings: list[dict[str, str | None]],
) -> None:
    related_seen: dict[str, set[tuple[str | None, str | None]]] = {}
    for mapping in mappings:
        technique = techniques_by_name.get(_slug(mapping.get("defense_name") or ""))
        if technique is None:
            continue

        _append_unique(technique.tactics, mapping.get("defense_tactic"))
        _append_unique(technique.top_level_techniques, mapping.get("top_level_defense_name"))
        _append_unique(technique.artifacts, mapping.get("defense_artifact"))

        related_key = technique.d3fend_id
        seen = related_seen.setdefault(related_key, set())
        attack_tuple = (mapping.get("attack_id"), mapping.get("attack_name"))
        if attack_tuple in seen:
            continue
        seen.add(attack_tuple)
        technique.related_attack_techniques.append(
            {
                "attack_id": mapping.get("attack_id"),
                "name": mapping.get("attack_name"),
                "tactic": mapping.get("attack_tactic"),
            }
        )

    for technique in techniques_by_name.values():
        technique.tactics.sort(key=str.casefold)
        technique.top_level_techniques.sort(key=str.casefold)
        technique.artifacts.sort(key=str.casefold)
        technique.related_attack_techniques.sort(key=lambda item: item.get("attack_id") or "")


def _mapped_defensive_techniques(
    catalog: D3FendCatalog,
    mappings: list[dict[str, str | None]],
) -> list[dict[str, Any]]:
    results: dict[str, dict[str, Any]] = {}
    for mapping in mappings:
        technique = catalog.techniques_by_name.get(_slug(mapping.get("defense_name") or ""))
        if technique is None:
            continue
        item = results.setdefault(
            technique.d3fend_id,
            {
                **_technique_summary(technique),
                "mapping_tactics": [],
                "mapping_artifacts": [],
            },
        )
        _append_unique(item["mapping_tactics"], mapping.get("defense_tactic"))
        _append_unique(item["mapping_artifacts"], mapping.get("defense_artifact"))

    for item in results.values():
        item["mapping_tactics"].sort(key=str.casefold)
        item["mapping_artifacts"].sort(key=str.casefold)

    return sorted(results.values(), key=lambda item: item["d3fend_id"])


def _search_techniques(catalog: D3FendCatalog, query: str, limit: int) -> list[dict[str, Any]]:
    query_lower = query.lower()
    scored: list[tuple[int, D3FendTechnique]] = []
    seen: set[str] = set()

    for technique in catalog.techniques_by_id.values():
        if technique.d3fend_id in seen:
            continue
        seen.add(technique.d3fend_id)
        score = _score_technique(technique, query_lower)
        if score > 0:
            scored.append((score, technique))

    scored.sort(key=lambda item: (-item[0], item[1].d3fend_id))
    return [
        {
            **_technique_summary(technique),
            "score": score,
            "matched_context": _matched_context(technique, query_lower),
        }
        for score, technique in scored[:limit]
    ]


def _score_technique(technique: D3FendTechnique, query: str) -> int:
    score = 0
    if technique.d3fend_id.lower() == query:
        score += 100
    elif query in technique.d3fend_id.lower():
        score += 80
    if technique.name.lower() == query:
        score += 70
    elif query in technique.name.lower():
        score += 45

    for values, weight in [
        (technique.synonyms, 30),
        ([technique.definition], 20),
        (technique.tactics, 20),
        (technique.top_level_techniques, 15),
        (technique.artifacts, 15),
        ([item.get("attack_id") for item in technique.related_attack_techniques], 15),
        ([item.get("name") for item in technique.related_attack_techniques], 10),
    ]:
        for value in values:
            if value and query in value.lower():
                score += weight
                break
    return score


def _matched_context(technique: D3FendTechnique, query: str) -> str | None:
    values = [
        technique.d3fend_id,
        technique.name,
        technique.definition,
        *technique.synonyms,
        *technique.tactics,
        *technique.top_level_techniques,
        *technique.artifacts,
    ]
    for value in values:
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


def _technique_data(technique: D3FendTechnique) -> dict[str, Any]:
    return {
        **_technique_summary(technique),
        "definition": technique.definition,
        "synonyms": technique.synonyms,
        "top_level_techniques": technique.top_level_techniques,
        "artifacts": technique.artifacts,
        "related_attack_techniques": technique.related_attack_techniques[:25],
        "source": "MITRE D3FEND",
        "source_url": _source_url(technique),
    }


def _technique_summary(technique: D3FendTechnique) -> dict[str, Any]:
    return {
        "d3fend_id": technique.d3fend_id,
        "name": technique.name,
        "tactics": technique.tactics,
        "related_attack_technique_count": len(technique.related_attack_techniques),
    }


def _source_url(technique: D3FendTechnique) -> str:
    return f"https://d3fend.mitre.org/technique/{technique.ontology_id}/"


def _find_technique(catalog: D3FendCatalog, value: str) -> D3FendTechnique | None:
    if D3FEND_ID_PATTERN.fullmatch(value):
        return catalog.techniques_by_id.get(value.upper())
    return catalog.techniques_by_name.get(_slug(value))


def _normalize_lookup_value(value: str) -> str:
    lookup_value = " ".join(value.strip().split())
    if not lookup_value:
        raise InputValidationError("D3FEND technique ID or name must not be empty.")
    return lookup_value


def _normalize_search_query(value: str) -> str:
    query = " ".join(value.strip().split())
    if not query:
        raise InputValidationError("Search query must not be empty.")
    return query


def _normalize_attack_id(value: str) -> str:
    technique_id = value.strip().upper()
    if not technique_id:
        raise InputValidationError("ATT&CK technique ID must not be empty.")
    if ATTACK_ID_PATTERN.fullmatch(technique_id) is None:
        raise InputValidationError("ATT&CK technique ID must look like T1059 or T1059.001.")
    return technique_id


def _normalize_limit(value: int) -> int:
    if isinstance(value, bool) or not isinstance(value, int):
        raise InputValidationError("Limit must be an integer between 1 and 25.")
    if value < 1 or value > 25:
        raise InputValidationError("Limit must be between 1 and 25.")
    return value


def _binding_value(binding: dict[str, Any], key: str) -> str | None:
    item = binding.get(key)
    if not isinstance(item, dict):
        return None
    return _clean_optional_string(item.get("value"))


def _first_present(mappings: list[dict[str, str | None]], key: str) -> str | None:
    for mapping in mappings:
        value = mapping.get(key)
        if value:
            return value
    return None


def _append_unique(values: list[str], value: str | None) -> None:
    if value and value not in values:
        values.append(value)


def _string_values(value: object) -> list[str]:
    if isinstance(value, str):
        return [value]
    if isinstance(value, list):
        return sorted(
            {item.strip() for item in value if isinstance(item, str) and item.strip()},
            key=str.casefold,
        )
    return []


def _slug(value: str) -> str:
    return re.sub(r"[^a-z0-9]+", "-", value.strip().lower()).strip("-")


def _clean_optional_string(value: object) -> str | None:
    if not isinstance(value, str):
        return None
    cleaned = value.strip()
    return cleaned or None
