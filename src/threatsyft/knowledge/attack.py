"""Local MITRE ATT&CK Enterprise lookup tools."""

from __future__ import annotations

import json
import re
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any

from threatsyft.config import get_attack_stix_path, knowledge_update_command
from threatsyft.core import (
    InputValidationError,
    error_response,
    success_response,
)
from threatsyft.knowledge.snapshot_cache import load_cached

TECHNIQUE_ID_PATTERN = re.compile(r"^T\d{4}(?:\.\d{3})?$", re.IGNORECASE)
MITIGATION_ID_PATTERN = re.compile(r"^M\d{4}$", re.IGNORECASE)


@dataclass(frozen=True)
class Tactic:
    """Compact ATT&CK tactic metadata."""

    stix_id: str
    tactic_id: str | None
    name: str
    short_name: str
    description: str | None
    source_url: str | None


@dataclass
class Technique:
    """Compact ATT&CK technique metadata."""

    stix_id: str
    technique_id: str
    name: str
    description: str | None
    tactics: list[str]
    platforms: list[str]
    data_sources: list[str]
    detection: str | None
    references: list[dict[str, Any]]
    source_url: str | None
    revoked: bool
    deprecated: bool
    is_subtechnique: bool
    parent_id: str | None = None
    subtechnique_ids: list[str] = field(default_factory=list)
    mitigations: list[dict[str, Any]] = field(default_factory=list)


@dataclass(frozen=True)
class AttackKnowledge:
    """Parsed ATT&CK Enterprise data and simple lookup indexes."""

    path: Path
    techniques_by_id: dict[str, Technique]
    techniques_by_stix_id: dict[str, Technique]
    tactics_by_short_name: dict[str, Tactic]
    tactics_by_alias: dict[str, Tactic]
    mitigations_by_id: dict[str, dict[str, Any]] = field(default_factory=dict)


def attack_technique_lookup(technique_id: str) -> dict[str, Any]:
    """Look up one ATT&CK Enterprise technique by ID."""
    query = {"technique_id": technique_id}

    try:
        normalized_id = normalize_technique_id(technique_id)
        knowledge = load_attack_knowledge()
    except InputValidationError as exc:
        return error_response("attack_technique_lookup", query, "invalid_input", str(exc))
    except KnowledgeLoadError as exc:
        return exc.to_response("attack_technique_lookup", query)

    query["technique_id"] = normalized_id
    technique = knowledge.techniques_by_id.get(normalized_id)
    if technique is None:
        return error_response(
            "attack_technique_lookup",
            query,
            "not_found",
            f"ATT&CK technique {normalized_id} was not found in the local snapshot.",
            {"snapshot_path": str(knowledge.path)},
        )

    return success_response(
        "attack_technique_lookup",
        query,
        _technique_detail(technique, knowledge),
    )


def attack_search(query: str, limit: int = 10) -> dict[str, Any]:
    """Search local ATT&CK Enterprise techniques."""
    response_query: dict[str, Any] = {"query": query, "limit": limit}

    try:
        normalized_query = _normalize_search_query(query)
        normalized_limit = _normalize_limit(limit)
        knowledge = load_attack_knowledge()
    except InputValidationError as exc:
        return error_response("attack_search", response_query, "invalid_input", str(exc))
    except KnowledgeLoadError as exc:
        return exc.to_response("attack_search", response_query)

    response_query["query"] = normalized_query
    response_query["limit"] = normalized_limit
    match_count, matches = _search_techniques(knowledge, normalized_query, normalized_limit)

    return success_response(
        "attack_search",
        response_query,
        {
            "query": normalized_query,
            "limit": normalized_limit,
            "match_count": match_count,
            "returned": len(matches),
            "matches": matches,
            "snapshot_path": str(knowledge.path),
        },
    )


def attack_tactic_lookup(tactic: str) -> dict[str, Any]:
    """Look up one ATT&CK tactic by short name or display name."""
    query = {"tactic": tactic}

    try:
        tactic_alias = _normalize_tactic_alias(tactic)
        knowledge = load_attack_knowledge()
    except InputValidationError as exc:
        return error_response("attack_tactic_lookup", query, "invalid_input", str(exc))
    except KnowledgeLoadError as exc:
        return exc.to_response("attack_tactic_lookup", query)

    tactic_item = knowledge.tactics_by_alias.get(tactic_alias)
    if tactic_item is None:
        return error_response(
            "attack_tactic_lookup",
            query,
            "not_found",
            f"ATT&CK tactic {tactic!r} was not found in the local snapshot.",
            {"snapshot_path": str(knowledge.path)},
        )

    query["tactic"] = tactic_item.short_name
    # Identity only. A tactic holds dozens of techniques, and a full summary
    # each made this the largest response in the project; call lookup on any of
    # them for the detail.
    techniques = [
        _technique_ref(technique)
        for technique in sorted(
            knowledge.techniques_by_id.values(),
            key=lambda item: item.technique_id,
        )
        if tactic_item.short_name in technique.tactics
    ]

    return success_response(
        "attack_tactic_lookup",
        query,
        {
            "tactic": _tactic_data(tactic_item),
            "technique_count": len(techniques),
            "techniques": techniques,
            "snapshot_path": str(knowledge.path),
        },
    )


def attack_mitigation_lookup(mitigation_id: str) -> dict[str, Any]:
    """Look up one ATT&CK mitigation by ID, with its full description.

    This is what makes trimming the mitigation list on a technique safe: the
    prose is one call away instead of being inlined nine times over.
    """
    query = {"mitigation_id": mitigation_id}

    try:
        normalized_id = normalize_mitigation_id(mitigation_id)
        knowledge = load_attack_knowledge()
    except InputValidationError as exc:
        return error_response("attack_mitigation_lookup", query, "invalid_input", str(exc))
    except KnowledgeLoadError as exc:
        return exc.to_response("attack_mitigation_lookup", query)

    query["mitigation_id"] = normalized_id
    mitigation = knowledge.mitigations_by_id.get(normalized_id)
    if mitigation is None:
        return error_response(
            "attack_mitigation_lookup",
            query,
            "not_found",
            f"ATT&CK mitigation {normalized_id} was not found in the local snapshot.",
            {"snapshot_path": str(knowledge.path)},
        )

    techniques = [
        _technique_ref(technique)
        for technique in sorted(
            knowledge.techniques_by_id.values(), key=lambda item: item.technique_id
        )
        if any(entry.get("mitigation_id") == normalized_id for entry in technique.mitigations)
    ]

    return success_response(
        "attack_mitigation_lookup",
        query,
        {
            **mitigation,
            "technique_count": len(techniques),
            "techniques": techniques,
            "snapshot_path": str(knowledge.path),
        },
    )


def normalize_mitigation_id(value: str) -> str:
    """Normalize an ATT&CK mitigation ID such as ``M1038``."""
    mitigation_id = value.strip().upper()
    if not mitigation_id:
        raise InputValidationError("Mitigation ID must not be empty.")
    if not MITIGATION_ID_PATTERN.fullmatch(mitigation_id):
        raise InputValidationError("Mitigation ID must look like M1038.")
    return mitigation_id


class KnowledgeLoadError(Exception):
    """Raised when the local knowledge snapshot cannot be loaded."""

    def __init__(
        self,
        code: str,
        message: str,
        details: dict[str, Any] | str | None = None,
    ) -> None:
        super().__init__(message)
        self.code = code
        self.message = message
        self.details = details

    def to_response(self, tool: str, query: dict[str, Any]) -> dict[str, Any]:
        """Convert this load failure to a shared tool envelope."""
        return error_response(tool, query, self.code, self.message, self.details)


_ATTACK_CACHE: dict[str, tuple[float, AttackKnowledge]] = {}


def load_attack_knowledge(path: Path | None = None) -> AttackKnowledge:
    """Load the local ATT&CK Enterprise STIX snapshot, reusing an unchanged parse."""
    snapshot_path = path or get_attack_stix_path()
    return load_cached(_ATTACK_CACHE, snapshot_path, lambda: _load_attack_knowledge(snapshot_path))


def _load_attack_knowledge(snapshot_path: Path) -> AttackKnowledge:
    try:
        raw_text = snapshot_path.read_text(encoding="utf-8")
    except FileNotFoundError as exc:
        raise KnowledgeLoadError(
            "not_found",
            "ATT&CK Enterprise STIX snapshot was not found.",
            {
                "snapshot_path": str(snapshot_path),
                "setup_command": knowledge_update_command("attack"),
            },
        ) from exc
    except OSError as exc:
        raise KnowledgeLoadError(
            "upstream_error",
            "ATT&CK Enterprise STIX snapshot could not be read.",
            {"snapshot_path": str(snapshot_path), "reason": str(exc)},
        ) from exc

    try:
        bundle = json.loads(raw_text)
    except json.JSONDecodeError as exc:
        raise KnowledgeLoadError(
            "parse_error",
            "ATT&CK Enterprise STIX snapshot is not valid JSON.",
            {"snapshot_path": str(snapshot_path), "reason": str(exc)},
        ) from exc

    if not isinstance(bundle, dict) or not isinstance(bundle.get("objects"), list):
        raise KnowledgeLoadError(
            "parse_error",
            "ATT&CK Enterprise STIX snapshot must contain an objects list.",
            {"snapshot_path": str(snapshot_path)},
        )

    return _parse_attack_bundle(bundle["objects"], snapshot_path)


def _parse_attack_bundle(objects: list[Any], path: Path) -> AttackKnowledge:
    tactics_by_short_name: dict[str, Tactic] = {}
    tactics_by_alias: dict[str, Tactic] = {}
    techniques_by_id: dict[str, Technique] = {}
    techniques_by_stix_id: dict[str, Technique] = {}
    mitigations_by_stix_id: dict[str, dict[str, Any]] = {}
    relationships: list[dict[str, Any]] = []

    for item in objects:
        if not isinstance(item, dict):
            continue

        item_type = item.get("type")
        if item_type == "x-mitre-tactic":
            tactic = _parse_tactic(item)
            if tactic is not None:
                tactics_by_short_name[tactic.short_name] = tactic
                tactics_by_alias[tactic.short_name] = tactic
                tactics_by_alias[_slug(tactic.name)] = tactic
                # Also findable by its TA#### id, which is how ATT&CK itself
                # refers to a tactic and the only stable handle for it.
                if tactic.tactic_id:
                    tactics_by_alias[_slug(tactic.tactic_id)] = tactic
            continue

        if item_type == "attack-pattern":
            technique = _parse_technique(item)
            if technique is not None:
                techniques_by_id[technique.technique_id] = technique
                techniques_by_stix_id[technique.stix_id] = technique
            continue

        if item_type == "course-of-action":
            mitigation = _parse_mitigation(item)
            stix_id = _clean_optional_string(item.get("id"))
            if mitigation is not None and stix_id is not None:
                mitigations_by_stix_id[stix_id] = mitigation
            continue

        if item_type == "relationship":
            relationships.append(item)

    _apply_relationships(relationships, techniques_by_stix_id, mitigations_by_stix_id)
    return AttackKnowledge(
        path=path,
        techniques_by_id=techniques_by_id,
        techniques_by_stix_id=techniques_by_stix_id,
        tactics_by_short_name=tactics_by_short_name,
        tactics_by_alias=tactics_by_alias,
        mitigations_by_id={
            mitigation["mitigation_id"]: mitigation
            for mitigation in mitigations_by_stix_id.values()
        },
    )


def _parse_tactic(item: dict[str, Any]) -> Tactic | None:
    short_name = _clean_optional_string(item.get("x_mitre_shortname"))
    name = _clean_optional_string(item.get("name"))
    stix_id = _clean_optional_string(item.get("id"))
    if short_name is None or name is None or stix_id is None:
        return None

    external_id, source_url = _mitre_external_reference(item.get("external_references", []))
    return Tactic(
        stix_id=stix_id,
        tactic_id=external_id,
        name=name,
        short_name=short_name,
        description=_clean_optional_string(item.get("description")),
        source_url=source_url,
    )


def _parse_technique(item: dict[str, Any]) -> Technique | None:
    technique_id, source_url = _mitre_external_reference(item.get("external_references", []))
    name = _clean_optional_string(item.get("name"))
    stix_id = _clean_optional_string(item.get("id"))
    if technique_id is None or name is None or stix_id is None:
        return None

    return Technique(
        stix_id=stix_id,
        technique_id=technique_id,
        name=name,
        description=_clean_optional_string(item.get("description")),
        tactics=_kill_chain_phase_names(item.get("kill_chain_phases", [])),
        platforms=_string_list(item.get("x_mitre_platforms", [])),
        data_sources=_string_list(item.get("x_mitre_data_sources", [])),
        detection=_clean_optional_string(item.get("x_mitre_detection")),
        references=_external_references(item.get("external_references", [])),
        source_url=source_url,
        revoked=bool(item.get("revoked", False)),
        deprecated=bool(item.get("x_mitre_deprecated", False)),
        is_subtechnique=bool(item.get("x_mitre_is_subtechnique", False)),
    )


def _parse_mitigation(item: dict[str, Any]) -> dict[str, Any] | None:
    mitigation_id, source_url = _mitre_external_reference(item.get("external_references", []))
    name = _clean_optional_string(item.get("name"))
    if mitigation_id is None or name is None:
        return None

    return {
        "mitigation_id": mitigation_id,
        "name": name,
        "description": _clean_optional_string(item.get("description")),
        "source_url": source_url,
    }


def _apply_relationships(
    relationships: list[dict[str, Any]],
    techniques_by_stix_id: dict[str, Technique],
    mitigations_by_stix_id: dict[str, dict[str, Any]],
) -> None:
    for relationship in relationships:
        relationship_type = relationship.get("relationship_type")
        source_ref = relationship.get("source_ref")
        target_ref = relationship.get("target_ref")
        if not isinstance(source_ref, str) or not isinstance(target_ref, str):
            continue

        if relationship_type == "subtechnique-of":
            child = techniques_by_stix_id.get(source_ref)
            parent = techniques_by_stix_id.get(target_ref)
            if child is None or parent is None:
                continue
            child.parent_id = parent.technique_id
            if child.technique_id not in parent.subtechnique_ids:
                parent.subtechnique_ids.append(child.technique_id)
            continue

        if relationship_type == "mitigates":
            mitigation = mitigations_by_stix_id.get(source_ref)
            technique = techniques_by_stix_id.get(target_ref)
            if mitigation is not None and technique is not None:
                technique.mitigations.append(mitigation)

    for technique in techniques_by_stix_id.values():
        technique.subtechnique_ids.sort()
        technique.mitigations.sort(key=lambda item: item.get("mitigation_id") or "")


def _technique_detail(technique: Technique, knowledge: AttackKnowledge) -> dict[str, Any]:
    parent = None
    if technique.parent_id is not None:
        parent_technique = knowledge.techniques_by_id.get(technique.parent_id)
        if parent_technique is not None:
            parent = _technique_ref(parent_technique)

    return {
        **_technique_summary(technique, knowledge),
        "stix_id": technique.stix_id,
        "description": technique.description,
        "data_sources": technique.data_sources,
        "detection": technique.detection,
        # Trimmed to identity. The full prose for any one of these is a
        # lookup("M####") away, so nothing is lost and the common case stays
        # small. Nine full mitigation write-ups were 55% of this response.
        "mitigations": [_mitigation_ref(mitigation) for mitigation in technique.mitigations],
        "references": technique.references,
        "parent": parent,
        # Also trimmed to identity: each full summary re-embedded every tactic
        # object, so tactic descriptions repeated once per subtechnique. Call
        # lookup on a subtechnique id for its detail.
        "subtechniques": [
            _technique_ref(knowledge.techniques_by_id[subtechnique_id])
            for subtechnique_id in technique.subtechnique_ids
            if subtechnique_id in knowledge.techniques_by_id
        ],
        "snapshot_path": str(knowledge.path),
    }


def _technique_summary(technique: Technique, knowledge: AttackKnowledge) -> dict[str, Any]:
    return {
        "technique_id": technique.technique_id,
        "name": technique.name,
        # Tactic references, not full tactic objects. The description belongs on
        # the tactic you asked about, not repeated everywhere a tactic appears.
        "tactics": [_tactic_ref(tactic) for tactic in _technique_tactics(technique, knowledge)],
        "platforms": technique.platforms,
        "revoked": technique.revoked,
        "deprecated": technique.deprecated,
        "is_subtechnique": technique.is_subtechnique,
        "source_url": technique.source_url,
    }


def _tactic_data(tactic: Tactic) -> dict[str, Any]:
    """Full tactic, description included. Only for the tactic being asked about."""
    return {**_tactic_ref(tactic), "description": tactic.description}


def _tactic_ref(tactic: Tactic) -> dict[str, Any]:
    """Enough to identify a tactic and look it up, without its prose."""
    return {
        "tactic_id": tactic.tactic_id,
        "name": tactic.name,
        "short_name": tactic.short_name,
        "source_url": tactic.source_url,
    }


def _technique_ref(technique: Technique) -> dict[str, Any]:
    """Enough to identify a technique and look it up, without its detail."""
    return {"technique_id": technique.technique_id, "name": technique.name}


def _mitigation_ref(mitigation: dict[str, Any]) -> dict[str, Any]:
    """Enough to identify a mitigation and look it up, without its prose."""
    return {
        "mitigation_id": mitigation.get("mitigation_id"),
        "name": mitigation.get("name"),
        "source_url": mitigation.get("source_url"),
    }


def _technique_tactics(technique: Technique, knowledge: AttackKnowledge) -> list[Tactic]:
    return [
        knowledge.tactics_by_short_name[short_name]
        for short_name in technique.tactics
        if short_name in knowledge.tactics_by_short_name
    ]


def _search_techniques(
    knowledge: AttackKnowledge,
    query: str,
    limit: int,
) -> tuple[int, list[dict[str, Any]]]:
    """Return the total number of matches and the limited slice of them.

    The total is counted before the limit is applied, so a caller can tell
    10-of-11 from 10-of-400 instead of seeing a count that always equals the
    number of rows it was handed.
    """
    query_lower = query.lower()
    scored: list[tuple[int, Technique]] = []

    for technique in knowledge.techniques_by_id.values():
        score = _score_technique(technique, knowledge, query_lower)
        if score > 0:
            scored.append((score, technique))

    scored.sort(key=lambda item: (-item[0], item[1].technique_id))
    return len(scored), [
        {
            **_technique_summary(technique, knowledge),
            "score": score,
            "matched_context": _matched_context(technique, query_lower),
        }
        for score, technique in scored[:limit]
    ]


def _score_technique(technique: Technique, knowledge: AttackKnowledge, query: str) -> int:
    score = 0
    technique_id = technique.technique_id.lower()
    name = technique.name.lower()
    tactic_text = " ".join(
        f"{tactic.name} {tactic.short_name}" for tactic in _technique_tactics(technique, knowledge)
    ).lower()

    if technique_id == query:
        score += 100
    elif query in technique_id:
        score += 80
    if name == query:
        score += 60
    elif query in name:
        score += 40
    if query in tactic_text:
        score += 25
    if query in " ".join(technique.platforms).lower():
        score += 15
    if technique.detection and query in technique.detection.lower():
        score += 12
    if technique.description and query in technique.description.lower():
        score += 10
    if query in " ".join(technique.data_sources).lower():
        score += 10

    return score


def _matched_context(technique: Technique, query: str) -> str | None:
    for value in [technique.name, technique.detection, technique.description]:
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


def normalize_technique_id(value: str) -> str:
    """Normalize and validate an ATT&CK technique ID such as ``T1059`` or ``T1059.001``.

    Shared with the technique-brief tool so both agree on valid technique IDs.
    """
    technique_id = value.strip().upper()
    if not technique_id:
        raise InputValidationError("Technique ID must not be empty.")
    if not TECHNIQUE_ID_PATTERN.fullmatch(technique_id):
        raise InputValidationError("Technique ID must look like T1059 or T1059.001.")
    return technique_id


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


def _normalize_tactic_alias(value: str) -> str:
    tactic = value.strip()
    if not tactic:
        raise InputValidationError("Tactic must not be empty.")
    return _slug(tactic)


def _slug(value: str) -> str:
    return re.sub(r"[^a-z0-9]+", "-", value.strip().lower()).strip("-")


def _mitre_external_reference(references: object) -> tuple[str | None, str | None]:
    for reference in _reference_dicts(references):
        if reference.get("source_name") == "mitre-attack":
            return (
                _clean_optional_string(reference.get("external_id")),
                _clean_optional_string(reference.get("url")),
            )
    return None, None


def _external_references(references: object) -> list[dict[str, Any]]:
    results: list[dict[str, Any]] = []
    for reference in _reference_dicts(references):
        source_name = _clean_optional_string(reference.get("source_name"))
        external_id = _clean_optional_string(reference.get("external_id"))
        url = _clean_optional_string(reference.get("url"))
        description = _clean_optional_string(reference.get("description"))
        if source_name is None and url is None:
            continue
        results.append(
            {
                "source_name": source_name,
                "external_id": external_id,
                "url": url,
                "description": description,
            }
        )
    return results


def _reference_dicts(references: object) -> list[dict[str, Any]]:
    if not isinstance(references, list):
        return []
    return [reference for reference in references if isinstance(reference, dict)]


def _kill_chain_phase_names(phases: object) -> list[str]:
    if not isinstance(phases, list):
        return []
    names: list[str] = []
    for phase in phases:
        if not isinstance(phase, dict):
            continue
        if phase.get("kill_chain_name") != "mitre-attack":
            continue
        phase_name = _clean_optional_string(phase.get("phase_name"))
        if phase_name is not None:
            names.append(phase_name)
    return _unique_sorted(names)


def _string_list(value: object) -> list[str]:
    if not isinstance(value, list):
        return []
    return _unique_sorted(item.strip() for item in value if isinstance(item, str) and item.strip())


def _unique_sorted(values: object) -> list[str]:
    return sorted({value for value in values if isinstance(value, str) and value})


def _clean_optional_string(value: object) -> str | None:
    if not isinstance(value, str):
        return None
    cleaned = value.strip()
    return cleaned or None
