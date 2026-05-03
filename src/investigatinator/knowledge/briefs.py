"""Deterministic knowledge brief tools."""

from __future__ import annotations

from typing import Any

from investigatinator.enrichment.models import (
    InputValidationError,
    error_response,
    success_response,
)
from investigatinator.knowledge.attack import _normalize_technique_id
from investigatinator.knowledge.attack import attack_technique_lookup as run_attack_lookup
from investigatinator.knowledge.cve import _normalize_cve_id
from investigatinator.knowledge.cve import cve_lookup as run_cve_lookup
from investigatinator.knowledge.d3fend import attack_defense_mapping as run_defense_mapping
from investigatinator.knowledge.kev import kev_lookup as run_kev_lookup
from investigatinator.knowledge.lolbas import lolbas_search as run_lolbas_search

TECHNIQUE_BRIEF_TOOL = "technique_brief"
VULNERABILITY_BRIEF_TOOL = "vulnerability_brief"


def technique_brief(technique_id: str) -> dict[str, Any]:
    """Build a compact defensive knowledge bundle for one ATT&CK technique."""
    query = {"technique_id": technique_id}

    try:
        normalized_id = _normalize_technique_id(technique_id)
    except InputValidationError as exc:
        return error_response(TECHNIQUE_BRIEF_TOOL, query, "invalid_input", str(exc))

    query["technique_id"] = normalized_id
    attack_result = run_attack_lookup(normalized_id)
    if attack_result.get("ok") is not True or not isinstance(attack_result.get("data"), dict):
        return _primary_source_error(query, attack_result)

    source_results: dict[str, str] = {"attack": "ok"}
    source_errors: list[dict[str, Any]] = []
    defense_result = run_defense_mapping(normalized_id)
    lolbas_result = run_lolbas_search(normalized_id, limit=10)

    defensive_mappings = _optional_data(
        "d3fend",
        defense_result,
        source_results,
        source_errors,
    ).get("defensive_techniques", [])
    related_lolbas = _optional_data(
        "lolbas",
        lolbas_result,
        source_results,
        source_errors,
    ).get("matches", [])

    technique = attack_result["data"]
    return success_response(
        TECHNIQUE_BRIEF_TOOL,
        query,
        {
            "technique": technique,
            "defensive_mappings": defensive_mappings,
            "related_lolbas": related_lolbas,
            "key_points": _key_points(technique, defensive_mappings, related_lolbas),
            "source_results": source_results,
            "source_errors": source_errors,
        },
    )


def vulnerability_brief(cve_id: str) -> dict[str, Any]:
    """Build a compact vulnerability knowledge bundle for one CVE."""
    query = {"cve_id": cve_id}

    try:
        normalized_cve = _normalize_cve_id(cve_id)
    except InputValidationError as exc:
        return error_response(VULNERABILITY_BRIEF_TOOL, query, "invalid_input", str(exc))

    query["cve_id"] = normalized_cve
    source_results: dict[str, str] = {}
    source_errors: list[dict[str, Any]] = []
    cve_data = _optional_data(
        "nvd",
        run_cve_lookup(normalized_cve),
        source_results,
        source_errors,
    )
    kev_data = _optional_data(
        "kev",
        run_kev_lookup(normalized_cve),
        source_results,
        source_errors,
    )

    if not cve_data and not kev_data:
        return error_response(
            VULNERABILITY_BRIEF_TOOL,
            query,
            "upstream_error",
            "Both NVD CVE and CISA KEV lookups failed or found no data.",
            {"source_results": source_results, "source_errors": source_errors},
        )

    in_kev = _kev_status(source_results, kev_data)
    return success_response(
        VULNERABILITY_BRIEF_TOOL,
        query,
        {
            "cve_id": normalized_cve,
            "nvd": cve_data or None,
            "kev": kev_data.get("vulnerability") if kev_data else None,
            "in_kev": in_kev,
            "key_points": _vulnerability_key_points(normalized_cve, cve_data, kev_data, in_kev),
            "source_results": source_results,
            "source_errors": source_errors,
        },
    )


def _primary_source_error(query: dict[str, Any], result: dict[str, Any]) -> dict[str, Any]:
    error = result.get("error") if isinstance(result.get("error"), dict) else {}
    return error_response(
        TECHNIQUE_BRIEF_TOOL,
        query,
        error.get("code", "upstream_error"),
        error.get("message", "ATT&CK technique lookup failed."),
        error.get("details"),
    )


def _optional_data(
    source: str,
    result: dict[str, Any],
    source_results: dict[str, str],
    source_errors: list[dict[str, Any]],
) -> dict[str, Any]:
    if result.get("ok") is True and isinstance(result.get("data"), dict):
        source_results[source] = "ok"
        return result["data"]

    error = result.get("error") if isinstance(result.get("error"), dict) else {}
    code = error.get("code", "unexpected_error")
    if code == "not_found":
        source_results[source] = "not_found"
        return {}

    source_results[source] = "error"
    source_errors.append(
        {
            "source": source,
            "code": code,
            "message": error.get("message", "Knowledge source lookup failed."),
            "details": error.get("details"),
        }
    )
    return {}


def _key_points(
    technique: dict[str, Any],
    defensive_mappings: object,
    related_lolbas: object,
) -> list[str]:
    points: list[str] = []
    technique_id = technique.get("technique_id", "unknown")
    name = technique.get("name", "unknown")
    points.append(f"{technique_id} is {name}.")

    tactics = technique.get("tactics")
    if isinstance(tactics, list) and tactics:
        tactic_names = [
            item.get("name") for item in tactics if isinstance(item, dict) and item.get("name")
        ]
        if tactic_names:
            points.append(f"ATT&CK tactics: {', '.join(tactic_names[:5])}.")

    if isinstance(defensive_mappings, list) and defensive_mappings:
        names = [
            item.get("name")
            for item in defensive_mappings
            if isinstance(item, dict) and item.get("name")
        ]
        if names:
            points.append(f"D3FEND defensive mappings include: {', '.join(names[:5])}.")

    if isinstance(related_lolbas, list) and related_lolbas:
        names = [
            item.get("name")
            for item in related_lolbas
            if isinstance(item, dict) and item.get("name")
        ]
        if names:
            points.append(f"Related LOLBAS entries include: {', '.join(names[:5])}.")

    if not points:
        points.append("No local knowledge summary points were generated.")
    return points


def _kev_status(source_results: dict[str, str], kev_data: dict[str, Any]) -> bool | str:
    if source_results.get("kev") == "ok":
        return True
    if source_results.get("kev") == "not_found":
        return False
    return "unknown"


def _vulnerability_key_points(
    cve_id: str,
    cve_data: dict[str, Any],
    kev_data: dict[str, Any],
    in_kev: bool | str,
) -> list[str]:
    points = [f"{cve_id} vulnerability context was collected."]

    cvss = cve_data.get("cvss") if cve_data else None
    if isinstance(cvss, dict):
        severity = cvss.get("base_severity")
        score = cvss.get("base_score")
        if severity is not None and score is not None:
            points.append(f"NVD CVSS severity is {severity} with base score {score}.")

    status = cve_data.get("vuln_status") if cve_data else None
    if status:
        points.append(f"NVD status is {status}.")

    if in_kev is True:
        vulnerability = kev_data.get("vulnerability", {}) if kev_data else {}
        if isinstance(vulnerability, dict):
            name = vulnerability.get("vulnerability_name")
            due_date = vulnerability.get("due_date")
            ransomware = vulnerability.get("known_ransomware_campaign_use")
            if name:
                points.append(f"CISA KEV lists this as {name}.")
            if due_date:
                points.append(f"CISA KEV due date is {due_date}.")
            if ransomware:
                points.append(f"CISA ransomware campaign use is {ransomware}.")
    elif in_kev is False:
        points.append("This CVE was not found in the local CISA KEV catalog.")
    else:
        points.append("CISA KEV status is unknown because the KEV lookup did not complete.")

    return points
