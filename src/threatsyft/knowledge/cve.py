"""Targeted NVD CVE lookup for vulnerability context."""

from __future__ import annotations

import re
from typing import Any

import httpx

from threatsyft.config import get_api_key, get_nvd_base_url, get_timeout_seconds
from threatsyft.core import (
    InputValidationError,
    error_response,
    success_response,
)

TOOL_NAME = "cve_lookup"
API_KEY_NAME = "NVD_API_KEY"
CVE_ID_PATTERN = re.compile(r"^CVE-\d{4}-\d{4,}$", re.IGNORECASE)


def cve_lookup(cve_id: str) -> dict[str, Any]:
    """Look up one CVE using the NVD CVE API."""
    query = {"cve_id": cve_id}

    try:
        normalized_cve = normalize_cve_id(cve_id)
    except InputValidationError as exc:
        return error_response(TOOL_NAME, query, "invalid_input", str(exc))

    query["cve_id"] = normalized_cve
    headers = {"Accept": "application/json"}
    api_key = get_api_key(API_KEY_NAME)
    if api_key is not None:
        headers["apiKey"] = api_key

    try:
        response = httpx.get(
            get_nvd_base_url(),
            params={"cveId": normalized_cve},
            headers=headers,
            timeout=get_timeout_seconds(),
        )
        if response.status_code in {401, 403}:
            return error_response(
                TOOL_NAME,
                query,
                "authentication_error",
                "NVD rejected the configured API key.",
                {"status_code": response.status_code},
            )
        if response.status_code == 429:
            return error_response(
                TOOL_NAME,
                query,
                "rate_limited",
                "NVD rate limit was reached.",
                {"status_code": response.status_code},
            )
        response.raise_for_status()
        payload = response.json()
    except httpx.TimeoutException:
        return error_response(TOOL_NAME, query, "timeout", "NVD CVE lookup timed out.")
    except httpx.HTTPStatusError as exc:
        return error_response(
            TOOL_NAME,
            query,
            "upstream_error",
            "NVD returned an unexpected error.",
            {"status_code": exc.response.status_code},
        )
    except httpx.RequestError as exc:
        return error_response(TOOL_NAME, query, "network_error", "NVD CVE lookup failed.", str(exc))
    except ValueError as exc:
        return error_response(
            TOOL_NAME,
            query,
            "parse_error",
            "NVD response was not JSON.",
            str(exc),
        )

    if not isinstance(payload, dict):
        return error_response(TOOL_NAME, query, "parse_error", "NVD response was not an object.")

    vulnerabilities = payload.get("vulnerabilities")
    if not isinstance(vulnerabilities, list):
        return error_response(
            TOOL_NAME,
            query,
            "parse_error",
            "NVD response did not contain a vulnerabilities list.",
        )
    if not vulnerabilities:
        return error_response(
            TOOL_NAME,
            query,
            "not_found",
            f"{normalized_cve} was not found in NVD.",
        )

    vulnerability = vulnerabilities[0]
    cve = vulnerability.get("cve") if isinstance(vulnerability, dict) else None
    if not isinstance(cve, dict):
        return error_response(TOOL_NAME, query, "parse_error", "NVD CVE item was malformed.")

    return success_response(
        TOOL_NAME,
        query,
        {
            "cve_id": cve.get("id") or normalized_cve,
            "source_identifier": cve.get("sourceIdentifier"),
            "published": cve.get("published"),
            "last_modified": cve.get("lastModified"),
            "vuln_status": cve.get("vulnStatus"),
            "description": _english_description(cve.get("descriptions")),
            "cvss": _best_cvss_metric(cve.get("metrics")),
            "weaknesses": _weaknesses(cve.get("weaknesses")),
            "references": _references(cve.get("references")),
            "cisa": _cisa_fields(cve),
            "affected_cpes": _affected_cpes(cve.get("configurations")),
            "source": "nvd",
            "source_url": f"https://nvd.nist.gov/vuln/detail/{normalized_cve}",
        },
    )


def normalize_cve_id(value: str) -> str:
    """Normalize and validate a CVE ID such as ``CVE-2024-12345``.

    Shared by the NVD, KEV, and vulnerability-brief tools so they agree on what a
    valid CVE ID is.
    """
    cve_id = value.strip().upper()
    if not cve_id:
        raise InputValidationError("CVE ID must not be empty.")
    if CVE_ID_PATTERN.fullmatch(cve_id) is None:
        raise InputValidationError("CVE ID must look like CVE-2024-12345.")
    return cve_id


def _english_description(value: object) -> str | None:
    if not isinstance(value, list):
        return None
    for item in value:
        if (
            isinstance(item, dict)
            and item.get("lang") == "en"
            and isinstance(item.get("value"), str)
        ):
            return item["value"]
    return None


def _best_cvss_metric(metrics: object) -> dict[str, Any] | None:
    if not isinstance(metrics, dict):
        return None
    for key in ["cvssMetricV40", "cvssMetricV31", "cvssMetricV30", "cvssMetricV2"]:
        metric = _preferred_metric(metrics.get(key))
        if metric is not None:
            return metric
    return None


def _preferred_metric(value: object) -> dict[str, Any] | None:
    if not isinstance(value, list) or not value:
        return None

    metric = next(
        (item for item in value if isinstance(item, dict) and item.get("type") == "Primary"),
        None,
    )
    if metric is None:
        metric = next((item for item in value if isinstance(item, dict)), None)
    if not isinstance(metric, dict):
        return None

    data = metric.get("cvssData")
    if not isinstance(data, dict):
        return None

    return {
        "version": data.get("version"),
        "vector_string": data.get("vectorString"),
        "base_score": data.get("baseScore"),
        "base_severity": data.get("baseSeverity") or metric.get("baseSeverity"),
        "source": metric.get("source"),
        "type": metric.get("type"),
        "exploitability_score": metric.get("exploitabilityScore"),
        "impact_score": metric.get("impactScore"),
    }


def _weaknesses(value: object) -> list[str]:
    if not isinstance(value, list):
        return []
    weaknesses: set[str] = set()
    for item in value:
        if not isinstance(item, dict):
            continue
        descriptions = item.get("description")
        if not isinstance(descriptions, list):
            continue
        for description in descriptions:
            weakness = description.get("value") if isinstance(description, dict) else None
            if isinstance(weakness, str) and weakness:
                weaknesses.add(weakness)
    return sorted(weaknesses)


def _references(value: object) -> list[dict[str, Any]]:
    if not isinstance(value, list):
        return []
    references: list[dict[str, Any]] = []
    for item in value[:25]:
        if not isinstance(item, dict):
            continue
        references.append(
            {
                "url": item.get("url"),
                "source": item.get("source"),
                "tags": _sorted_strings(item.get("tags")),
            }
        )
    return references


def _cisa_fields(cve: dict[str, Any]) -> dict[str, Any]:
    return {
        "exploit_add": cve.get("cisaExploitAdd"),
        "action_due": cve.get("cisaActionDue"),
        "required_action": cve.get("cisaRequiredAction"),
        "vulnerability_name": cve.get("cisaVulnerabilityName"),
    }


def _affected_cpes(value: object) -> list[str]:
    if not isinstance(value, list):
        return []
    cpes: set[str] = set()
    for configuration in value:
        if not isinstance(configuration, dict):
            continue
        _collect_cpes(configuration.get("nodes"), cpes)
    return sorted(cpes)[:25]


def _collect_cpes(nodes: object, cpes: set[str]) -> None:
    if not isinstance(nodes, list):
        return
    for node in nodes:
        if not isinstance(node, dict):
            continue
        matches = node.get("cpeMatch")
        if isinstance(matches, list):
            for item in matches:
                if not isinstance(item, dict) or item.get("vulnerable") is not True:
                    continue
                criteria = item.get("criteria")
                if isinstance(criteria, str):
                    cpes.add(criteria)
        _collect_cpes(node.get("nodes"), cpes)


def _sorted_strings(value: object) -> list[str]:
    if not isinstance(value, list):
        return []
    return sorted({item for item in value if isinstance(item, str)})
