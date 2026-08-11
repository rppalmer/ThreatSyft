"""Hybrid Analysis (Falcon Sandbox) detonation reports for a file hash.

The hash lane had only VirusTotal and OTX, and both answer the same question:
how many parties call this bad. Hybrid Analysis answers a different one — what
the sample did when it ran. Processes started, hosts contacted, files dropped.

The part worth the integration is ``mitre_attcks``. Falcon Sandbox maps observed
behaviour onto ATT&CK technique IDs, and this project already resolves technique
IDs locally, so the technique IDs collected here hand straight to ``lookup``
with no further network call. That is why the distinct IDs are lifted to the top
of the response instead of being left buried per report.

Reads existing reports only. The submission endpoints detonate a sample and are
not reachable from here, for the same reason urlscan submission is not: an
``enrich`` fan-out must not take an active action on the caller's behalf.

Note on ``verdict`` and ``threat_score``: these are Falcon Sandbox's own fields,
passed through unchanged. That is collection, not the locally-computed per-source
verdict this project deliberately removed.
"""

from __future__ import annotations

from typing import Any

import httpx

from threatsyft.config import (
    get_api_key,
    get_hybrid_analysis_base_url,
    get_timeout_seconds,
)
from threatsyft.enrichment.http import (
    auth_or_rate_error,
    guarded_get,
    parse_json_array,
)
from threatsyft.enrichment.models import (
    InputValidationError,
    error_response,
    normalize_file_hash,
    success_response,
)

TOOL_NAME = "hybrid_analysis_hash_lookup"
API_KEY_NAME = "HYBRID_ANALYSIS_API_KEY"
PROVIDER = "Hybrid Analysis"

# Falcon Sandbox rejects requests that do not identify themselves this way. It
# is a fixed protocol requirement, not a courtesy string, so it is not derived
# from the package name.
USER_AGENT = "Falcon Sandbox"

# One report per sandbox environment the sample was run in. A handful is normal;
# the bound is here so a heavily-analysed sample cannot flood the response.
MAX_REPORTS = 10

# Network observables can run to hundreds per report. Bounded, with the report's
# own total beside them, so a caller can see it is looking at a slice.
MAX_NETWORK_ENTRIES = 25

REPORT_FIELDS = (
    "job_id",
    "environment_id",
    "environment_description",
    "submit_name",
    "type",
    "size",
    "verdict",
    "threat_score",
    "threat_level",
    "av_detect",
    "vx_family",
    "classification_tags",
    "tags",
    "total_processes",
    "total_network_connections",
    "total_signatures",
)

# Trimmed to what identifies the technique. The identifier lists behind each
# entry are evidence for the mapping, not the mapping, and they are the bulk of
# the field.
ATTACK_FIELDS = ("attck_id", "tactic", "technique")


def hybrid_analysis_hash_lookup(file_hash: str) -> dict[str, Any]:
    """Look up existing Falcon Sandbox detonation reports for one file hash."""
    query = {"hash": file_hash}

    try:
        normalized_hash = normalize_file_hash(file_hash)
    except InputValidationError as exc:
        return error_response(TOOL_NAME, query, "invalid_input", str(exc))

    query["hash"] = normalized_hash
    api_key = get_api_key(API_KEY_NAME)
    if api_key is None:
        return error_response(
            TOOL_NAME,
            query,
            "missing_api_key",
            f"{API_KEY_NAME} is not configured.",
        )

    url = f"{get_hybrid_analysis_base_url()}/search/hash"
    headers = {
        "Accept": "application/json",
        "User-Agent": USER_AGENT,
        "api-key": api_key,
    }
    params = {"hash": normalized_hash}

    result = guarded_get(
        TOOL_NAME,
        query,
        PROVIDER,
        lambda: httpx.get(url, params=params, headers=headers, timeout=get_timeout_seconds()),
    )
    if result.error:
        return result.error
    response = result.response

    auth_error = auth_or_rate_error(TOOL_NAME, query, PROVIDER, response)
    if auth_error:
        return auth_error

    # An unknown hash comes back as 404 rather than an empty array. That is a
    # normal outcome for a provider that only holds what was submitted to it, so
    # it becomes zero reports rather than a not_found error.
    if response.status_code == 404:
        found = []
    else:
        parsed = parse_json_array(TOOL_NAME, query, PROVIDER, response)
        if parsed.error:
            return parsed.error
        found = parsed.payload

    reports = [_report(entry) for entry in found[:MAX_REPORTS]]
    return success_response(
        TOOL_NAME,
        query,
        {
            "hash": normalized_hash,
            "report_count": len(found),
            "reports": reports,
            # Lifted out of the per-report mappings and de-duplicated because
            # this is the field that feeds `lookup`, and a caller should not
            # have to walk every environment's report to assemble it.
            "attack_technique_ids": _distinct_attack_ids(reports),
            "source": "hybrid_analysis",
            "source_url": "https://www.hybrid-analysis.com/",
            "note": (
                "Existing sandbox reports only; nothing was submitted for detonation. "
                "Hybrid Analysis covers samples someone submitted to it, so no report "
                "is common and is not evidence the file is safe."
            ),
        },
    )


def _report(entry: Any) -> dict[str, Any]:
    """Reduce one detonation report to its verdict fields and behaviour summary."""
    if not isinstance(entry, dict):
        return {}

    report = {field: entry[field] for field in REPORT_FIELDS if field in entry}
    report["mitre_attcks"] = _attack_mappings(entry.get("mitre_attcks"))
    report["network"] = _network(entry)
    return {key: value for key, value in report.items() if value not in (None, {}, [])}


def _attack_mappings(value: Any) -> list[dict[str, Any]]:
    if not isinstance(value, list):
        return []
    mappings = [
        {field: item[field] for field in ATTACK_FIELDS if field in item}
        for item in value
        if isinstance(item, dict)
    ]
    return [mapping for mapping in mappings if mapping]


def _network(entry: dict[str, Any]) -> dict[str, Any]:
    """Bounded network observables, each beside its own untruncated count."""
    network: dict[str, Any] = {}
    for field in ("domains", "hosts", "compromised_hosts"):
        values = entry.get(field)
        if not isinstance(values, list) or not values:
            continue
        network[field] = values[:MAX_NETWORK_ENTRIES]
        network[f"{field}_count"] = len(values)
    return network


def _distinct_attack_ids(reports: list[dict[str, Any]]) -> list[str]:
    """Every ATT&CK technique ID across all reports, de-duplicated and sorted."""
    ids = {
        mapping["attck_id"]
        for report in reports
        for mapping in report.get("mitre_attcks", [])
        if isinstance(mapping.get("attck_id"), str)
    }
    return sorted(ids)
