"""Hybrid Analysis (Falcon Sandbox) detonation reports for a file hash.

The hash lane had only VirusTotal and OTX, and both answer the same question:
how many parties call this bad. Hybrid Analysis answers a different one — what
the sample did when it ran. Processes started, hosts contacted, files dropped.

The part worth the integration is ``mitre_attcks``. Falcon Sandbox maps observed
behaviour onto ATT&CK technique IDs, and this project already resolves technique
IDs locally, so the technique IDs collected here hand straight to ``lookup``
with no further network call. That is why the distinct IDs are lifted to the top
of the response instead of being left buried in a report.

Two requests, because the API splits the answer in half. ``/search/hash`` takes
any hash type and returns one lean stub per sandbox environment — an id, the
environment, and whether the run succeeded — and nothing about behaviour. The
behaviour, and ``mitre_attcks`` with it, lives on ``/report/{id}/summary``. So
this resolves the hash to a run that actually completed and then fetches that
one run. A sample can have hundreds of stubs (EICAR has over six hundred), so
picking one and fetching it is also what keeps the response bounded.

The second request is best-effort: if it fails, the environment list from the
first still comes back, because knowing a sample was detonated ten times and
called malicious is worth more than an error.

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
    parse_json_object,
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

# A widely-submitted sample has hundreds of environment stubs. They are small,
# but they are also repetitive, so a slice plus the true total is the useful
# form. EICAR returns over 600.
MAX_ENVIRONMENTS = 10

# Network observables can run to hundreds on a real sample. Bounded, with the
# report's own total beside them, so a caller can see it is looking at a slice.
MAX_NETWORK_ENTRIES = 25

# The state Falcon Sandbox gives a run that completed. Anything else (ERROR,
# IN_QUEUE, IN_PROGRESS) has no behaviour to report, so it is not worth
# spending the second request on.
COMPLETED_STATE = "SUCCESS"

ENVIRONMENT_FIELDS = (
    "environment_id",
    "environment_description",
    "state",
    "verdict",
    "error_type",
)

DETAIL_FIELDS = (
    "job_id",
    "environment_id",
    "environment_description",
    "state",
    "verdict",
    "threat_score",
    "threat_level",
    "av_detect",
    "vx_family",
    "classification_tags",
    "tags",
    "type",
    "type_short",
    "size",
    "md5",
    "sha256",
    "imphash",
    "ssdeep",
    "total_processes",
    "total_network_connections",
    "total_signatures",
)

# Lists whose length is the useful part; the contents are bulk that belongs to
# the full report rather than to a triage answer.
COUNTED_LISTS = ("processes", "signatures", "extracted_files")

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

    headers = _headers(api_key)
    search = _get(
        query,
        f"{get_hybrid_analysis_base_url()}/search/hash",
        headers,
        params={"hash": normalized_hash},
    )
    if search.get("error"):
        return search["error"]

    payload = search["payload"]
    stubs = payload.get("reports")
    stubs = stubs if isinstance(stubs, list) else []
    sha256s = [value for value in (payload.get("sha256s") or []) if isinstance(value, str)]

    detail, detail_error = _detail(query, headers, stubs)

    data: dict[str, Any] = {
        "hash": normalized_hash,
        "sha256": sha256s[0] if sha256s else None,
        # Every environment the sample was run in, which is the count of runs
        # rather than the count of distinct results.
        "report_count": len(stubs),
        "completed_report_count": sum(1 for stub in stubs if _state(stub) == COMPLETED_STATE),
        "environments": [_environment(stub) for stub in stubs[:MAX_ENVIRONMENTS]],
        "report": detail,
        "attack_technique_ids": _distinct_attack_ids(detail),
        "source": "hybrid_analysis",
        "source_url": "https://www.hybrid-analysis.com/",
        "note": (
            "Existing sandbox reports only; nothing was submitted for detonation. "
            "Hybrid Analysis covers samples someone submitted to it, so no report "
            "is common and is not evidence the file is safe."
        ),
    }
    if detail_error:
        # Reported rather than raised: the environment list is still worth
        # returning, and a caller should see which half was unavailable.
        data["report_unavailable"] = detail_error

    return success_response(TOOL_NAME, query, data)


def _headers(api_key: str) -> dict[str, str]:
    return {"Accept": "application/json", "User-Agent": USER_AGENT, "api-key": api_key}


def _get(
    query: dict[str, Any],
    url: str,
    headers: dict[str, str],
    params: dict[str, Any] | None = None,
) -> dict[str, Any]:
    """Run one request and return a parsed object or a ready error envelope.

    Redirects are deliberately not followed. The API key travels in a custom
    header, and httpx strips ``auth=`` across hosts but not custom headers, so
    chasing a redirect could hand the key to whatever the Location names.
    """
    result = guarded_get(
        TOOL_NAME,
        query,
        PROVIDER,
        lambda: httpx.get(url, params=params, headers=headers, timeout=get_timeout_seconds()),
    )
    if result.error:
        return {"error": result.error}

    auth_error = auth_or_rate_error(TOOL_NAME, query, PROVIDER, result.response)
    if auth_error:
        return {"error": auth_error}

    # An unknown hash is a 404 rather than an empty body. That is a normal
    # outcome for a provider holding only what was submitted to it.
    if result.response.status_code == 404:
        return {"payload": {}}

    parsed = parse_json_object(TOOL_NAME, query, PROVIDER, result.response)
    if parsed.error:
        return {"error": parsed.error}
    return {"payload": parsed.payload}


def _detail(
    query: dict[str, Any],
    headers: dict[str, str],
    stubs: list[Any],
) -> tuple[dict[str, Any] | None, str | None]:
    """Fetch the one completed run that carries behaviour and ATT&CK mappings."""
    completed = next(
        (stub for stub in stubs if isinstance(stub, dict) and _state(stub) == COMPLETED_STATE),
        None,
    )
    if completed is None:
        if stubs:
            return None, "No sandbox run completed, so no behaviour detail is available."
        return None, None

    job_id = completed.get("id") or completed.get("job_id")
    if not isinstance(job_id, str):
        return None, "A completed run carried no report id."

    url = f"{get_hybrid_analysis_base_url()}/report/{job_id}/summary"
    result = _get(query, url, headers)
    if result.get("error"):
        return (
            None,
            f"The behaviour report could not be fetched: {result['error']['error']['code']}",
        )

    return _report(result["payload"]), None


def _state(stub: Any) -> str | None:
    return stub.get("state") if isinstance(stub, dict) else None


def _environment(stub: Any) -> dict[str, Any]:
    """One sandbox run reduced to which environment it was and how it ended."""
    if not isinstance(stub, dict):
        return {}
    environment = {field: stub[field] for field in ENVIRONMENT_FIELDS if field in stub}
    environment["report_id"] = stub.get("id") or stub.get("job_id")
    return {key: value for key, value in environment.items() if value is not None}


def _report(payload: dict[str, Any]) -> dict[str, Any]:
    """Reduce one detonation report to its verdict fields and behaviour summary."""
    report = {field: payload[field] for field in DETAIL_FIELDS if field in payload}
    for field in COUNTED_LISTS:
        value = payload.get(field)
        if isinstance(value, list) and value:
            report[f"{field}_count"] = len(value)
    report["mitre_attcks"] = _attack_mappings(payload.get("mitre_attcks"))
    report["network"] = _network(payload)
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


def _network(payload: dict[str, Any]) -> dict[str, Any]:
    """Bounded network observables, each beside its own untruncated count."""
    network: dict[str, Any] = {}
    for field in ("domains", "hosts", "compromised_hosts"):
        values = payload.get(field)
        if not isinstance(values, list) or not values:
            continue
        network[field] = values[:MAX_NETWORK_ENTRIES]
        network[f"{field}_count"] = len(values)
    return network


def _distinct_attack_ids(report: dict[str, Any] | None) -> list[str]:
    """Every ATT&CK technique ID in the report, de-duplicated and sorted."""
    if not report:
        return []
    ids = {
        mapping["attck_id"]
        for mapping in report.get("mitre_attcks", [])
        if isinstance(mapping.get("attck_id"), str)
    }
    return sorted(ids)
