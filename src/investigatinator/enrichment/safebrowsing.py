"""Google Safe Browsing URL lookups."""

from __future__ import annotations

from typing import Any

import httpx

from investigatinator.config import (
    get_api_key,
    get_google_safebrowsing_base_url,
    get_timeout_seconds,
)
from investigatinator.enrichment.models import (
    InputValidationError,
    error_response,
    normalize_url,
    success_response,
)

TOOL_NAME = "google_safebrowsing_check_url"
API_KEY_NAME = "GOOGLE_SAFEBROWSING_API_KEY"


def google_safebrowsing_check_url(url: str) -> dict[str, Any]:
    """Check one URL against Google Safe Browsing threat lists."""
    query = {"url": url}

    try:
        normalized_url = normalize_url(url)
    except InputValidationError as exc:
        return error_response(TOOL_NAME, query, "invalid_input", str(exc))

    query["url"] = normalized_url
    api_key = get_api_key(API_KEY_NAME)
    if api_key is None:
        return error_response(
            TOOL_NAME,
            query,
            "missing_api_key",
            f"{API_KEY_NAME} is not configured.",
        )

    request_url = f"{get_google_safebrowsing_base_url()}/v4/threatMatches:find"
    params = {"key": api_key}
    body = {
        "client": {
            "clientId": "investigatinator",
            "clientVersion": "1.0",
        },
        "threatInfo": {
            "threatTypes": [
                "MALWARE",
                "SOCIAL_ENGINEERING",
                "UNWANTED_SOFTWARE",
                "POTENTIALLY_HARMFUL_APPLICATION",
            ],
            "platformTypes": ["ANY_PLATFORM"],
            "threatEntryTypes": ["URL"],
            "threatEntries": [{"url": normalized_url}],
        },
    }

    try:
        response = httpx.post(request_url, params=params, json=body, timeout=get_timeout_seconds())
        if response.status_code in {401, 403}:
            return error_response(
                TOOL_NAME,
                query,
                "authentication_error",
                "Google Safe Browsing rejected the configured API key.",
                {"status_code": response.status_code},
            )
        if response.status_code == 429:
            return error_response(
                TOOL_NAME,
                query,
                "rate_limited",
                "Google Safe Browsing rate limit was reached.",
                {"status_code": response.status_code},
            )
        if response.status_code == 404:
            return error_response(
                TOOL_NAME,
                query,
                "not_found",
                "Google Safe Browsing endpoint was not found.",
            )
        response.raise_for_status()
        payload = response.json()
    except httpx.TimeoutException:
        return error_response(TOOL_NAME, query, "timeout", "Google Safe Browsing lookup timed out.")
    except httpx.HTTPStatusError as exc:
        return error_response(
            TOOL_NAME,
            query,
            "upstream_error",
            "Google Safe Browsing returned an unexpected error.",
            {"status_code": exc.response.status_code},
        )
    except httpx.RequestError as exc:
        return error_response(
            TOOL_NAME,
            query,
            "network_error",
            "Google Safe Browsing lookup failed.",
            str(exc),
        )
    except ValueError as exc:
        return error_response(
            TOOL_NAME,
            query,
            "parse_error",
            "Google Safe Browsing response was not JSON.",
            str(exc),
        )

    if not isinstance(payload, dict):
        return error_response(
            TOOL_NAME,
            query,
            "parse_error",
            "Google Safe Browsing response was not an object.",
        )

    matches = payload.get("matches", [])
    if matches is None:
        matches = []
    if not isinstance(matches, list):
        return error_response(
            TOOL_NAME,
            query,
            "parse_error",
            "Google Safe Browsing matches field was not a list.",
        )

    compact_matches = _compact_matches(matches)
    return success_response(
        TOOL_NAME,
        query,
        {
            "url": normalized_url,
            "matched": bool(compact_matches),
            "matches": compact_matches,
            "verdict": "malicious" if compact_matches else "benign",
            "source": "google_safebrowsing",
            "source_url": "https://developers.google.com/safe-browsing/v4/lookup-api",
            "note": (
                "No match means the URL was not found on checked Safe Browsing lists; "
                "it is not proof of safety."
            ),
        },
    )


def _compact_matches(matches: list[object]) -> list[dict[str, Any]]:
    compact: list[dict[str, Any]] = []
    for item in matches:
        if not isinstance(item, dict):
            continue
        threat = item.get("threat") if isinstance(item.get("threat"), dict) else {}
        compact.append(
            {
                key: value
                for key, value in {
                    "threat_type": item.get("threatType"),
                    "platform_type": item.get("platformType"),
                    "threat_entry_type": item.get("threatEntryType"),
                    "url": threat.get("url") if isinstance(threat, dict) else None,
                    "cache_duration": item.get("cacheDuration"),
                    "metadata": _metadata_dict(item.get("threatEntryMetadata")),
                }.items()
                if value not in (None, {})
            }
        )
    return compact


def _metadata_dict(value: object) -> dict[str, str]:
    if not isinstance(value, dict):
        return {}
    entries = value.get("entries")
    if not isinstance(entries, list):
        return {}

    metadata: dict[str, str] = {}
    for item in entries:
        if not isinstance(item, dict):
            continue
        key = item.get("key")
        metadata_value = item.get("value")
        if isinstance(key, str) and isinstance(metadata_value, str):
            metadata[key] = metadata_value
    return metadata
