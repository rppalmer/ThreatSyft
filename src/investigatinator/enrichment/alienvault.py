"""AlienVault OTX indicator enrichment lookups."""

from __future__ import annotations

import ipaddress
from typing import Any
from urllib.parse import quote

import httpx

from investigatinator.config import get_alienvault_base_url, get_api_key, get_timeout_seconds
from investigatinator.enrichment.models import (
    InputValidationError,
    error_response,
    is_file_hash,
    normalize_domain,
    normalize_file_hash,
    normalize_url,
    success_response,
)

TOOL_NAME = "alienvault_indicator_lookup"
API_KEY_NAME = "ALIENVAULT_API_KEY"


def alienvault_indicator_lookup(indicator: str) -> dict[str, Any]:
    """Fetch compact AlienVault OTX context for one IP, domain, URL, or file hash."""
    query = {"indicator": indicator}

    try:
        indicator_type, normalized_indicator = _classify_indicator(indicator)
    except InputValidationError as exc:
        return error_response(TOOL_NAME, query, "invalid_input", str(exc))

    query["indicator"] = normalized_indicator
    query["indicator_type"] = indicator_type
    api_key = get_api_key(API_KEY_NAME)
    if api_key is None:
        return error_response(
            TOOL_NAME,
            query,
            "missing_api_key",
            f"{API_KEY_NAME} is not configured.",
        )

    quoted_indicator = quote(normalized_indicator, safe="")
    url = f"{get_alienvault_base_url()}/indicators/{indicator_type}/{quoted_indicator}/general"
    headers = {"Accept": "application/json", "X-OTX-API-KEY": api_key}

    try:
        response = httpx.get(url, headers=headers, timeout=get_timeout_seconds())
        if response.status_code in {401, 403}:
            return error_response(
                TOOL_NAME,
                query,
                "authentication_error",
                "AlienVault OTX rejected the configured API key.",
                {"status_code": response.status_code},
            )
        if response.status_code == 429:
            return error_response(
                TOOL_NAME,
                query,
                "rate_limited",
                "AlienVault OTX rate limit was reached.",
                {"status_code": response.status_code},
            )
        if response.status_code == 404:
            return error_response(
                TOOL_NAME,
                query,
                "not_found",
                "AlienVault OTX did not find context for this indicator.",
            )
        response.raise_for_status()
        payload = response.json()
    except httpx.TimeoutException:
        return error_response(TOOL_NAME, query, "timeout", "AlienVault OTX lookup timed out.")
    except httpx.HTTPStatusError as exc:
        return error_response(
            TOOL_NAME,
            query,
            "upstream_error",
            "AlienVault OTX returned an unexpected error.",
            {"status_code": exc.response.status_code},
        )
    except httpx.RequestError as exc:
        return error_response(
            TOOL_NAME,
            query,
            "network_error",
            "AlienVault OTX lookup failed.",
            str(exc),
        )
    except ValueError as exc:
        return error_response(
            TOOL_NAME,
            query,
            "parse_error",
            "AlienVault OTX response was not JSON.",
            str(exc),
        )

    if not isinstance(payload, dict):
        return error_response(
            TOOL_NAME,
            query,
            "parse_error",
            "AlienVault OTX response was not an object.",
        )

    pulse_info = payload.get("pulse_info") if isinstance(payload.get("pulse_info"), dict) else {}
    pulse_count = _int_or_zero(pulse_info.get("count")) if isinstance(pulse_info, dict) else 0
    pulses = _compact_pulses(pulse_info.get("pulses") if isinstance(pulse_info, dict) else None)
    if pulse_count == 0 and pulses:
        pulse_count = len(pulses)

    return success_response(
        TOOL_NAME,
        query,
        {
            "indicator": normalized_indicator,
            "indicator_type": indicator_type,
            "pulse_count": pulse_count,
            "pulses": pulses,
            "reputation": payload.get("reputation"),
            "validation": payload.get("validation"),
            "sections": _sorted_strings(payload.get("sections")),
            "verdict": "suspicious" if pulse_count > 0 else "unknown",
            "source": "alienvault_otx",
            "source_url": url,
            "note": "OTX pulses provide community context and are not proof of maliciousness.",
        },
    )


def _classify_indicator(value: str) -> tuple[str, str]:
    indicator = value.strip()
    if not indicator:
        raise InputValidationError("Indicator must not be empty.")

    try:
        ip = ipaddress.ip_address(indicator)
    except ValueError:
        pass
    else:
        return ("IPv4" if ip.version == 4 else "IPv6"), str(ip)

    try:
        return "url", normalize_url(indicator)
    except InputValidationError:
        pass

    if is_file_hash(indicator):
        return "file", normalize_file_hash(indicator)

    try:
        return "domain", normalize_domain(indicator)
    except InputValidationError as exc:
        raise InputValidationError(
            "Indicator must be an IP address, domain, URL, or MD5/SHA1/SHA256 hash."
        ) from exc


def _compact_pulses(value: object) -> list[dict[str, Any]]:
    if not isinstance(value, list):
        return []

    pulses: list[dict[str, Any]] = []
    for item in value[:10]:
        if not isinstance(item, dict):
            continue
        pulse = {
            "id": item.get("id"),
            "name": item.get("name"),
            "created": item.get("created"),
            "modified": item.get("modified"),
            "tlp": item.get("TLP") or item.get("tlp"),
            "tags": _sorted_strings(item.get("tags")),
        }
        pulses.append({key: value for key, value in pulse.items() if value not in (None, [])})
    return pulses


def _sorted_strings(value: object) -> list[str]:
    if not isinstance(value, list):
        return []
    return sorted({item for item in value if isinstance(item, str)})


def _int_or_zero(value: object) -> int:
    if isinstance(value, bool) or value is None:
        return 0
    try:
        return int(value)
    except (TypeError, ValueError):
        return 0
