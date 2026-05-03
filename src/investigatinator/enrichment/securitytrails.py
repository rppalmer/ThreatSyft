"""SecurityTrails domain enrichment lookups."""

from __future__ import annotations

from typing import Any

import httpx

from investigatinator.config import get_api_key, get_securitytrails_base_url, get_timeout_seconds
from investigatinator.enrichment.models import (
    InputValidationError,
    error_response,
    normalize_domain,
    success_response,
)

TOOL_NAME = "securitytrails_domain_lookup"
API_KEY_NAME = "SECURITYTRAILS_API_KEY"


def securitytrails_domain_lookup(domain: str) -> dict[str, Any]:
    """Fetch compact SecurityTrails domain intelligence for one domain."""
    query = {"domain": domain}

    try:
        normalized_domain = normalize_domain(domain)
    except InputValidationError as exc:
        return error_response(TOOL_NAME, query, "invalid_input", str(exc))

    query["domain"] = normalized_domain
    api_key = get_api_key(API_KEY_NAME)
    if api_key is None:
        return error_response(
            TOOL_NAME,
            query,
            "missing_api_key",
            f"{API_KEY_NAME} is not configured.",
        )

    url = f"{get_securitytrails_base_url()}/domain/{normalized_domain}"
    headers = {"Accept": "application/json", "APIKEY": api_key}

    try:
        response = httpx.get(url, headers=headers, timeout=get_timeout_seconds())
        if response.status_code in {401, 403}:
            return error_response(
                TOOL_NAME,
                query,
                "authentication_error",
                "SecurityTrails rejected the configured API key.",
                {"status_code": response.status_code},
            )
        if response.status_code == 429:
            return error_response(
                TOOL_NAME,
                query,
                "rate_limited",
                "SecurityTrails rate limit was reached.",
                {"status_code": response.status_code},
            )
        if response.status_code == 404:
            return error_response(
                TOOL_NAME,
                query,
                "not_found",
                "SecurityTrails did not find domain intelligence for this domain.",
            )
        response.raise_for_status()
        payload = response.json()
    except httpx.TimeoutException:
        return error_response(TOOL_NAME, query, "timeout", "SecurityTrails lookup timed out.")
    except httpx.HTTPStatusError as exc:
        return error_response(
            TOOL_NAME,
            query,
            "upstream_error",
            "SecurityTrails returned an unexpected error.",
            {"status_code": exc.response.status_code},
        )
    except httpx.RequestError as exc:
        return error_response(
            TOOL_NAME,
            query,
            "network_error",
            "SecurityTrails lookup failed.",
            str(exc),
        )
    except ValueError as exc:
        return error_response(
            TOOL_NAME,
            query,
            "parse_error",
            "SecurityTrails response was not JSON.",
            str(exc),
        )

    if not isinstance(payload, dict):
        return error_response(
            TOOL_NAME,
            query,
            "parse_error",
            "SecurityTrails response was not an object.",
        )

    return success_response(
        TOOL_NAME,
        query,
        {
            "domain": normalized_domain,
            "hostname": payload.get("hostname"),
            "apex_domain": payload.get("apex_domain"),
            "alexa_rank": payload.get("alexa_rank"),
            "current_dns": _compact_current_dns(payload.get("current_dns")),
            "whois": _compact_whois(payload.get("whois")),
            "source": "securitytrails",
            "source_url": f"https://securitytrails.com/domain/{normalized_domain}/dns",
        },
    )


def _compact_current_dns(value: object) -> dict[str, list[dict[str, Any]]]:
    if not isinstance(value, dict):
        return {}

    records: dict[str, list[dict[str, Any]]] = {}
    for record_type, record_data in value.items():
        if not isinstance(record_type, str) or not isinstance(record_data, dict):
            continue
        values = record_data.get("values")
        if not isinstance(values, list):
            continue
        compact_values = [_compact_dns_value(item) for item in values if isinstance(item, dict)]
        records[record_type.lower()] = [item for item in compact_values if item]
    return records


def _compact_dns_value(value: dict[str, Any]) -> dict[str, Any]:
    compact = {
        "value": _first_present(value, ("value", "ip", "ipv6", "hostname", "nameserver", "email")),
        "priority": value.get("priority"),
        "ttl": value.get("ttl"),
    }
    return {key: item for key, item in compact.items() if item is not None}


def _compact_whois(value: object) -> dict[str, Any]:
    if not isinstance(value, dict):
        return {}

    return {
        key: item
        for key, item in {
            "registrar": value.get("registrar"),
            "created_date": value.get("createdDate") or value.get("created_date"),
            "updated_date": value.get("updatedDate") or value.get("updated_date"),
            "expires_date": value.get("expiresDate") or value.get("expires_date"),
        }.items()
        if item is not None
    }


def _first_present(value: dict[str, Any], keys: tuple[str, ...]) -> Any:
    for key in keys:
        item = value.get(key)
        if item is not None:
            return item
    return None
