"""Shodan passive host enrichment lookups."""

from __future__ import annotations

from typing import Any

import httpx

from threatsyft.config import get_api_key, get_shodan_base_url, get_timeout_seconds
from threatsyft.enrichment.http import (
    auth_or_rate_error,
    guarded_get,
    not_found_error,
    parse_json_object,
)
from threatsyft.enrichment.models import (
    InputValidationError,
    error_response,
    normalize_ip,
    success_response,
)

TOOL_NAME = "shodan_host_lookup"
API_KEY_NAME = "SHODAN_API_KEY"
PROVIDER = "Shodan"


def shodan_host_lookup(ip: str) -> dict[str, Any]:
    """Fetch passive Shodan host information for one IP address."""
    query = {"ip": ip}

    try:
        normalized_ip = normalize_ip(ip)
    except InputValidationError as exc:
        return error_response(TOOL_NAME, query, "invalid_input", str(exc))

    query["ip"] = normalized_ip
    api_key = get_api_key(API_KEY_NAME)
    if api_key is None:
        return error_response(
            TOOL_NAME,
            query,
            "missing_api_key",
            f"{API_KEY_NAME} is not configured.",
        )

    url = f"{get_shodan_base_url()}/shodan/host/{normalized_ip}"
    params: dict[str, Any] = {
        "key": api_key,
        "history": "false",
        "minify": "false",
    }

    result = guarded_get(
        TOOL_NAME,
        query,
        PROVIDER,
        lambda: httpx.get(url, params=params, timeout=get_timeout_seconds()),
    )
    if result.error:
        return result.error
    response = result.response

    auth_error = auth_or_rate_error(TOOL_NAME, query, PROVIDER, response)
    if auth_error:
        return auth_error

    if response.status_code == 404:
        return not_found_error(
            TOOL_NAME,
            query,
            "Shodan did not find passive host information for this IP address.",
        )

    parsed = parse_json_object(TOOL_NAME, query, PROVIDER, response)
    if parsed.error:
        return parsed.error
    payload = parsed.payload

    services = _extract_services(payload.get("data"))
    vulnerabilities = _extract_vulnerabilities(payload)
    ports = _sorted_ints(payload.get("ports"))

    return success_response(
        TOOL_NAME,
        query,
        {
            "ip": normalized_ip,
            "organization": payload.get("org"),
            "isp": payload.get("isp"),
            "asn": payload.get("asn"),
            "country_code": payload.get("country_code"),
            "country_name": payload.get("country_name"),
            "city": payload.get("city"),
            "region_code": payload.get("region_code"),
            "hostnames": _sorted_strings(payload.get("hostnames")),
            "domains": _sorted_strings(payload.get("domains")),
            "ports": ports or sorted({service["port"] for service in services}),
            "services": services,
            "vulnerabilities": vulnerabilities,
            "tags": _sorted_strings(payload.get("tags")),
            "last_update": payload.get("last_update"),
            "source": "shodan",
            "source_url": f"https://www.shodan.io/host/{normalized_ip}",
        },
    )


def _extract_services(value: object) -> list[dict[str, Any]]:
    if not isinstance(value, list):
        return []

    services: list[dict[str, Any]] = []
    for item in value:
        if not isinstance(item, dict):
            continue
        port = _int_or_none(item.get("port"))
        if port is None:
            continue
        services.append(
            {
                "port": port,
                "transport": item.get("transport"),
                "product": item.get("product"),
                "version": item.get("version"),
                "timestamp": item.get("timestamp"),
                "module": item.get("_shodan", {}).get("module")
                if isinstance(item.get("_shodan"), dict)
                else None,
                "ssl": isinstance(item.get("ssl"), dict),
            }
        )

    return sorted(services, key=lambda service: service["port"])


def _extract_vulnerabilities(payload: dict[str, Any]) -> list[str]:
    vulns = payload.get("vulns")
    if isinstance(vulns, dict):
        return sorted(vuln for vuln in vulns if isinstance(vuln, str))
    if isinstance(vulns, list):
        return _sorted_strings(vulns)

    services = payload.get("data")
    if not isinstance(services, list):
        return []

    found: set[str] = set()
    for service in services:
        if not isinstance(service, dict):
            continue
        service_vulns = service.get("vulns")
        if isinstance(service_vulns, dict | list):
            found.update(vuln for vuln in service_vulns if isinstance(vuln, str))
    return sorted(found)


def _sorted_strings(value: object) -> list[str]:
    if not isinstance(value, list):
        return []
    return sorted({item for item in value if isinstance(item, str)})


def _sorted_ints(value: object) -> list[int]:
    if not isinstance(value, list):
        return []
    return sorted({item for item in value if isinstance(item, int) and not isinstance(item, bool)})


def _int_or_none(value: object) -> int | None:
    if isinstance(value, bool) or value is None:
        return None
    try:
        return int(value)
    except (TypeError, ValueError):
        return None
