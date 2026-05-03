"""Shodan passive host enrichment lookups."""

from __future__ import annotations

from typing import Any

import httpx

from investigatinator.config import get_api_key, get_shodan_base_url, get_timeout_seconds
from investigatinator.enrichment.models import (
    InputValidationError,
    error_response,
    normalize_ip,
    success_response,
)

TOOL_NAME = "shodan_host_lookup"
API_KEY_NAME = "SHODAN_API_KEY"


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

    try:
        response = httpx.get(url, params=params, timeout=get_timeout_seconds())
        if response.status_code in {401, 403}:
            return error_response(
                TOOL_NAME,
                query,
                "authentication_error",
                "Shodan rejected the configured API key.",
                {"status_code": response.status_code},
            )
        if response.status_code == 429:
            return error_response(
                TOOL_NAME,
                query,
                "rate_limited",
                "Shodan rate limit was reached.",
                {"status_code": response.status_code},
            )
        if response.status_code == 404:
            return error_response(
                TOOL_NAME,
                query,
                "not_found",
                "Shodan did not find passive host information for this IP address.",
            )
        response.raise_for_status()
        payload = response.json()
    except httpx.TimeoutException:
        return error_response(TOOL_NAME, query, "timeout", "Shodan lookup timed out.")
    except httpx.HTTPStatusError as exc:
        return error_response(
            TOOL_NAME,
            query,
            "upstream_error",
            "Shodan returned an unexpected error.",
            {"status_code": exc.response.status_code},
        )
    except httpx.RequestError as exc:
        return error_response(TOOL_NAME, query, "network_error", "Shodan lookup failed.", str(exc))
    except ValueError as exc:
        return error_response(
            TOOL_NAME,
            query,
            "parse_error",
            "Shodan response was not JSON.",
            str(exc),
        )

    if not isinstance(payload, dict):
        return error_response(TOOL_NAME, query, "parse_error", "Shodan response was not an object.")

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
            "verdict": _shodan_verdict(services, vulnerabilities),
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


def _shodan_verdict(services: list[dict[str, Any]], vulnerabilities: list[str]) -> str:
    if vulnerabilities:
        return "suspicious"
    if services:
        return "observed"
    return "unknown"


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
