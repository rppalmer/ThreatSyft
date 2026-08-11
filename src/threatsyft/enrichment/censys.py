"""Censys host lookups.

Answers what an address is actually exposing. Censys identifies the software
behind each open port — `pure-ftpd`, `openssh`, `exim` — which is attack-surface
detail the reputation providers do not carry and Shodan reports differently.
"""

from __future__ import annotations

from typing import Any

import httpx

from threatsyft.config import get_api_key, get_censys_base_url, get_timeout_seconds
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

TOOL_NAME = "censys_host_lookup"
API_KEY_NAME = "CENSYS_API_KEY"
PROVIDER = "Censys"

# Censys reports every observed service and every name resolving to the address.
# A busy host returns hundreds, so the lists are bounded and the authoritative
# totals are reported beside them: a caller can see that it is seeing a slice.
MAX_SERVICES = 25
MAX_DNS_NAMES = 25

LOCATION_FIELDS = ("continent", "country", "country_code", "province", "city")
AUTONOMOUS_SYSTEM_FIELDS = ("asn", "name", "description", "bgp_prefix", "country_code")


def censys_host_lookup(ip: str) -> dict[str, Any]:
    """Look up Censys host detail for one IP address."""
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

    url = f"{get_censys_base_url()}/global/asset/host/{normalized_ip}"
    headers = {"Accept": "application/json", "Authorization": f"Bearer {api_key}"}

    result = guarded_get(
        TOOL_NAME,
        query,
        PROVIDER,
        lambda: httpx.get(url, headers=headers, timeout=get_timeout_seconds()),
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
            "Censys has no host record for this IP address.",
        )

    parsed = parse_json_object(TOOL_NAME, query, PROVIDER, response)
    if parsed.error:
        return parsed.error

    resource = (parsed.payload.get("result") or {}).get("resource") or {}
    return _success_from_resource(query, normalized_ip, resource)


def _success_from_resource(
    query: dict[str, Any],
    normalized_ip: str,
    resource: dict[str, Any],
) -> dict[str, Any]:
    dns = resource.get("dns")
    dns = dns if isinstance(dns, dict) else {}
    names = [name for name in (dns.get("names") or []) if isinstance(name, str)]
    services = resource.get("services")
    services = services if isinstance(services, list) else []

    return success_response(
        TOOL_NAME,
        query,
        {
            "ip": normalized_ip,
            "location": _subset(resource.get("location"), LOCATION_FIELDS),
            "autonomous_system": _subset(
                resource.get("autonomous_system"), AUTONOMOUS_SYSTEM_FIELDS
            ),
            # Censys's own count, not the length of the list below it.
            "service_count": resource.get("service_count"),
            "services": [_service(entry) for entry in services[:MAX_SERVICES]],
            "dns_name_count": len(names),
            "dns_names": names[:MAX_DNS_NAMES],
            "source": "censys",
        },
    )


def _service(entry: Any) -> dict[str, Any]:
    """Reduce one observed service to what identifies it.

    The per-protocol detail Censys attaches — banners, TLS handshakes, HTTP
    bodies — is the bulk of the response and is not what a triage question asks.
    Port, protocol, and the software behind it are.
    """
    if not isinstance(entry, dict):
        return {}
    software = [
        {key: value for key, value in item.items() if key in ("vendor", "product", "version")}
        for item in (entry.get("software") or [])
        if isinstance(item, dict)
    ]
    return {
        "port": entry.get("port"),
        "protocol": entry.get("protocol"),
        "transport_protocol": entry.get("transport_protocol"),
        "software": [item for item in software if item],
    }


def _subset(value: Any, fields: tuple[str, ...]) -> dict[str, Any] | None:
    if not isinstance(value, dict):
        return None
    return {field: value[field] for field in fields if field in value}
