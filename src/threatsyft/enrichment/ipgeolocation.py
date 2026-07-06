"""Keyed IPGeolocation.io IP geolocation lookups."""

from __future__ import annotations

from typing import Any

import httpx

from threatsyft.config import get_api_key, get_ipgeolocation_base_url, get_timeout_seconds
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

TOOL_NAME = "ipgeolocation_lookup"
API_KEY_NAME = "IPGEOLOCATION_API_KEY"
PROVIDER = "IPGeolocation.io"


def ipgeolocation_lookup(ip: str) -> dict[str, Any]:
    """Fetch keyed best-effort IP geolocation details for one IP address."""
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

    url = f"{get_ipgeolocation_base_url()}/v3/ipgeo"
    params = {"apiKey": api_key, "ip": normalized_ip}

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
            "IPGeolocation.io did not find geolocation details for this IP address.",
        )

    parsed = parse_json_object(TOOL_NAME, query, PROVIDER, response)
    if parsed.error:
        return parsed.error
    payload = parsed.payload

    location = _dict_or_empty(payload.get("location"))
    asn = _dict_or_empty(payload.get("asn"))
    company = _dict_or_empty(payload.get("company"))
    time_zone = _dict_or_empty(payload.get("time_zone"))

    return success_response(
        TOOL_NAME,
        query,
        {
            "ip": payload.get("ip") or normalized_ip,
            "country_name": _first_present(location, payload, ("country_name",)),
            "country_code": _first_present(
                location,
                payload,
                ("country_code2", "country_code", "country"),
            ),
            "region": _first_present(location, payload, ("state_prov", "region", "region_name")),
            "city": _first_present(location, payload, ("city",)),
            "zipcode": _first_present(location, payload, ("zipcode", "zip")),
            "latitude": _first_present(location, payload, ("latitude", "lat")),
            "longitude": _first_present(location, payload, ("longitude", "lon")),
            "time_zone": _first_present(time_zone, payload, ("name", "time_zone", "timezone")),
            "asn": _first_present(asn, payload, ("as_number", "asn")),
            "isp": _first_present(company, payload, ("name", "isp")),
            "organization": _first_present(
                asn,
                company,
                ("organization", "name", "org"),
            ),
            "source": "ipgeolocation",
            "source_url": "https://ipgeolocation.io/",
            "note": "IP geolocation is best-effort and may be approximate.",
        },
    )


def _dict_or_empty(value: object) -> dict[str, Any]:
    if isinstance(value, dict):
        return value
    return {}


def _first_present(
    primary: dict[str, Any],
    secondary: dict[str, Any],
    keys: tuple[str, ...],
) -> Any:
    for key in keys:
        value = primary.get(key)
        if value is not None:
            return value
        value = secondary.get(key)
        if value is not None:
            return value
    return None
