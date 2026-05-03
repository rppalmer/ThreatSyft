"""Keyed IPGeolocation.io IP geolocation lookups."""

from __future__ import annotations

from typing import Any

import httpx

from investigatinator.config import get_api_key, get_ipgeolocation_base_url, get_timeout_seconds
from investigatinator.enrichment.models import (
    InputValidationError,
    error_response,
    normalize_ip,
    success_response,
)

TOOL_NAME = "ipgeolocation_lookup"
API_KEY_NAME = "IPGEOLOCATION_API_KEY"


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

    try:
        response = httpx.get(url, params=params, timeout=get_timeout_seconds())
        if response.status_code in {401, 403}:
            return error_response(
                TOOL_NAME,
                query,
                "authentication_error",
                "IPGeolocation.io rejected the configured API key.",
                {"status_code": response.status_code},
            )
        if response.status_code == 429:
            return error_response(
                TOOL_NAME,
                query,
                "rate_limited",
                "IPGeolocation.io rate limit was reached.",
                {"status_code": response.status_code},
            )
        if response.status_code == 404:
            return error_response(
                TOOL_NAME,
                query,
                "not_found",
                "IPGeolocation.io did not find geolocation details for this IP address.",
            )
        response.raise_for_status()
        payload = response.json()
    except httpx.TimeoutException:
        return error_response(TOOL_NAME, query, "timeout", "IPGeolocation.io lookup timed out.")
    except httpx.HTTPStatusError as exc:
        return error_response(
            TOOL_NAME,
            query,
            "upstream_error",
            "IPGeolocation.io returned an unexpected error.",
            {"status_code": exc.response.status_code},
        )
    except httpx.RequestError as exc:
        return error_response(
            TOOL_NAME,
            query,
            "network_error",
            "IPGeolocation.io lookup failed.",
            str(exc),
        )
    except ValueError as exc:
        return error_response(
            TOOL_NAME,
            query,
            "parse_error",
            "IPGeolocation.io response was not JSON.",
            str(exc),
        )

    if not isinstance(payload, dict):
        return error_response(
            TOOL_NAME,
            query,
            "parse_error",
            "IPGeolocation.io response was not an object.",
        )

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
