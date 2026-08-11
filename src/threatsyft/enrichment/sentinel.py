"""Sentinel anonymization lookups.

Answers "is this address hiding behind something, and behind what" — commercial
VPN, residential or SOCKS proxy, Tor exit, or datacenter ASN — which none of the
other IP providers name directly. GreyNoise classifies scanning behaviour and
Shodan describes the host; neither says which VPN service an address belongs to.
"""

from __future__ import annotations

from typing import Any

import httpx

from threatsyft.config import get_api_key, get_sentinel_base_url, get_timeout_seconds
from threatsyft.enrichment.http import (
    auth_or_rate_error,
    guarded_get,
    parse_json_object,
)
from threatsyft.enrichment.models import (
    InputValidationError,
    error_response,
    normalize_ip,
    success_response,
)

TOOL_NAME = "sentinel_ip_lookup"
API_KEY_NAME = "SENTINEL_API_KEY"
PROVIDER = "Sentinel"


def sentinel_ip_lookup(ip: str) -> dict[str, Any]:
    """Look up Sentinel anonymization context for one IP address."""
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

    url = f"{get_sentinel_base_url()}/lookup/{normalized_ip}"
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

    if response.status_code == 400:
        return error_response(
            TOOL_NAME,
            query,
            "invalid_input",
            "Sentinel rejected the IP address.",
        )

    auth_error = auth_or_rate_error(TOOL_NAME, query, PROVIDER, response)
    if auth_error:
        return auth_error

    parsed = parse_json_object(TOOL_NAME, query, PROVIDER, response)
    if parsed.error:
        return parsed.error

    return _success_from_payload(query, normalized_ip, parsed.payload)


def _success_from_payload(
    query: dict[str, Any],
    normalized_ip: str,
    payload: dict[str, Any],
) -> dict[str, Any]:
    # `verdict` and `risk_score` are Sentinel's own fields, passed through under
    # its source name rather than folded into anything. Nothing here is computed.
    signals = payload.get("signals")
    network = payload.get("network")

    return success_response(
        TOOL_NAME,
        query,
        {
            "ip": normalized_ip,
            "known": payload.get("known"),
            "verdict": payload.get("verdict"),
            "risk_score": payload.get("risk_score"),
            "signals": signals if isinstance(signals, dict) else None,
            "network": network if isinstance(network, dict) else None,
            "source": "sentinel",
        },
    )
