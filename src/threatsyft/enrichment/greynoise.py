"""GreyNoise enrichment lookups."""

from __future__ import annotations

from typing import Any

import httpx

from threatsyft.config import get_api_key, get_greynoise_base_url, get_timeout_seconds
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

TOOL_NAME = "greynoise_ip_context"
API_KEY_NAME = "GREYNOISE_API_KEY"
PROVIDER = "GreyNoise"


def greynoise_ip_context(ip: str) -> dict[str, Any]:
    """Look up GreyNoise Community context for one IP address."""
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

    url = f"{get_greynoise_base_url()}/{normalized_ip}"
    headers = {"Accept": "application/json", "key": api_key}

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
            _response_message(response) or "GreyNoise rejected the IP address.",
        )

    auth_error = auth_or_rate_error(TOOL_NAME, query, PROVIDER, response)
    if auth_error:
        return auth_error

    # GreyNoise returns 404 with a valid "IP not observed" body, not a hard error.
    parsed = parse_json_object(
        TOOL_NAME,
        query,
        PROVIDER,
        response,
        raise_for_status=response.status_code != 404,
    )
    if parsed.error:
        return parsed.error

    return _success_from_payload(query, normalized_ip, parsed.payload)


def _success_from_payload(
    query: dict[str, Any],
    normalized_ip: str,
    payload: dict[str, Any],
) -> dict[str, Any]:
    classification = payload.get("classification")
    noise = payload.get("noise")
    riot = payload.get("riot")

    return success_response(
        TOOL_NAME,
        query,
        {
            "ip": normalized_ip,
            "noise": noise,
            "riot": riot,
            "classification": classification,
            "name": payload.get("name"),
            "link": payload.get("link"),
            "last_seen": payload.get("last_seen"),
            "message": payload.get("message"),
            "verdict": _greynoise_verdict(classification, noise, riot),
            "source": "greynoise",
        },
    )


def _greynoise_verdict(classification: object, noise: object, riot: object) -> str:
    if classification in {"malicious", "benign", "unknown"}:
        return str(classification)
    if riot is True:
        return "benign"
    if noise is True:
        return "suspicious"
    return "unknown"


def _response_message(response: httpx.Response) -> str | None:
    try:
        payload = response.json()
    except ValueError:
        return None

    if not isinstance(payload, dict):
        return None
    message = payload.get("message")
    return message if isinstance(message, str) else None
