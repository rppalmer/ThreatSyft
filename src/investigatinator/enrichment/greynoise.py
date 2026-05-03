"""GreyNoise enrichment lookups."""

from __future__ import annotations

from typing import Any

import httpx

from investigatinator.config import get_api_key, get_greynoise_base_url, get_timeout_seconds
from investigatinator.enrichment.models import (
    InputValidationError,
    error_response,
    normalize_ip,
    success_response,
)

TOOL_NAME = "greynoise_ip_context"
API_KEY_NAME = "GREYNOISE_API_KEY"


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

    try:
        response = httpx.get(url, headers=headers, timeout=get_timeout_seconds())
        if response.status_code == 400:
            return error_response(
                TOOL_NAME,
                query,
                "invalid_input",
                _response_message(response) or "GreyNoise rejected the IP address.",
            )
        if response.status_code in {401, 403}:
            return error_response(
                TOOL_NAME,
                query,
                "authentication_error",
                "GreyNoise rejected the configured API key.",
                {"status_code": response.status_code},
            )
        if response.status_code == 429:
            return error_response(
                TOOL_NAME,
                query,
                "rate_limited",
                "GreyNoise rate limit was reached.",
                {"status_code": response.status_code},
            )
        if response.status_code == 404:
            payload = response.json()
            if not isinstance(payload, dict):
                return error_response(
                    TOOL_NAME,
                    query,
                    "parse_error",
                    "GreyNoise response was not an object.",
                )
            return _success_from_payload(query, normalized_ip, payload)
        response.raise_for_status()
        payload = response.json()
    except httpx.TimeoutException:
        return error_response(TOOL_NAME, query, "timeout", "GreyNoise lookup timed out.")
    except httpx.HTTPStatusError as exc:
        return error_response(
            TOOL_NAME,
            query,
            "upstream_error",
            "GreyNoise returned an unexpected error.",
            {"status_code": exc.response.status_code},
        )
    except httpx.RequestError as exc:
        return error_response(
            TOOL_NAME,
            query,
            "network_error",
            "GreyNoise lookup failed.",
            str(exc),
        )
    except ValueError as exc:
        return error_response(
            TOOL_NAME,
            query,
            "parse_error",
            "GreyNoise response was not JSON.",
            str(exc),
        )

    if not isinstance(payload, dict):
        return error_response(
            TOOL_NAME,
            query,
            "parse_error",
            "GreyNoise response was not an object.",
        )

    return _success_from_payload(query, normalized_ip, payload)


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
