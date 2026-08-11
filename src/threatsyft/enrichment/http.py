"""Shared HTTP request/error mapping for enrichment providers.

Providers share one ``try/except`` ladder mapping
httpx failures and common status codes onto the shared error envelope, which let
the copies drift. These helpers centralize that mapping while leaving the actual
``httpx.get`` call inside each provider module (passed in as ``call``) so provider
tests that patch ``<module>.httpx.get`` keep intercepting the request.

Provider-specific status handling (404 semantics, one-off 400 branches) stays
inline in each provider; only the universal parts live here.
"""

from __future__ import annotations

from collections.abc import Callable
from dataclasses import dataclass
from typing import Any

import httpx

from threatsyft.enrichment.models import error_response


@dataclass(frozen=True)
class HttpResult:
    """A completed request or a ready-to-return error envelope, never both."""

    response: httpx.Response | None
    error: dict[str, Any] | None


@dataclass(frozen=True)
class JsonResult:
    """A parsed JSON object or a ready-to-return error envelope, never both."""

    payload: dict[str, Any] | None
    error: dict[str, Any] | None


@dataclass(frozen=True)
class JsonArrayResult:
    """A parsed JSON array or a ready-to-return error envelope, never both."""

    payload: list[Any] | None
    error: dict[str, Any] | None


def guarded_get(
    tool: str,
    query: dict[str, Any],
    provider: str,
    call: Callable[[], httpx.Response],
) -> HttpResult:
    """Run ``call`` and map transport-level httpx failures onto error envelopes.

    ``call`` performs the actual request from the provider module (typically
    ``lambda: httpx.get(...)``) so monkeypatched ``httpx.get`` is still used.
    """
    try:
        response = call()
    except httpx.TimeoutException:
        return HttpResult(
            None, error_response(tool, query, "timeout", f"{provider} lookup timed out.")
        )
    except httpx.RequestError as exc:
        return HttpResult(
            None,
            error_response(tool, query, "network_error", f"{provider} lookup failed.", str(exc)),
        )
    return HttpResult(response, None)


def auth_or_rate_error(
    tool: str,
    query: dict[str, Any],
    provider: str,
    response: httpx.Response,
) -> dict[str, Any] | None:
    """Map 401/403 and 429 onto error envelopes; return None for other codes."""
    if response.status_code in {401, 403}:
        return error_response(
            tool,
            query,
            "authentication_error",
            f"{provider} rejected the configured API key.",
            {"status_code": response.status_code},
        )
    if response.status_code == 429:
        return error_response(
            tool,
            query,
            "rate_limited",
            f"{provider} rate limit was reached.",
            {"status_code": response.status_code},
        )
    return None


def not_found_error(
    tool: str,
    query: dict[str, Any],
    message: str,
) -> dict[str, Any]:
    """Build a not_found error envelope for a provider's 404 handling."""
    return error_response(tool, query, "not_found", message)


def parse_json_object(
    tool: str,
    query: dict[str, Any],
    provider: str,
    response: httpx.Response,
    *,
    raise_for_status: bool = True,
) -> JsonResult:
    """Raise-for-status (optional), parse JSON, and require a top-level object.

    Non-2xx becomes ``upstream_error``, non-JSON or non-object bodies become
    ``parse_error``. Providers that treat a specific non-2xx code as data (e.g.
    a 404 body) pass ``raise_for_status=False``.
    """
    if raise_for_status:
        try:
            response.raise_for_status()
        except httpx.HTTPStatusError as exc:
            return JsonResult(
                None,
                error_response(
                    tool,
                    query,
                    "upstream_error",
                    f"{provider} returned an unexpected error.",
                    {"status_code": exc.response.status_code},
                ),
            )

    try:
        payload = response.json()
    except ValueError as exc:
        return JsonResult(
            None,
            error_response(
                tool, query, "parse_error", f"{provider} response was not JSON.", str(exc)
            ),
        )

    if not isinstance(payload, dict):
        return JsonResult(
            None,
            error_response(
                tool, query, "parse_error", f"{provider} response was not a JSON object."
            ),
        )
    return JsonResult(payload, None)


def parse_json_array(
    tool: str,
    query: dict[str, Any],
    provider: str,
    response: httpx.Response,
) -> JsonArrayResult:
    """Raise-for-status, parse JSON, and require a top-level array.

    The sibling of ``parse_json_object`` for providers that return a bare list at
    the top level, which that function rejects. Same status and parse mapping, so
    an array-returning provider produces the same error codes as every other one.
    """
    try:
        response.raise_for_status()
    except httpx.HTTPStatusError as exc:
        return JsonArrayResult(
            None,
            error_response(
                tool,
                query,
                "upstream_error",
                f"{provider} returned an unexpected error.",
                {"status_code": exc.response.status_code},
            ),
        )

    try:
        payload = response.json()
    except ValueError as exc:
        return JsonArrayResult(
            None,
            error_response(
                tool, query, "parse_error", f"{provider} response was not JSON.", str(exc)
            ),
        )

    if not isinstance(payload, list):
        return JsonArrayResult(
            None,
            error_response(
                tool, query, "parse_error", f"{provider} response was not a JSON array."
            ),
        )
    return JsonArrayResult(payload, None)
