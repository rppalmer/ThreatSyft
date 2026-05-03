"""AbuseIPDB enrichment lookups."""

from __future__ import annotations

from typing import Any

import httpx

from investigatinator.config import get_abuseipdb_base_url, get_api_key, get_timeout_seconds
from investigatinator.enrichment.models import (
    InputValidationError,
    error_response,
    normalize_ip,
    success_response,
)

TOOL_NAME = "abuseipdb_check_ip"
API_KEY_NAME = "ABUSEIPDB_API_KEY"


def abuseipdb_check_ip(ip: str, max_age_days: int = 90) -> dict[str, Any]:
    """Check AbuseIPDB reputation for one IP address."""
    query: dict[str, Any] = {"ip": ip, "max_age_days": max_age_days}

    try:
        normalized_ip = normalize_ip(ip)
    except InputValidationError as exc:
        return error_response(TOOL_NAME, query, "invalid_input", str(exc))

    if not 1 <= max_age_days <= 365:
        return error_response(
            TOOL_NAME,
            query,
            "invalid_input",
            "max_age_days must be between 1 and 365.",
        )

    query["ip"] = normalized_ip
    api_key = get_api_key(API_KEY_NAME)
    if api_key is None:
        return error_response(
            TOOL_NAME,
            query,
            "missing_api_key",
            f"{API_KEY_NAME} is not configured.",
        )

    url = f"{get_abuseipdb_base_url()}/check"
    headers = {"Accept": "application/json", "Key": api_key}
    params: dict[str, Any] = {
        "ipAddress": normalized_ip,
        "maxAgeInDays": max_age_days,
    }

    try:
        response = httpx.get(url, headers=headers, params=params, timeout=get_timeout_seconds())
        if response.status_code in {401, 403}:
            return error_response(
                TOOL_NAME,
                query,
                "authentication_error",
                "AbuseIPDB rejected the configured API key.",
                {"status_code": response.status_code},
            )
        if response.status_code == 429:
            return error_response(
                TOOL_NAME,
                query,
                "rate_limited",
                "AbuseIPDB rate limit was reached.",
                {"status_code": response.status_code},
            )
        if response.status_code == 404:
            return error_response(
                TOOL_NAME,
                query,
                "not_found",
                "AbuseIPDB did not find a record for this IP address.",
            )
        response.raise_for_status()
        payload = response.json()
    except httpx.TimeoutException:
        return error_response(TOOL_NAME, query, "timeout", "AbuseIPDB lookup timed out.")
    except httpx.HTTPStatusError as exc:
        return error_response(
            TOOL_NAME,
            query,
            "upstream_error",
            "AbuseIPDB returned an unexpected error.",
            {"status_code": exc.response.status_code},
        )
    except httpx.RequestError as exc:
        return error_response(
            TOOL_NAME,
            query,
            "network_error",
            "AbuseIPDB lookup failed.",
            str(exc),
        )
    except ValueError as exc:
        return error_response(
            TOOL_NAME,
            query,
            "parse_error",
            "AbuseIPDB response was not JSON.",
            str(exc),
        )

    if not isinstance(payload, dict) or not isinstance(payload.get("data"), dict):
        return error_response(
            TOOL_NAME,
            query,
            "parse_error",
            "AbuseIPDB response did not include a data object.",
        )

    data = payload["data"]
    total_reports = _int_or_none(data.get("totalReports"))
    abuse_score = _int_or_none(data.get("abuseConfidenceScore"))

    return success_response(
        TOOL_NAME,
        query,
        {
            "ip": normalized_ip,
            "is_public": data.get("isPublic"),
            "ip_version": data.get("ipVersion"),
            "is_whitelisted": data.get("isWhitelisted"),
            "abuse_confidence_score": abuse_score,
            "total_reports": total_reports,
            "num_distinct_users": data.get("numDistinctUsers"),
            "country_code": data.get("countryCode"),
            "country_name": data.get("countryName"),
            "usage_type": data.get("usageType"),
            "isp": data.get("isp"),
            "domain": data.get("domain"),
            "is_tor": data.get("isTor"),
            "last_reported_at": data.get("lastReportedAt"),
            "verdict": _abuseipdb_verdict(
                abuse_score,
                total_reports,
                data.get("isWhitelisted"),
            ),
            "source": "abuseipdb",
        },
    )


def _abuseipdb_verdict(
    abuse_score: int | None,
    total_reports: int | None,
    is_whitelisted: object,
) -> str:
    if is_whitelisted is True and abuse_score == 0:
        return "benign"
    if abuse_score is None and total_reports is None:
        return "unknown"
    if abuse_score is not None and abuse_score >= 75:
        return "malicious"
    has_score = abuse_score is not None and abuse_score > 0
    has_reports = total_reports is not None and total_reports > 0
    if has_score or has_reports:
        return "suspicious"
    return "benign"


def _int_or_none(value: object) -> int | None:
    if isinstance(value, bool) or value is None:
        return None
    try:
        return int(value)
    except (TypeError, ValueError):
        return None
