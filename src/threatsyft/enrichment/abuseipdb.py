"""AbuseIPDB enrichment lookups."""

from __future__ import annotations

from typing import Any

import httpx

from threatsyft.config import get_abuseipdb_base_url, get_api_key, get_timeout_seconds
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

TOOL_NAME = "abuseipdb_check_ip"
API_KEY_NAME = "ABUSEIPDB_API_KEY"
PROVIDER = "AbuseIPDB"


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

    result = guarded_get(
        TOOL_NAME,
        query,
        PROVIDER,
        lambda: httpx.get(url, headers=headers, params=params, timeout=get_timeout_seconds()),
    )
    if result.error:
        return result.error
    response = result.response

    auth_error = auth_or_rate_error(TOOL_NAME, query, PROVIDER, response)
    if auth_error:
        return auth_error

    if response.status_code == 404:
        return not_found_error(
            TOOL_NAME, query, "AbuseIPDB did not find a record for this IP address."
        )

    parsed = parse_json_object(TOOL_NAME, query, PROVIDER, response)
    if parsed.error:
        return parsed.error
    payload = parsed.payload

    if not isinstance(payload.get("data"), dict):
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
            "source": "abuseipdb",
        },
    )


def _int_or_none(value: object) -> int | None:
    if isinstance(value, bool) or value is None:
        return None
    try:
        return int(value)
    except (TypeError, ValueError):
        return None
