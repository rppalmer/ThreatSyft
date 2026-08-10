"""VirusTotal enrichment lookups."""

from __future__ import annotations

import base64
from datetime import UTC, datetime
from typing import Any

import httpx

from threatsyft.config import get_api_key, get_timeout_seconds, get_virustotal_base_url
from threatsyft.enrichment.http import (
    auth_or_rate_error,
    guarded_get,
    not_found_error,
    parse_json_object,
)
from threatsyft.enrichment.models import (
    InputValidationError,
    error_response,
    file_hash_type,
    normalize_domain,
    normalize_file_hash,
    normalize_ip,
    normalize_url,
    success_response,
)

API_KEY_NAME = "VIRUSTOTAL_API_KEY"
PROVIDER = "VirusTotal"


def virustotal_ip_report(ip: str) -> dict[str, Any]:
    """Fetch a compact VirusTotal report for one IP address."""
    tool_name = "virustotal_ip_report"
    query = {"ip": ip}

    try:
        normalized_ip = normalize_ip(ip)
    except InputValidationError as exc:
        return error_response(tool_name, query, "invalid_input", str(exc))

    query["ip"] = normalized_ip
    payload_or_error = _get_virustotal_object(
        tool_name,
        query,
        f"ip_addresses/{normalized_ip}",
        "IP address",
    )
    if _is_error_response(payload_or_error):
        return payload_or_error

    attributes_or_error = _extract_attributes(tool_name, query, payload_or_error)
    if _is_error_response(attributes_or_error):
        return attributes_or_error
    attributes = attributes_or_error

    last_analysis_stats = _dict_or_empty(attributes.get("last_analysis_stats"))
    reputation = _int_or_none(attributes.get("reputation"))

    return success_response(
        tool_name,
        query,
        {
            "ip": normalized_ip,
            "asn": attributes.get("asn"),
            "as_owner": attributes.get("as_owner"),
            "country": attributes.get("country"),
            "continent": attributes.get("continent"),
            "network": attributes.get("network"),
            "regional_internet_registry": attributes.get("regional_internet_registry"),
            "reputation": reputation,
            "last_analysis_stats": last_analysis_stats,
            "total_votes": _dict_or_empty(attributes.get("total_votes")),
            "tags": _string_list(attributes.get("tags")),
            "last_analysis_date": _timestamp_to_iso(attributes.get("last_analysis_date")),
            "last_modification_date": _timestamp_to_iso(attributes.get("last_modification_date")),
            "source": "virustotal",
            "source_url": f"https://www.virustotal.com/gui/ip-address/{normalized_ip}",
        },
    )


def virustotal_domain_report(domain: str) -> dict[str, Any]:
    """Fetch a compact VirusTotal report for one domain."""
    tool_name = "virustotal_domain_report"
    query = {"domain": domain}

    try:
        normalized_domain = normalize_domain(domain)
    except InputValidationError as exc:
        return error_response(tool_name, query, "invalid_input", str(exc))

    query["domain"] = normalized_domain
    payload_or_error = _get_virustotal_object(
        tool_name,
        query,
        f"domains/{normalized_domain}",
        "domain",
    )
    if _is_error_response(payload_or_error):
        return payload_or_error

    attributes_or_error = _extract_attributes(tool_name, query, payload_or_error)
    if _is_error_response(attributes_or_error):
        return attributes_or_error
    attributes = attributes_or_error

    last_analysis_stats = _dict_or_empty(attributes.get("last_analysis_stats"))
    reputation = _int_or_none(attributes.get("reputation"))

    return success_response(
        tool_name,
        query,
        {
            "domain": normalized_domain,
            "reputation": reputation,
            "registrar": attributes.get("registrar"),
            "whois_date": _timestamp_to_iso(attributes.get("whois_date")),
            "creation_date": _timestamp_to_iso(attributes.get("creation_date")),
            "last_analysis_stats": last_analysis_stats,
            "last_dns_records": _compact_dns_records(attributes.get("last_dns_records")),
            "categories": _dict_or_empty(attributes.get("categories")),
            "total_votes": _dict_or_empty(attributes.get("total_votes")),
            "tags": _string_list(attributes.get("tags")),
            "last_analysis_date": _timestamp_to_iso(attributes.get("last_analysis_date")),
            "last_modification_date": _timestamp_to_iso(attributes.get("last_modification_date")),
            "source": "virustotal",
            "source_url": f"https://www.virustotal.com/gui/domain/{normalized_domain}",
        },
    )


def virustotal_url_report(url: str) -> dict[str, Any]:
    """Fetch a compact VirusTotal report for one URL."""
    tool_name = "virustotal_url_report"
    query = {"url": url}

    try:
        normalized_url = normalize_url(url)
    except InputValidationError as exc:
        return error_response(tool_name, query, "invalid_input", str(exc))

    url_id = _url_identifier(normalized_url)
    query["url"] = normalized_url
    payload_or_error = _get_virustotal_object(
        tool_name,
        query,
        f"urls/{url_id}",
        "URL",
    )
    if _is_error_response(payload_or_error):
        return payload_or_error

    attributes_or_error = _extract_attributes(tool_name, query, payload_or_error)
    if _is_error_response(attributes_or_error):
        return attributes_or_error
    attributes = attributes_or_error

    last_analysis_stats = _dict_or_empty(attributes.get("last_analysis_stats"))
    reputation = _int_or_none(attributes.get("reputation"))

    return success_response(
        tool_name,
        query,
        {
            "url": normalized_url,
            "id": url_id,
            "final_url": attributes.get("last_final_url") or attributes.get("url"),
            "title": attributes.get("title"),
            "reputation": reputation,
            "last_analysis_stats": last_analysis_stats,
            "categories": _dict_or_empty(attributes.get("categories")),
            "total_votes": _dict_or_empty(attributes.get("total_votes")),
            "tags": _string_list(attributes.get("tags")),
            "first_submission_date": _timestamp_to_iso(attributes.get("first_submission_date")),
            "last_submission_date": _timestamp_to_iso(attributes.get("last_submission_date")),
            "last_analysis_date": _timestamp_to_iso(attributes.get("last_analysis_date")),
            "last_modification_date": _timestamp_to_iso(attributes.get("last_modification_date")),
            "last_http_response_code": attributes.get("last_http_response_code"),
            "source": "virustotal",
            "source_url": f"https://www.virustotal.com/gui/url/{url_id}",
        },
    )


def virustotal_file_report(file_hash: str) -> dict[str, Any]:
    """Fetch a compact VirusTotal report for one file hash."""
    tool_name = "virustotal_file_report"
    query = {"hash": file_hash}

    try:
        normalized_hash = normalize_file_hash(file_hash)
    except InputValidationError as exc:
        return error_response(tool_name, query, "invalid_input", str(exc))

    query["hash"] = normalized_hash
    payload_or_error = _get_virustotal_object(
        tool_name,
        query,
        f"files/{normalized_hash}",
        "file hash",
    )
    if _is_error_response(payload_or_error):
        return payload_or_error

    attributes_or_error = _extract_attributes(tool_name, query, payload_or_error)
    if _is_error_response(attributes_or_error):
        return attributes_or_error
    attributes = attributes_or_error

    last_analysis_stats = _dict_or_empty(attributes.get("last_analysis_stats"))
    reputation = _int_or_none(attributes.get("reputation"))

    return success_response(
        tool_name,
        query,
        {
            "hash": normalized_hash,
            "hash_type": file_hash_type(normalized_hash),
            "md5": attributes.get("md5"),
            "sha1": attributes.get("sha1"),
            "sha256": attributes.get("sha256"),
            "meaningful_name": attributes.get("meaningful_name"),
            "names": _string_list(attributes.get("names"))[:10],
            "type_description": attributes.get("type_description"),
            "type_tag": attributes.get("type_tag"),
            "size": attributes.get("size"),
            "reputation": reputation,
            "last_analysis_stats": last_analysis_stats,
            "total_votes": _dict_or_empty(attributes.get("total_votes")),
            "tags": _string_list(attributes.get("tags")),
            "signature_info": _dict_or_empty(attributes.get("signature_info")),
            "first_submission_date": _timestamp_to_iso(attributes.get("first_submission_date")),
            "last_submission_date": _timestamp_to_iso(attributes.get("last_submission_date")),
            "last_analysis_date": _timestamp_to_iso(attributes.get("last_analysis_date")),
            "last_modification_date": _timestamp_to_iso(attributes.get("last_modification_date")),
            "source": "virustotal",
            "source_url": f"https://www.virustotal.com/gui/file/{normalized_hash}",
        },
    )


def _get_virustotal_object(
    tool_name: str,
    query: dict[str, Any],
    path: str,
    target_description: str,
) -> dict[str, Any]:
    api_key = get_api_key(API_KEY_NAME)
    if api_key is None:
        return error_response(
            tool_name,
            query,
            "missing_api_key",
            f"{API_KEY_NAME} is not configured.",
        )

    url = f"{get_virustotal_base_url()}/{path}"
    headers = {"Accept": "application/json", "x-apikey": api_key}

    result = guarded_get(
        tool_name,
        query,
        PROVIDER,
        lambda: httpx.get(url, headers=headers, timeout=get_timeout_seconds()),
    )
    if result.error:
        return result.error
    response = result.response

    auth_error = auth_or_rate_error(tool_name, query, PROVIDER, response)
    if auth_error:
        return auth_error

    if response.status_code == 404:
        return not_found_error(
            tool_name,
            query,
            f"VirusTotal did not find a report for this {target_description}.",
        )

    parsed = parse_json_object(tool_name, query, PROVIDER, response)
    if parsed.error:
        return parsed.error

    return parsed.payload


def _extract_attributes(
    tool_name: str,
    query: dict[str, Any],
    payload: dict[str, Any],
) -> dict[str, Any]:
    data = payload.get("data")
    if not isinstance(data, dict):
        return error_response(
            tool_name,
            query,
            "parse_error",
            "VirusTotal response did not include a data object.",
        )

    attributes = data.get("attributes")
    if not isinstance(attributes, dict):
        return error_response(
            tool_name,
            query,
            "parse_error",
            "VirusTotal response did not include attributes.",
        )

    return attributes


def _dict_or_empty(value: object) -> dict[str, Any]:
    return value if isinstance(value, dict) else {}


def _string_list(value: object) -> list[str]:
    if not isinstance(value, list):
        return []
    return [item for item in value if isinstance(item, str)]


def _compact_dns_records(value: object) -> list[dict[str, Any]]:
    if not isinstance(value, list):
        return []

    records: list[dict[str, Any]] = []
    for record in value:
        if not isinstance(record, dict):
            continue
        records.append(
            {
                "type": record.get("type"),
                "value": record.get("value"),
                "ttl": record.get("ttl"),
            }
        )
    return records


def _timestamp_to_iso(value: object) -> str | None:
    timestamp = _int_or_none(value)
    if timestamp is None:
        return None
    return datetime.fromtimestamp(timestamp, tz=UTC).isoformat()


def _int_or_none(value: object) -> int | None:
    if isinstance(value, bool) or value is None:
        return None
    try:
        return int(value)
    except (TypeError, ValueError):
        return None


def _url_identifier(url: str) -> str:
    return base64.urlsafe_b64encode(url.encode()).decode().rstrip("=")


def _is_error_response(value: dict[str, Any]) -> bool:
    return value.get("ok") is False and "error" in value
