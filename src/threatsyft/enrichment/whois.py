"""WHOIS enrichment lookups."""

from __future__ import annotations

import ssl
import urllib.request
from datetime import date, datetime
from typing import Any

import certifi
import whois
from ipwhois import IPWhois
from ipwhois.exceptions import HTTPLookupError, IPDefinedError, WhoisLookupError

from threatsyft.config import get_timeout_seconds
from threatsyft.enrichment.models import (
    InputValidationError,
    classify_target,
    error_response,
    success_response,
)

TOOL_NAME = "whois_lookup"
MAX_RAW_CHARS = 2000


def whois_lookup(target: str) -> dict[str, Any]:
    """Look up WHOIS information for a domain or IP address."""
    query = {"target": target}

    try:
        target_type, normalized_target = classify_target(target)
    except InputValidationError as exc:
        return error_response(TOOL_NAME, query, "invalid_input", str(exc))

    query.update({"target": normalized_target, "target_type": target_type})
    if target_type == "ip":
        return _ip_whois_lookup(normalized_target, query)

    return _domain_whois_lookup(normalized_target, query)


def _domain_whois_lookup(domain: str, query: dict[str, Any]) -> dict[str, Any]:
    try:
        record = whois.whois(domain)
    except TimeoutError:
        return error_response(TOOL_NAME, query, "timeout", "WHOIS lookup timed out.")
    except Exception as exc:  # python-whois raises broad parser/network exceptions.
        return error_response(TOOL_NAME, query, "upstream_error", "WHOIS lookup failed.", str(exc))

    if not record:
        return error_response(TOOL_NAME, query, "not_found", "WHOIS record was not found.")

    data = {
        "target": domain,
        "target_type": "domain",
        "domain_name": _clean_value(_first(record.get("domain_name"))),
        "registrar": _clean_value(_first(record.get("registrar"))),
        "whois_server": _clean_value(_first(record.get("whois_server"))),
        "creation_date": _serialize_datetime(_first(record.get("creation_date"))),
        "expiration_date": _serialize_datetime(_first(record.get("expiration_date"))),
        "updated_date": _serialize_datetime(_first(record.get("updated_date"))),
        "name_servers": _clean_string_list(record.get("name_servers")),
        "status": _clean_string_list(record.get("status")),
        "emails": _clean_string_list(record.get("emails")),
        "raw": _capped(_clean_value(record.get("text"))),
    }
    return success_response(TOOL_NAME, query, data)


def _ip_whois_lookup(ip: str, query: dict[str, Any]) -> dict[str, Any]:
    try:
        record = IPWhois(
            ip,
            timeout=get_timeout_seconds(),
            proxy_opener=_build_certifi_opener(),
        ).lookup_rdap()
    except IPDefinedError as exc:
        return error_response(TOOL_NAME, query, "unsupported_target", str(exc))
    except HTTPLookupError as exc:
        return error_response(
            TOOL_NAME,
            query,
            "network_error",
            "IP WHOIS lookup failed.",
            str(exc),
        )
    except WhoisLookupError as exc:
        return error_response(
            TOOL_NAME,
            query,
            "upstream_error",
            "IP WHOIS lookup failed.",
            str(exc),
        )
    except TimeoutError:
        return error_response(TOOL_NAME, query, "timeout", "IP WHOIS lookup timed out.")
    except Exception as exc:
        return error_response(
            TOOL_NAME,
            query,
            "unexpected_error",
            "IP WHOIS lookup failed.",
            str(exc),
        )

    network = record.get("network") if isinstance(record.get("network"), dict) else {}
    data = {
        "target": ip,
        "target_type": "ip",
        "asn": _clean_value(record.get("asn")),
        "asn_description": _clean_value(record.get("asn_description")),
        "asn_country_code": _clean_value(record.get("asn_country_code")),
        "network": {
            "name": _clean_value(network.get("name")),
            "handle": _clean_value(network.get("handle")),
            "country": _clean_value(network.get("country")),
            "start_address": _clean_value(network.get("start_address")),
            "end_address": _clean_value(network.get("end_address")),
        },
    }
    return success_response(TOOL_NAME, query, data)


def _capped(value: str | None) -> str | None:
    """Cap raw WHOIS text.

    Every field worth having is parsed out above; the raw text is a fallback for
    the occasional registrar-specific line, not the payload. Full records run to
    tens of kilobytes of mostly boilerplate.
    """
    if value is None or len(value) <= MAX_RAW_CHARS:
        return value
    return value[:MAX_RAW_CHARS] + "... [truncated]"


def _build_certifi_opener() -> urllib.request.OpenerDirector:
    context = ssl.create_default_context(cafile=certifi.where())
    https_handler = urllib.request.HTTPSHandler(context=context)
    return urllib.request.build_opener(https_handler)


def _first(value: object) -> object:
    if isinstance(value, list):
        return value[0] if value else None
    return value


def _clean_value(value: object) -> str | None:
    if value is None:
        return None
    text = str(value).strip()
    return text or None


def _clean_string_list(value: object) -> list[str]:
    if value is None:
        return []
    values = value if isinstance(value, list) else [value]
    return sorted({text for item in values if (text := _clean_value(item))})


def _serialize_datetime(value: object) -> str | None:
    if isinstance(value, datetime | date):
        return value.isoformat()
    return _clean_value(value)
