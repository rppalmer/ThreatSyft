"""DNS enrichment lookups."""

from __future__ import annotations

from typing import Any

import dns.exception
import dns.resolver

from threatsyft.config import get_timeout_seconds
from threatsyft.enrichment.models import (
    InputValidationError,
    error_response,
    normalize_domain,
    success_response,
)

TOOL_NAME = "dns_lookup"
RECORD_TYPES = ("A", "AAAA", "MX", "NS", "TXT")


def dns_lookup(domain: str) -> dict[str, Any]:
    """Look up common DNS records for a domain."""
    query = {"domain": domain}

    try:
        normalized_domain = normalize_domain(domain)
    except InputValidationError as exc:
        return error_response(TOOL_NAME, query, "invalid_input", str(exc))

    query["domain"] = normalized_domain
    resolver = dns.resolver.Resolver()
    timeout = get_timeout_seconds()
    resolver.timeout = timeout
    resolver.lifetime = timeout

    records: dict[str, list[str]] = {record_type: [] for record_type in RECORD_TYPES}

    for record_type in RECORD_TYPES:
        try:
            answers = resolver.resolve(normalized_domain, record_type)
        except dns.resolver.NXDOMAIN:
            return error_response(
                TOOL_NAME,
                query,
                "not_found",
                f"No DNS records found because {normalized_domain} does not exist.",
            )
        except dns.resolver.NoAnswer:
            continue
        except dns.resolver.NoNameservers as exc:
            return error_response(
                TOOL_NAME,
                query,
                "upstream_error",
                "DNS nameservers could not answer the query.",
                str(exc),
            )
        except dns.exception.Timeout:
            return error_response(TOOL_NAME, query, "timeout", "DNS lookup timed out.")
        except dns.exception.DNSException as exc:
            return error_response(TOOL_NAME, query, "network_error", "DNS lookup failed.", str(exc))

        records[record_type] = [_format_dns_answer(record_type, answer) for answer in answers]

    return success_response(
        TOOL_NAME,
        query,
        {
            "domain": normalized_domain,
            "records": records,
        },
    )


def _format_dns_answer(record_type: str, answer: object) -> str:
    if record_type == "MX":
        preference = getattr(answer, "preference", None)
        exchange = getattr(answer, "exchange", None)
        if preference is not None and exchange is not None:
            return f"{preference} {str(exchange).rstrip('.')}".strip()
        return str(answer).rstrip(".")
    if record_type == "NS":
        return str(answer).rstrip(".")
    if record_type == "TXT":
        return str(answer).strip('"')
    return str(answer)
