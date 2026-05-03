"""Shared response models and validation helpers for enrichment tools."""

from __future__ import annotations

import ipaddress
import re
from typing import Any, Literal
from urllib.parse import urlparse

from pydantic import BaseModel, Field

ErrorCode = Literal[
    "invalid_input",
    "not_found",
    "timeout",
    "network_error",
    "upstream_error",
    "parse_error",
    "missing_api_key",
    "authentication_error",
    "rate_limited",
    "unsupported_target",
    "unexpected_error",
]

TargetType = Literal["domain", "ip"]

DOMAIN_PATTERN = re.compile(r"^(?=.{1,253}\.?$)(?!-)(?:[a-zA-Z0-9-]{1,63}\.)+[a-zA-Z]{2,63}\.?$")
FILE_HASH_PATTERN = re.compile(r"^(?:[a-fA-F0-9]{32}|[a-fA-F0-9]{40}|[a-fA-F0-9]{64})$")


class EnrichmentError(BaseModel):
    """Structured error returned by enrichment tools."""

    code: ErrorCode
    message: str
    details: dict[str, Any] | str | None = None


class EnrichmentResponse(BaseModel):
    """Stable response envelope for MCP tool results."""

    ok: bool
    tool: str
    query: dict[str, Any] = Field(default_factory=dict)
    data: dict[str, Any] | None = None
    error: EnrichmentError | None = None


class InputValidationError(ValueError):
    """Raised when a tool input cannot be safely handled."""


def success_response(tool: str, query: dict[str, Any], data: dict[str, Any]) -> dict[str, Any]:
    """Build a successful tool response."""
    return EnrichmentResponse(ok=True, tool=tool, query=query, data=data).model_dump(mode="json")


def error_response(
    tool: str,
    query: dict[str, Any],
    code: ErrorCode,
    message: str,
    details: dict[str, Any] | str | None = None,
) -> dict[str, Any]:
    """Build a failed tool response."""
    error = EnrichmentError(code=code, message=message, details=details)
    return EnrichmentResponse(ok=False, tool=tool, query=query, error=error).model_dump(mode="json")


def normalize_domain(value: str) -> str:
    """Normalize and validate a domain name."""
    domain = value.strip().lower().rstrip(".")
    if not domain:
        raise InputValidationError("Domain must not be empty.")

    parsed = urlparse(domain)
    if parsed.scheme or parsed.netloc or "/" in domain:
        raise InputValidationError("Enter a domain name, not a URL.")

    if not DOMAIN_PATTERN.fullmatch(domain):
        raise InputValidationError("Domain must look like example.com.")

    return domain


def normalize_ip(value: str) -> str:
    """Normalize and validate an IP address."""
    target = value.strip()
    if not target:
        raise InputValidationError("IP address must not be empty.")

    try:
        return str(ipaddress.ip_address(target))
    except ValueError as exc:
        raise InputValidationError("Target must be a valid IP address.") from exc


def normalize_url(value: str) -> str:
    """Normalize and validate an HTTP or HTTPS URL."""
    url = value.strip()
    if not url:
        raise InputValidationError("URL must not be empty.")

    parsed = urlparse(url)
    if parsed.scheme not in {"http", "https"} or not parsed.netloc:
        raise InputValidationError("URL must include http:// or https:// and a hostname.")

    return url


def normalize_file_hash(value: str) -> str:
    """Normalize and validate an MD5, SHA1, or SHA256 file hash."""
    file_hash = value.strip().lower()
    if not file_hash:
        raise InputValidationError("File hash must not be empty.")
    if not FILE_HASH_PATTERN.fullmatch(file_hash):
        raise InputValidationError("File hash must be MD5, SHA1, or SHA256 hex.")
    return file_hash


def is_file_hash(value: str) -> bool:
    """Return whether a value looks like an MD5, SHA1, or SHA256 file hash."""
    return FILE_HASH_PATTERN.fullmatch(value.strip()) is not None


def file_hash_type(value: str) -> str:
    """Return md5, sha1, or sha256 for a normalized file hash."""
    if len(value) == 32:
        return "md5"
    if len(value) == 40:
        return "sha1"
    return "sha256"


def classify_target(value: str) -> tuple[TargetType, str]:
    """Return whether a target is an IP address or domain, with normalized value."""
    stripped = value.strip()
    if not stripped:
        raise InputValidationError("Target must not be empty.")

    try:
        return "ip", str(ipaddress.ip_address(stripped))
    except ValueError:
        return "domain", normalize_domain(stripped)
