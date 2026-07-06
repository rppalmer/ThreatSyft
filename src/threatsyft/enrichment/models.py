"""Enrichment-specific indicator validation helpers.

The shared response envelope and error types now live in ``threatsyft.core``.
This module keeps the enrichment-specific indicator validators and re-exports the
envelope so existing ``enrichment`` imports keep resolving through one place.
"""

from __future__ import annotations

import ipaddress
import re
from typing import Literal
from urllib.parse import urlparse

from threatsyft.core import (
    ErrorCode,
    InputValidationError,
    error_response,
    success_response,
)

__all__ = [
    "ErrorCode",
    "InputValidationError",
    "error_response",
    "success_response",
    "TargetType",
    "normalize_domain",
    "normalize_ip",
    "normalize_url",
    "normalize_file_hash",
    "is_file_hash",
    "file_hash_type",
    "classify_target",
]

TargetType = Literal["domain", "ip"]

DOMAIN_PATTERN = re.compile(r"^(?=.{1,253}\.?$)(?!-)(?:[a-zA-Z0-9-]{1,63}\.)+[a-zA-Z]{2,63}\.?$")
FILE_HASH_PATTERN = re.compile(r"^(?:[a-fA-F0-9]{32}|[a-fA-F0-9]{40}|[a-fA-F0-9]{64})$")


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
