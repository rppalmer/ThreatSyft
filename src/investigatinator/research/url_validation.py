"""URL validation helpers for public research fetches."""

from __future__ import annotations

import ipaddress
from urllib.parse import urlparse

from investigatinator.enrichment.models import InputValidationError


def normalize_public_http_url(value: str) -> str:
    """Normalize and validate a public HTTP or HTTPS URL."""
    url = value.strip()
    if not url:
        raise InputValidationError("URL must not be empty.")

    parsed = urlparse(url)
    if parsed.scheme not in {"http", "https"} or not parsed.netloc:
        raise InputValidationError("URL must include http:// or https:// and a hostname.")

    hostname = parsed.hostname
    if hostname is None:
        raise InputValidationError("URL must include a hostname.")

    normalized_hostname = hostname.strip().lower().rstrip(".")
    if normalized_hostname in {"localhost", "localhost.localdomain"}:
        raise InputValidationError("Research URLs must not point to localhost.")

    try:
        ip_address = ipaddress.ip_address(normalized_hostname)
    except ValueError:
        return url

    if not ip_address.is_global:
        raise InputValidationError("Research URLs must not point to private or reserved IPs.")

    return url
