"""URL validation helpers for public research fetches."""

from __future__ import annotations

import ipaddress
import socket
from urllib.parse import urlparse

from threatsyft.core import InputValidationError

# Cap on how much of a fetched body downstream parsers/regex are allowed to see.
# Research fetches are attacker-influenceable (the URL is a tool argument), so this
# bounds the CPU/memory a hostile or accidentally huge page can cost us.
MAX_FETCH_BYTES = 3_000_000

IpAddress = ipaddress.IPv4Address | ipaddress.IPv6Address


def normalize_public_http_url(value: str) -> str:
    """Normalize and validate a public HTTP or HTTPS URL.

    Rejects non-HTTP schemes, localhost, IP literals in private/reserved ranges,
    and hostnames that resolve to private/reserved addresses. The DNS-resolution
    check narrows SSRF exposure but cannot fully close DNS-rebinding TOCTOU: the
    connection may re-resolve to a different address than the one validated here.
    Fully closing that would require pinning the validated IP into the connection.
    """
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
        ip_literal = ipaddress.ip_address(normalized_hostname)
    except ValueError:
        # A hostname, not an IP literal: resolve it and reject if it maps to any
        # non-global address (loopback, link-local, private, cloud metadata, etc.).
        for resolved in resolve_host_addresses(normalized_hostname):
            if not resolved.is_global:
                raise InputValidationError(
                    "Research URLs must not resolve to private or reserved IPs."
                ) from None
        return url

    if not ip_literal.is_global:
        raise InputValidationError("Research URLs must not point to private or reserved IPs.")

    return url


def resolve_host_addresses(hostname: str) -> list[IpAddress]:
    """Resolve a hostname to its IP addresses for SSRF validation.

    Returns an empty list when resolution fails, so a resolver hiccup falls
    through to a normal connection attempt rather than being treated as a block.
    Isolated as a module-level function so tests can stub DNS resolution.
    """
    try:
        infos = socket.getaddrinfo(hostname, None, proto=socket.IPPROTO_TCP)
    except socket.gaierror:
        return []

    addresses: list[IpAddress] = []
    for *_, sockaddr in infos:
        candidate = sockaddr[0]
        try:
            addresses.append(ipaddress.ip_address(candidate))
        except ValueError:
            continue
    return addresses
