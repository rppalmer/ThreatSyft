"""MCP server exposing Investigatinator enrichment tools."""

from __future__ import annotations

from typing import Any

from mcp.server.fastmcp import FastMCP

from investigatinator.enrichment.abuseipdb import abuseipdb_check_ip as run_abuseipdb_check_ip
from investigatinator.enrichment.alienvault import (
    alienvault_indicator_lookup as run_alienvault_indicator_lookup,
)
from investigatinator.enrichment.dns import dns_lookup as run_dns_lookup
from investigatinator.enrichment.domain_reputation import domain_reputation as run_domain_reputation
from investigatinator.enrichment.file_reputation import file_reputation as run_file_reputation
from investigatinator.enrichment.greynoise import greynoise_ip_context as run_greynoise_ip_context
from investigatinator.enrichment.ip_reputation import ip_reputation as run_ip_reputation
from investigatinator.enrichment.ipgeolocation import (
    ipgeolocation_lookup as run_ipgeolocation_lookup,
)
from investigatinator.enrichment.rdap import rdap_lookup as run_rdap_lookup
from investigatinator.enrichment.safebrowsing import (
    google_safebrowsing_check_url as run_google_safebrowsing_check_url,
)
from investigatinator.enrichment.securitytrails import (
    securitytrails_domain_lookup as run_securitytrails_domain_lookup,
)
from investigatinator.enrichment.shodan import shodan_host_lookup as run_shodan_host_lookup
from investigatinator.enrichment.status import enrichment_status as run_enrichment_status
from investigatinator.enrichment.url_reputation import url_reputation as run_url_reputation
from investigatinator.enrichment.virustotal import (
    virustotal_domain_report as run_virustotal_domain_report,
)
from investigatinator.enrichment.virustotal import (
    virustotal_file_report as run_virustotal_file_report,
)
from investigatinator.enrichment.virustotal import (
    virustotal_ip_report as run_virustotal_ip_report,
)
from investigatinator.enrichment.virustotal import (
    virustotal_url_report as run_virustotal_url_report,
)
from investigatinator.enrichment.whois import whois_lookup as run_whois_lookup

mcp = FastMCP(
    "Investigatinator Enrichment",
    instructions=(
        "Focused read-only indicator enrichment tools. Use this server for IPs, domains, "
        "URLs, file hashes, DNS, RDAP, WHOIS, geolocation, provider reputation, and "
        "aggregate reputation fact packs. Provider-specific tools return one vendor's "
        "view; ip_reputation, domain_reputation, url_reputation, and file_reputation "
        "combine multiple providers. Use enrichment_status to check configured providers "
        "without exposing secrets or calling external APIs."
    ),
)


@mcp.tool()
def enrichment_status() -> dict[str, Any]:
    """Check local enrichment provider configuration without network calls or secret values."""
    return run_enrichment_status()


@mcp.tool()
def dns_lookup(domain: str) -> dict[str, Any]:
    """Look up A, AAAA, MX, NS, and TXT DNS records for a domain."""
    return run_dns_lookup(domain)


@mcp.tool()
def rdap_lookup(target: str) -> dict[str, Any]:
    """Look up compact RDAP details for a domain or IP address."""
    return run_rdap_lookup(target)


@mcp.tool()
def whois_lookup(target: str) -> dict[str, Any]:
    """Look up WHOIS details for a domain or IP address."""
    return run_whois_lookup(target)


@mcp.tool()
def abuseipdb_check_ip(ip: str, max_age_days: int = 90) -> dict[str, Any]:
    """Check AbuseIPDB's provider-specific reputation for an IP address."""
    return run_abuseipdb_check_ip(ip, max_age_days)


@mcp.tool()
def greynoise_ip_context(ip: str) -> dict[str, Any]:
    """Look up GreyNoise's provider-specific internet scanner context for an IP address."""
    return run_greynoise_ip_context(ip)


@mcp.tool()
def virustotal_ip_report(ip: str) -> dict[str, Any]:
    """Fetch VirusTotal's provider-specific report for an IP address."""
    return run_virustotal_ip_report(ip)


@mcp.tool()
def virustotal_domain_report(domain: str) -> dict[str, Any]:
    """Fetch VirusTotal's provider-specific report for a domain."""
    return run_virustotal_domain_report(domain)


@mcp.tool()
def virustotal_url_report(url: str) -> dict[str, Any]:
    """Fetch VirusTotal's provider-specific report for a URL."""
    return run_virustotal_url_report(url)


@mcp.tool()
def virustotal_file_report(file_hash: str) -> dict[str, Any]:
    """Fetch VirusTotal's provider-specific report for a file hash."""
    return run_virustotal_file_report(file_hash)


@mcp.tool()
def securitytrails_domain_lookup(domain: str) -> dict[str, Any]:
    """Fetch compact SecurityTrails domain intelligence for a domain."""
    return run_securitytrails_domain_lookup(domain)


@mcp.tool()
def shodan_host_lookup(ip: str) -> dict[str, Any]:
    """Fetch passive Shodan host information for an IP address."""
    return run_shodan_host_lookup(ip)


@mcp.tool()
def ipgeolocation_lookup(ip: str) -> dict[str, Any]:
    """Fetch keyed best-effort IP geolocation details for an IP address."""
    return run_ipgeolocation_lookup(ip)


@mcp.tool()
def alienvault_indicator_lookup(indicator: str) -> dict[str, Any]:
    """Fetch AlienVault OTX context for an IP, domain, URL, or file hash."""
    return run_alienvault_indicator_lookup(indicator)


@mcp.tool()
def google_safebrowsing_check_url(url: str) -> dict[str, Any]:
    """Check one URL against Google Safe Browsing threat lists."""
    return run_google_safebrowsing_check_url(url)


@mcp.tool()
def ip_reputation(ip: str) -> dict[str, Any]:
    """Build an aggregate IP reputation fact pack from multiple provider results."""
    return run_ip_reputation(ip)


@mcp.tool()
def domain_reputation(domain: str) -> dict[str, Any]:
    """Build an aggregate domain reputation fact pack from multiple provider results."""
    return run_domain_reputation(domain)


@mcp.tool()
def url_reputation(url: str) -> dict[str, Any]:
    """Build an aggregate URL reputation fact pack from multiple provider results."""
    return run_url_reputation(url)


@mcp.tool()
def file_reputation(file_hash: str) -> dict[str, Any]:
    """Build an aggregate file hash reputation fact pack from multiple provider results."""
    return run_file_reputation(file_hash)


def main() -> None:
    """Run the enrichment MCP server over stdio."""
    mcp.run(transport="stdio")


if __name__ == "__main__":
    main()
