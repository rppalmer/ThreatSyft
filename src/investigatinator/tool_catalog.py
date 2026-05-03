"""Local tool catalog metadata for Investigatinator."""

from __future__ import annotations

from typing import Any

API_KEYS = {
    "abuseipdb": ["ABUSEIPDB_API_KEY"],
    "greynoise": ["GREYNOISE_API_KEY"],
    "virustotal": ["VIRUSTOTAL_API_KEY"],
    "shodan": ["SHODAN_API_KEY"],
    "securitytrails": ["SECURITYTRAILS_API_KEY"],
    "ipgeolocation": ["IPGEOLOCATION_API_KEY"],
    "alienvault": ["ALIENVAULT_API_KEY"],
    "safebrowsing": ["GOOGLE_SAFEBROWSING_API_KEY"],
}

IP_REPUTATION_KEYS = [
    *API_KEYS["abuseipdb"],
    *API_KEYS["greynoise"],
    *API_KEYS["virustotal"],
    *API_KEYS["shodan"],
]
DOMAIN_REPUTATION_KEYS = [*API_KEYS["virustotal"], *API_KEYS["securitytrails"]]
URL_REPUTATION_KEYS = [
    *API_KEYS["safebrowsing"],
    *API_KEYS["virustotal"],
    *API_KEYS["alienvault"],
]
FILE_REPUTATION_KEYS = [*API_KEYS["virustotal"], *API_KEYS["alienvault"]]
FACT_PACK_KEYS = sorted(
    {
        *IP_REPUTATION_KEYS,
        *DOMAIN_REPUTATION_KEYS,
        *URL_REPUTATION_KEYS,
        *FILE_REPUTATION_KEYS,
    }
)


def _tool(
    name: str,
    input_type: str,
    description: str,
    required_api_keys: list[str],
    live_network: bool,
    interfaces: list[str],
) -> dict[str, Any]:
    return {
        "name": name,
        "input_type": input_type,
        "description": description,
        "required_api_keys": required_api_keys,
        "live_network": live_network,
        "local_only": not live_network,
        "interfaces": interfaces,
        "recommended_use": description,
    }


TOOL_CATALOG: tuple[dict[str, Any], ...] = (
    _tool(
        "dns_lookup",
        "domain",
        "Look up A, AAAA, MX, NS, and TXT records.",
        [],
        True,
        ["mcp"],
    ),
    _tool(
        "rdap_lookup",
        "domain_or_ip",
        "Look up compact RDAP registration data.",
        [],
        True,
        ["mcp"],
    ),
    _tool("whois_lookup", "domain_or_ip", "Look up WHOIS details.", [], True, ["mcp"]),
    _tool(
        "abuseipdb_check_ip",
        "ip",
        "Check AbuseIPDB IP reputation.",
        API_KEYS["abuseipdb"],
        True,
        ["mcp"],
    ),
    _tool(
        "greynoise_ip_context",
        "ip",
        "Check GreyNoise Community IP context.",
        API_KEYS["greynoise"],
        True,
        ["mcp"],
    ),
    _tool(
        "virustotal_ip_report",
        "ip",
        "Fetch a compact VirusTotal IP report.",
        API_KEYS["virustotal"],
        True,
        ["mcp"],
    ),
    _tool(
        "virustotal_domain_report",
        "domain",
        "Fetch a compact VirusTotal domain report.",
        API_KEYS["virustotal"],
        True,
        ["mcp"],
    ),
    _tool(
        "virustotal_url_report",
        "url",
        "Fetch a compact VirusTotal URL report.",
        API_KEYS["virustotal"],
        True,
        ["mcp"],
    ),
    _tool(
        "virustotal_file_report",
        "file_hash",
        "Fetch a compact VirusTotal file hash report.",
        API_KEYS["virustotal"],
        True,
        ["mcp"],
    ),
    _tool(
        "securitytrails_domain_lookup",
        "domain",
        "Fetch compact SecurityTrails domain intelligence.",
        API_KEYS["securitytrails"],
        True,
        ["mcp"],
    ),
    _tool(
        "shodan_host_lookup",
        "ip",
        "Fetch passive Shodan host information.",
        API_KEYS["shodan"],
        True,
        ["mcp"],
    ),
    _tool(
        "ipgeolocation_lookup",
        "ip",
        "Fetch keyed best-effort IP geolocation.",
        API_KEYS["ipgeolocation"],
        True,
        ["mcp"],
    ),
    _tool(
        "alienvault_indicator_lookup",
        "indicator",
        "Fetch AlienVault OTX context for an IP, domain, URL, or file hash.",
        API_KEYS["alienvault"],
        True,
        ["mcp"],
    ),
    _tool(
        "google_safebrowsing_check_url",
        "url",
        "Check a URL against Google Safe Browsing threat lists.",
        API_KEYS["safebrowsing"],
        True,
        ["mcp"],
    ),
    _tool(
        "ip_reputation",
        "ip",
        "Build an IP reputation fact pack.",
        IP_REPUTATION_KEYS,
        True,
        ["mcp", "cli"],
    ),
    _tool(
        "domain_reputation",
        "domain",
        "Build a domain reputation fact pack.",
        DOMAIN_REPUTATION_KEYS,
        True,
        ["mcp", "cli"],
    ),
    _tool(
        "url_reputation",
        "url",
        "Build a URL reputation fact pack.",
        URL_REPUTATION_KEYS,
        True,
        ["mcp", "cli"],
    ),
    _tool(
        "file_reputation",
        "file_hash",
        "Build a file hash reputation fact pack.",
        FILE_REPUTATION_KEYS,
        True,
        ["mcp", "cli"],
    ),
    _tool("ip", "ip", "CLI alias for ip_reputation.", IP_REPUTATION_KEYS, True, ["cli"]),
    _tool(
        "domain",
        "domain",
        "CLI alias for domain_reputation.",
        DOMAIN_REPUTATION_KEYS,
        True,
        ["cli"],
    ),
    _tool("url", "url", "CLI alias for url_reputation.", URL_REPUTATION_KEYS, True, ["cli"]),
    _tool(
        "file",
        "file_hash",
        "CLI alias for file_reputation.",
        FILE_REPUTATION_KEYS,
        True,
        ["cli"],
    ),
    _tool("doctor", "none", "Run a local-only configuration check.", [], False, ["cli"]),
    _tool("tools", "none", "Print this local-only tool catalog.", [], False, ["cli"]),
    _tool(
        "smoke",
        "none",
        "Run live safe-sample fact pack checks.",
        FACT_PACK_KEYS,
        True,
        ["cli"],
    ),
    _tool(
        "knowledge-status",
        "none",
        "Run a local-only knowledge snapshot status check.",
        [],
        False,
        ["cli"],
    ),
    _tool(
        "knowledge-update",
        "source",
        "Download local knowledge snapshots for ATT&CK, D3FEND, KEV, or LOLBAS.",
        [],
        True,
        ["cli"],
    ),
)


def catalog() -> list[dict[str, Any]]:
    """Return the local tool catalog."""
    return [dict(item) for item in TOOL_CATALOG]


def compact_catalog() -> list[dict[str, Any]]:
    """Return a smaller local tool catalog."""
    return [
        {
            "name": item["name"],
            "input_type": item["input_type"],
            "required_api_keys": item["required_api_keys"],
            "live_network": item["live_network"],
            "local_only": item["local_only"],
            "interfaces": item["interfaces"],
        }
        for item in TOOL_CATALOG
    ]
