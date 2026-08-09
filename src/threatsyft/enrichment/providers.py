"""Provider metadata: which API keys each keyed provider needs, and its tools.

Kept next to its only consumer, ``enrichment_status``. The names used as keys
here are the same names ``enrich`` reports in its ``sources`` map, so a caller
seeing a source fail can look up whether a key was missing without translating
between two vocabularies.
"""

from __future__ import annotations

# Single source of truth for provider-specific tools and their API keys. Both the
# tool catalog and the enrichment status tool derive from this so the provider ->
# key -> tool mapping cannot drift between them.
PROVIDERS: dict[str, dict[str, list[str]]] = {
    "abuseipdb": {
        "api_keys": ["ABUSEIPDB_API_KEY"],
        "tools": ["abuseipdb_check_ip"],
    },
    "greynoise": {
        "api_keys": ["GREYNOISE_API_KEY"],
        "tools": ["greynoise_ip_context"],
    },
    "virustotal": {
        "api_keys": ["VIRUSTOTAL_API_KEY"],
        "tools": [
            "virustotal_ip_report",
            "virustotal_domain_report",
            "virustotal_url_report",
            "virustotal_file_report",
        ],
    },
    "securitytrails": {
        "api_keys": ["SECURITYTRAILS_API_KEY"],
        "tools": ["securitytrails_domain_lookup"],
    },
    "shodan": {
        "api_keys": ["SHODAN_API_KEY"],
        "tools": ["shodan_host_lookup"],
    },
    "ipgeolocation": {
        "api_keys": ["IPGEOLOCATION_API_KEY"],
        "tools": ["ipgeolocation_lookup"],
    },
    "alienvault": {
        "api_keys": ["ALIENVAULT_API_KEY"],
        "tools": ["alienvault_indicator_lookup"],
    },
    "google_safebrowsing": {
        "api_keys": ["GOOGLE_SAFEBROWSING_API_KEY"],
        "tools": ["google_safebrowsing_check_url"],
    },
}
