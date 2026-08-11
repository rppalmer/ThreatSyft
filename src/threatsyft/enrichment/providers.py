"""Which API key each keyed provider needs.

Kept next to its only consumer, ``enrichment_status``. The names used as keys
here are the same names ``enrich`` reports in its ``sources`` map, so a caller
seeing a source fail can look up whether a key was missing without translating
between two vocabularies.

Which indicator types each provider covers is deliberately not recorded here.
That lives in ``enrich.DISPATCH``, and ``enrichment_status`` derives it, so the
two cannot drift apart.
"""

from __future__ import annotations

PROVIDERS: dict[str, list[str]] = {
    "abuseipdb": ["ABUSEIPDB_API_KEY"],
    "greynoise": ["GREYNOISE_API_KEY"],
    "virustotal": ["VIRUSTOTAL_API_KEY"],
    "securitytrails": ["SECURITYTRAILS_API_KEY"],
    "shodan": ["SHODAN_API_KEY"],
    "alienvault": ["ALIENVAULT_API_KEY"],
    "google_safebrowsing": ["GOOGLE_SAFEBROWSING_API_KEY"],
    "sentinel": ["SENTINEL_API_KEY"],
    "censys": ["CENSYS_API_KEY"],
    "urlscan": ["URLSCAN_API_KEY"],
    "hybrid_analysis": ["HYBRID_ANALYSIS_API_KEY"],
}

# Providers that still answer without their key, at a reduced quota. Listing
# them keeps ``enrichment_status`` from reporting an unkeyed urlscan the same
# way it reports an unkeyed Shodan: one is a smaller rate limit, the other is a
# source that cannot run at all, and a caller deciding what to trust needs the
# difference.
OPTIONAL_KEY_PROVIDERS = {"urlscan"}
