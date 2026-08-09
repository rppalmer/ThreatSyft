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
    "ipgeolocation": ["IPGEOLOCATION_API_KEY"],
    "alienvault": ["ALIENVAULT_API_KEY"],
    "google_safebrowsing": ["GOOGLE_SAFEBROWSING_API_KEY"],
}
