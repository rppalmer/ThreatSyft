"""Single-call indicator enrichment across every provider that supports the type.

Collection, not judgement. The caller is the reasoning layer, so this returns
what each source said and who failed, with no aggregate verdict or confidence
score. A verdict computed here would silently change meaning when one provider
rate-limits, and the caller cannot see that happen.
"""

from __future__ import annotations

import re
from collections.abc import Callable
from typing import Any

from threatsyft.core import build_sources
from threatsyft.enrichment.abuseipdb import abuseipdb_check_ip
from threatsyft.enrichment.alienvault import alienvault_indicator_lookup
from threatsyft.enrichment.censys import censys_host_lookup
from threatsyft.enrichment.dns import dns_lookup
from threatsyft.enrichment.greynoise import greynoise_ip_context
from threatsyft.enrichment.hybrid_analysis import hybrid_analysis_hash_lookup
from threatsyft.enrichment.maxmind import maxmind_ip_lookup
from threatsyft.enrichment.models import (
    InputValidationError,
    classify_indicator,
    error_response,
    success_response,
)
from threatsyft.enrichment.rdap import rdap_lookup
from threatsyft.enrichment.safebrowsing import google_safebrowsing_check_url
from threatsyft.enrichment.securitytrails import securitytrails_domain_lookup
from threatsyft.enrichment.sentinel import sentinel_ip_lookup
from threatsyft.enrichment.shodan import shodan_host_lookup
from threatsyft.enrichment.urlscan import urlscan_search
from threatsyft.enrichment.virustotal import (
    virustotal_domain_report,
    virustotal_file_report,
    virustotal_ip_report,
    virustotal_url_report,
)
from threatsyft.enrichment.whois import whois_lookup
from threatsyft.fanout import run_sources

TOOL_NAME = "enrich"

SourceFunction = tuple[str, Callable[[str], dict[str, Any]]]

# Data, not logic. Every source supporting an indicator type is called; there is
# no cost tier and no ordering by preference. Running out of provider credit
# degrades to less data, attributed per source, rather than to a partial answer
# that looks complete.
DISPATCH: dict[str, tuple[SourceFunction, ...]] = {
    "ip": (
        ("abuseipdb", abuseipdb_check_ip),
        ("greynoise", greynoise_ip_context),
        ("sentinel", sentinel_ip_lookup),
        ("virustotal", virustotal_ip_report),
        ("shodan", shodan_host_lookup),
        ("censys", censys_host_lookup),
        ("maxmind", maxmind_ip_lookup),
        ("alienvault", alienvault_indicator_lookup),
        ("rdap", rdap_lookup),
        ("whois", whois_lookup),
    ),
    "domain": (
        ("dns", dns_lookup),
        ("rdap", rdap_lookup),
        ("whois", whois_lookup),
        ("virustotal", virustotal_domain_report),
        ("securitytrails", securitytrails_domain_lookup),
        ("alienvault", alienvault_indicator_lookup),
    ),
    "url": (
        ("google_safebrowsing", google_safebrowsing_check_url),
        ("virustotal", virustotal_url_report),
        ("urlscan", urlscan_search),
        ("alienvault", alienvault_indicator_lookup),
    ),
    "hash": (
        ("virustotal", virustotal_file_report),
        ("hybrid_analysis", hybrid_analysis_hash_lookup),
        ("alienvault", alienvault_indicator_lookup),
    ),
}

# Inputs that are valid references but not enrichable indicators. Matching these
# turns a dead end into a redirect: the caller named the wrong tool, and saying
# which one is right costs nothing. Kept as local patterns rather than importing
# the knowledge classifiers, because enrichment must not depend on that package.
CVE_PATTERN = re.compile(r"^CVE-\d{4}-\d{4,}$", re.IGNORECASE)
TECHNIQUE_PATTERN = re.compile(r"^T\d{4}(?:\.\d{3})?$", re.IGNORECASE)


def enrich(indicator: str) -> dict[str, Any]:
    """Classify one indicator and fan out to every source that supports its type."""
    query = {"indicator": indicator}

    redirect = _wrong_tool_error(indicator, query)
    if redirect:
        return redirect

    try:
        indicator_type, normalized = classify_indicator(indicator)
    except InputValidationError as exc:
        return error_response(TOOL_NAME, query, "invalid_input", str(exc))

    query["indicator"] = normalized
    source_entries, summary = build_sources(run_sources(DISPATCH[indicator_type], normalized))

    return success_response(
        TOOL_NAME,
        query,
        {
            "indicator": normalized,
            # Echoed back so a caller that guessed wrong can self-correct. One
            # `indicator: str` argument cannot catch what separate `ip` and
            # `domain` parameters used to.
            "indicator_type": indicator_type,
            "source_summary": summary,
            "sources": source_entries,
            # Collected from whichever sources declared one. Snapshot-backed
            # sources know their own age; this only lifts what they said to
            # where a reader will see it. Empty on a healthy install.
            "warnings": _warnings(source_entries),
        },
    )


def _warnings(source_entries: dict[str, Any]) -> list[str]:
    """Lift each source's own staleness warning to the top of the response.

    Kept shape-agnostic on purpose: a source declares ``staleness_warning`` or it
    does not, so adding another snapshot-backed provider needs no change here.
    """
    return [
        entry["data"]["staleness_warning"]
        for _, entry in sorted(source_entries.items())
        if entry.get("ok")
        and isinstance(entry.get("data"), dict)
        and isinstance(entry["data"].get("staleness_warning"), str)
    ]


def _wrong_tool_error(indicator: str, query: dict[str, Any]) -> dict[str, Any] | None:
    value = indicator.strip()
    if CVE_PATTERN.fullmatch(value):
        return _redirect(query, value, "cve", "a vulnerability reference")
    if TECHNIQUE_PATTERN.fullmatch(value):
        return _redirect(query, value, "attack_technique", "an ATT&CK technique reference")
    return None


def _redirect(
    query: dict[str, Any],
    value: str,
    detected_type: str,
    description: str,
) -> dict[str, Any]:
    """Turn a dead end into a redirect naming the tool that does handle this."""
    return error_response(
        TOOL_NAME,
        query,
        "invalid_input",
        f"{value} is {description}, not an enrichable indicator.",
        {"detected_type": detected_type, "suggested_tool": "lookup"},
    )
