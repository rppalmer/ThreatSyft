"""Aggregate domain reputation fact pack."""

from __future__ import annotations

from typing import Any

from threatsyft.enrichment.aggregate import run_providers
from threatsyft.enrichment.dns import dns_lookup
from threatsyft.enrichment.models import (
    InputValidationError,
    error_response,
    normalize_domain,
    success_response,
)
from threatsyft.enrichment.rdap import rdap_lookup
from threatsyft.enrichment.securitytrails import securitytrails_domain_lookup
from threatsyft.enrichment.virustotal import virustotal_domain_report
from threatsyft.enrichment.whois import whois_lookup

TOOL_NAME = "domain_reputation"

ProviderFunction = tuple[str, Any]

PROVIDERS: tuple[ProviderFunction, ...] = (
    ("dns", dns_lookup),
    ("rdap", rdap_lookup),
    ("whois", whois_lookup),
    ("virustotal", virustotal_domain_report),
    ("securitytrails", securitytrails_domain_lookup),
)


def domain_reputation(domain: str) -> dict[str, Any]:
    """Build a deterministic domain reputation fact pack from provider results."""
    query = {"domain": domain}

    try:
        normalized_domain = normalize_domain(domain)
    except InputValidationError as exc:
        return error_response(TOOL_NAME, query, "invalid_input", str(exc))

    query["domain"] = normalized_domain
    provider_results, provider_errors = run_providers(PROVIDERS, normalized_domain)

    if not provider_results:
        return error_response(
            TOOL_NAME,
            query,
            "upstream_error",
            "All domain reputation providers failed.",
            {"provider_errors": provider_errors},
        )

    verdict = _overall_verdict(provider_results)

    return success_response(
        TOOL_NAME,
        query,
        {
            "domain": normalized_domain,
            "overall_verdict": verdict,
            "confidence": _confidence(provider_results, provider_errors, verdict),
            "key_signals": _key_signals(provider_results, provider_errors),
            "provider_results": provider_results,
            "provider_errors": provider_errors,
        },
    )


def _overall_verdict(provider_results: dict[str, dict[str, Any]]) -> str:
    virustotal = provider_results.get("virustotal", {})
    verdict = virustotal.get("verdict")
    if verdict in {"malicious", "suspicious", "benign"}:
        return str(verdict)

    return "unknown"


def _confidence(
    provider_results: dict[str, dict[str, Any]],
    provider_errors: list[dict[str, Any]],
    verdict: str,
) -> str:
    success_count = len(provider_results)
    error_count = len(provider_errors)

    if verdict == "unknown":
        # An unknown verdict is a non-answer; report low confidence to match the
        # ip/url/file fact packs rather than inflating confidence on provider count.
        return "low"
    if success_count >= 4 and error_count == 0:
        return "high"
    if success_count >= 2:
        return "medium"
    return "low"


def _key_signals(
    provider_results: dict[str, dict[str, Any]],
    provider_errors: list[dict[str, Any]],
) -> list[str]:
    signals: list[str] = []

    dns = provider_results.get("dns")
    if dns:
        records = dns.get("records")
        if isinstance(records, dict):
            populated_types = [
                record_type
                for record_type, values in records.items()
                if isinstance(values, list) and values
            ]
            if populated_types:
                signals.append(f"DNS has records for: {_join_values(populated_types)}.")

    rdap = provider_results.get("rdap")
    if rdap:
        status = rdap.get("status")
        if status:
            signals.append(f"RDAP status values: {_join_values(status)}.")
        entities = rdap.get("entities")
        if entities:
            signals.append(f"RDAP entities include: {_join_values(entities)}.")

    whois = provider_results.get("whois")
    if whois:
        registrar = whois.get("registrar")
        if registrar:
            signals.append(f"WHOIS registrar is {registrar}.")
        creation_date = whois.get("creation_date")
        if creation_date:
            signals.append(f"WHOIS creation date is {creation_date}.")

    virustotal = provider_results.get("virustotal")
    if virustotal:
        stats = virustotal.get("last_analysis_stats")
        if isinstance(stats, dict):
            malicious = stats.get("malicious", 0)
            suspicious = stats.get("suspicious", 0)
            signals.append(
                "VirusTotal domain analysis has "
                f"{malicious} malicious and {suspicious} suspicious detections."
            )
        reputation = virustotal.get("reputation")
        if reputation is not None:
            signals.append(f"VirusTotal domain reputation score is {reputation}.")

    securitytrails = provider_results.get("securitytrails")
    if securitytrails:
        current_dns = securitytrails.get("current_dns")
        if isinstance(current_dns, dict) and current_dns:
            signals.append(
                f"SecurityTrails current DNS types include: {_join_values(list(current_dns))}."
            )
        alexa_rank = securitytrails.get("alexa_rank")
        if alexa_rank is not None:
            signals.append(f"SecurityTrails Alexa rank is {alexa_rank}.")

    for error in provider_errors:
        provider = error.get("provider", "unknown")
        code = error.get("code", "unexpected_error")
        signals.append(f"{provider} lookup did not complete: {code}.")

    return signals


def _join_values(values: object) -> str:
    if not isinstance(values, list):
        return str(values)
    return ", ".join(str(value) for value in values[:10])
