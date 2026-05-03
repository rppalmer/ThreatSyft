"""Aggregate IP reputation fact pack."""

from __future__ import annotations

from typing import Any

from investigatinator.enrichment.abuseipdb import abuseipdb_check_ip
from investigatinator.enrichment.greynoise import greynoise_ip_context
from investigatinator.enrichment.models import (
    InputValidationError,
    error_response,
    normalize_ip,
    success_response,
)
from investigatinator.enrichment.shodan import shodan_host_lookup
from investigatinator.enrichment.virustotal import virustotal_ip_report

TOOL_NAME = "ip_reputation"

ProviderFunction = tuple[str, Any]

PROVIDERS: tuple[ProviderFunction, ...] = (
    ("abuseipdb", abuseipdb_check_ip),
    ("greynoise", greynoise_ip_context),
    ("virustotal", virustotal_ip_report),
    ("shodan", shodan_host_lookup),
)


def ip_reputation(ip: str) -> dict[str, Any]:
    """Build a deterministic IP reputation fact pack from provider results."""
    query = {"ip": ip}

    try:
        normalized_ip = normalize_ip(ip)
    except InputValidationError as exc:
        return error_response(TOOL_NAME, query, "invalid_input", str(exc))

    query["ip"] = normalized_ip
    provider_results: dict[str, dict[str, Any]] = {}
    provider_errors: list[dict[str, Any]] = []

    for provider_name, provider_function in PROVIDERS:
        result = provider_function(normalized_ip)
        if result.get("ok") is True and isinstance(result.get("data"), dict):
            provider_results[provider_name] = result["data"]
            continue

        error = result.get("error") if isinstance(result.get("error"), dict) else {}
        provider_errors.append(
            {
                "provider": provider_name,
                "code": error.get("code", "unexpected_error"),
                "message": error.get("message", "Provider lookup failed."),
            }
        )

    if not provider_results:
        return error_response(
            TOOL_NAME,
            query,
            "upstream_error",
            "All IP reputation providers failed.",
            {"provider_errors": provider_errors},
        )

    verdict = _overall_verdict(provider_results)
    key_signals = _key_signals(provider_results, provider_errors)

    return success_response(
        TOOL_NAME,
        query,
        {
            "ip": normalized_ip,
            "overall_verdict": verdict,
            "confidence": _confidence(provider_results, provider_errors, verdict),
            "key_signals": key_signals,
            "provider_results": provider_results,
            "provider_errors": provider_errors,
        },
    )


def _overall_verdict(provider_results: dict[str, dict[str, Any]]) -> str:
    verdicts = _provider_verdicts(provider_results)
    if "malicious" in verdicts:
        return "malicious"
    if "suspicious" in verdicts:
        return "suspicious"

    shodan = provider_results.get("shodan", {})
    if shodan.get("vulnerabilities"):
        return "suspicious"

    if verdicts and all(verdict in {"benign", "observed"} for verdict in verdicts):
        return "benign"

    return "unknown"


def _confidence(
    provider_results: dict[str, dict[str, Any]],
    provider_errors: list[dict[str, Any]],
    verdict: str,
) -> str:
    success_count = len(provider_results)
    error_count = len(provider_errors)

    if verdict == "unknown":
        return "low"
    if success_count >= 3 and error_count == 0:
        return "high"
    if success_count >= 2:
        return "medium"
    return "low"


def _key_signals(
    provider_results: dict[str, dict[str, Any]],
    provider_errors: list[dict[str, Any]],
) -> list[str]:
    signals: list[str] = []

    abuseipdb = provider_results.get("abuseipdb")
    if abuseipdb:
        score = abuseipdb.get("abuse_confidence_score")
        reports = abuseipdb.get("total_reports")
        verdict = abuseipdb.get("verdict")
        if verdict == "benign":
            signals.append("AbuseIPDB reports a benign result.")
        elif verdict in {"malicious", "suspicious"}:
            signals.append(f"AbuseIPDB reports {verdict} activity.")
        if score is not None:
            signals.append(f"AbuseIPDB abuse confidence score is {score}.")
        if reports is not None:
            signals.append(f"AbuseIPDB total report count is {reports}.")

    greynoise = provider_results.get("greynoise")
    if greynoise:
        if greynoise.get("riot") is True:
            signals.append("GreyNoise identifies this IP as RIOT/business-service infrastructure.")
        elif greynoise.get("noise") is True:
            signals.append("GreyNoise identifies this IP as internet noise.")
        classification = greynoise.get("classification")
        if classification:
            signals.append(f"GreyNoise classification is {classification}.")

    virustotal = provider_results.get("virustotal")
    if virustotal:
        stats = virustotal.get("last_analysis_stats")
        if isinstance(stats, dict):
            malicious = stats.get("malicious", 0)
            suspicious = stats.get("suspicious", 0)
            signals.append(
                "VirusTotal analysis has "
                f"{malicious} malicious and {suspicious} suspicious detections."
            )
        reputation = virustotal.get("reputation")
        if reputation is not None:
            signals.append(f"VirusTotal reputation score is {reputation}.")

    shodan = provider_results.get("shodan")
    if shodan:
        ports = shodan.get("ports")
        vulnerabilities = shodan.get("vulnerabilities")
        if ports:
            signals.append(f"Shodan observes services on ports: {_join_values(ports)}.")
        if vulnerabilities:
            signals.append(f"Shodan reports vulnerabilities: {_join_values(vulnerabilities)}.")
        elif shodan.get("verdict") == "observed":
            signals.append(
                "Shodan observes exposed services but no vulnerabilities in the compact result."
            )

    for error in provider_errors:
        provider = error.get("provider", "unknown")
        code = error.get("code", "unexpected_error")
        signals.append(f"{provider} lookup did not complete: {code}.")

    return signals


def _provider_verdicts(provider_results: dict[str, dict[str, Any]]) -> list[str]:
    verdicts: list[str] = []
    for result in provider_results.values():
        verdict = result.get("verdict")
        if isinstance(verdict, str):
            verdicts.append(verdict)
    return verdicts


def _join_values(values: object) -> str:
    if not isinstance(values, list):
        return str(values)
    return ", ".join(str(value) for value in values[:10])
