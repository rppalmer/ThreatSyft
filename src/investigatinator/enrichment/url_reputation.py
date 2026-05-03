"""Aggregate URL reputation fact pack."""

from __future__ import annotations

from typing import Any

from investigatinator.enrichment.alienvault import alienvault_indicator_lookup
from investigatinator.enrichment.models import (
    InputValidationError,
    error_response,
    normalize_url,
    success_response,
)
from investigatinator.enrichment.safebrowsing import google_safebrowsing_check_url
from investigatinator.enrichment.virustotal import virustotal_url_report

TOOL_NAME = "url_reputation"

ProviderFunction = tuple[str, Any]

PROVIDERS: tuple[ProviderFunction, ...] = (
    ("google_safebrowsing", google_safebrowsing_check_url),
    ("virustotal", virustotal_url_report),
    ("alienvault", alienvault_indicator_lookup),
)


def url_reputation(url: str) -> dict[str, Any]:
    """Build a deterministic URL reputation fact pack from provider results."""
    query = {"url": url}

    try:
        normalized_url = normalize_url(url)
    except InputValidationError as exc:
        return error_response(TOOL_NAME, query, "invalid_input", str(exc))

    query["url"] = normalized_url
    provider_results: dict[str, dict[str, Any]] = {}
    provider_errors: list[dict[str, Any]] = []

    for provider_name, provider_function in PROVIDERS:
        result = provider_function(normalized_url)
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
            "All URL reputation providers failed.",
            {"provider_errors": provider_errors},
        )

    verdict = _overall_verdict(provider_results)

    return success_response(
        TOOL_NAME,
        query,
        {
            "url": normalized_url,
            "overall_verdict": verdict,
            "confidence": _confidence(provider_results, provider_errors, verdict),
            "key_signals": _key_signals(provider_results, provider_errors),
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
    if "benign" in verdicts and not any(verdict == "unknown" for verdict in verdicts):
        return "benign"
    if verdicts.count("benign") >= 2:
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

    safebrowsing = provider_results.get("google_safebrowsing")
    if safebrowsing:
        if safebrowsing.get("matched") is True:
            signals.append("Google Safe Browsing found one or more threat list matches.")
        elif safebrowsing.get("matched") is False:
            signals.append("Google Safe Browsing did not find a threat list match.")

    virustotal = provider_results.get("virustotal")
    if virustotal:
        stats = virustotal.get("last_analysis_stats")
        if isinstance(stats, dict):
            malicious = stats.get("malicious", 0)
            suspicious = stats.get("suspicious", 0)
            signals.append(
                "VirusTotal URL analysis has "
                f"{malicious} malicious and {suspicious} suspicious detections."
            )
        reputation = virustotal.get("reputation")
        if reputation is not None:
            signals.append(f"VirusTotal URL reputation score is {reputation}.")

    alienvault = provider_results.get("alienvault")
    if alienvault:
        pulse_count = alienvault.get("pulse_count")
        if pulse_count is not None:
            signals.append(f"AlienVault OTX pulse count is {pulse_count}.")

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
