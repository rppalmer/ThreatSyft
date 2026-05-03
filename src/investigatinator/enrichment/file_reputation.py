"""Aggregate file hash reputation fact pack."""

from __future__ import annotations

from typing import Any

from investigatinator.enrichment.alienvault import alienvault_indicator_lookup
from investigatinator.enrichment.models import (
    InputValidationError,
    error_response,
    file_hash_type,
    normalize_file_hash,
    success_response,
)
from investigatinator.enrichment.virustotal import virustotal_file_report

TOOL_NAME = "file_reputation"

ProviderFunction = tuple[str, Any]

PROVIDERS: tuple[ProviderFunction, ...] = (
    ("virustotal", virustotal_file_report),
    ("alienvault", alienvault_indicator_lookup),
)


def file_reputation(file_hash: str) -> dict[str, Any]:
    """Build a deterministic file hash reputation fact pack from provider results."""
    query = {"hash": file_hash}

    try:
        normalized_hash = normalize_file_hash(file_hash)
    except InputValidationError as exc:
        return error_response(TOOL_NAME, query, "invalid_input", str(exc))

    query["hash"] = normalized_hash
    provider_results: dict[str, dict[str, Any]] = {}
    provider_errors: list[dict[str, Any]] = []

    for provider_name, provider_function in PROVIDERS:
        result = provider_function(normalized_hash)
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
            "All file reputation providers failed.",
            {"provider_errors": provider_errors},
        )

    verdict = _overall_verdict(provider_results)

    return success_response(
        TOOL_NAME,
        query,
        {
            "hash": normalized_hash,
            "hash_type": file_hash_type(normalized_hash),
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
    if (
        verdicts
        and all(verdict in {"benign", "unknown"} for verdict in verdicts)
        and "benign" in verdicts
    ):
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
    if success_count >= 2 and error_count == 0:
        return "high"
    if success_count >= 1:
        return "medium"
    return "low"


def _key_signals(
    provider_results: dict[str, dict[str, Any]],
    provider_errors: list[dict[str, Any]],
) -> list[str]:
    signals: list[str] = []

    virustotal = provider_results.get("virustotal")
    if virustotal:
        stats = virustotal.get("last_analysis_stats")
        if isinstance(stats, dict):
            malicious = stats.get("malicious", 0)
            suspicious = stats.get("suspicious", 0)
            signals.append(
                "VirusTotal file analysis has "
                f"{malicious} malicious and {suspicious} suspicious detections."
            )
        meaningful_name = virustotal.get("meaningful_name")
        if meaningful_name:
            signals.append(f"VirusTotal meaningful file name is {meaningful_name}.")

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
