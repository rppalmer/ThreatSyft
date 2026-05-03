"""Small console interface for Investigatinator tools."""

from __future__ import annotations

import argparse
import json
from collections.abc import Callable, Sequence
from typing import Any

from investigatinator.config import get_api_key, get_timeout_seconds
from investigatinator.enrichment.domain_reputation import domain_reputation
from investigatinator.enrichment.file_reputation import file_reputation
from investigatinator.enrichment.ip_reputation import ip_reputation
from investigatinator.enrichment.models import error_response, success_response
from investigatinator.enrichment.url_reputation import url_reputation
from investigatinator.knowledge.status import knowledge_status
from investigatinator.knowledge.update_attack import update_attack_snapshot
from investigatinator.knowledge.update_d3fend import update_d3fend_snapshot
from investigatinator.knowledge.update_kev import update_kev_snapshot
from investigatinator.knowledge.update_lolbas import update_lolbas_snapshot
from investigatinator.tool_catalog import catalog as tool_catalog
from investigatinator.tool_catalog import compact_catalog

CommandFunction = Callable[[str], dict[str, Any]]
KnowledgeUpdateFunction = Callable[[], dict[str, Any]]

API_KEY_NAMES = (
    "ABUSEIPDB_API_KEY",
    "GREYNOISE_API_KEY",
    "VIRUSTOTAL_API_KEY",
    "SHODAN_API_KEY",
    "SECURITYTRAILS_API_KEY",
    "IPGEOLOCATION_API_KEY",
    "ALIENVAULT_API_KEY",
    "GOOGLE_SAFEBROWSING_API_KEY",
)

SMOKE_SAMPLES = {
    "ip": "8.8.8.8",
    "domain": "example.com",
    "url": "https://example.com/",
    "file": "d41d8cd98f00b204e9800998ecf8427e",
}

COMMANDS: dict[str, tuple[CommandFunction, str]] = {
    "ip": (ip_reputation, "Build an IP reputation fact pack."),
    "domain": (domain_reputation, "Build a domain reputation fact pack."),
    "url": (url_reputation, "Build a URL reputation fact pack."),
    "file": (file_reputation, "Build a file hash reputation fact pack."),
}

KNOWLEDGE_UPDATE_FUNCTIONS: dict[str, tuple[KnowledgeUpdateFunction, str]] = {
    "attack": (
        update_attack_snapshot,
        "Download the local MITRE ATT&CK Enterprise snapshot.",
    ),
    "d3fend": (
        update_d3fend_snapshot,
        "Download the local MITRE D3FEND snapshot.",
    ),
    "kev": (
        update_kev_snapshot,
        "Download the local CISA KEV snapshot.",
    ),
    "lolbas": (
        update_lolbas_snapshot,
        "Download the local LOLBAS snapshot.",
    ),
}


def main(argv: Sequence[str] | None = None) -> int:
    """Run the console interface and return a process exit code."""
    parser = _build_parser()
    args = parser.parse_args(argv)

    if args.command == "doctor":
        result = doctor()
    elif args.command == "tools":
        result = tools(compact=args.compact)
    elif args.command == "smoke":
        result = smoke()
    elif args.command == "knowledge-status":
        result = knowledge_status()
    elif args.command == "knowledge-update":
        result = knowledge_update(args.source)
    else:
        command_function = COMMANDS[args.command][0]
        result = command_function(args.value)

    if args.compact and args.command != "tools":
        result = _compact_result(result)

    print(json.dumps(result, indent=2, sort_keys=True))
    return 0 if result.get("ok") is True else 1


def _build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(
        prog="investigatinator",
        description="Run local Investigatinator security lookups from the console.",
    )
    parser.add_argument(
        "--compact",
        action="store_true",
        help="Print a smaller status-focused JSON response.",
    )

    subparsers = parser.add_subparsers(dest="command", required=True)
    for command, (_, description) in COMMANDS.items():
        subparser = subparsers.add_parser(command, help=description)
        subparser.add_argument("value", help="Indicator value to enrich.")

    subparsers.add_parser("doctor", help="Run a local-only configuration check.")
    subparsers.add_parser("tools", help="Print the local-only tool catalog.")
    subparsers.add_parser("smoke", help="Run live safe-sample checks; uses provider network calls.")
    subparsers.add_parser(
        "knowledge-status",
        help="Run a local-only knowledge snapshot status check.",
    )
    knowledge_update_parser = subparsers.add_parser(
        "knowledge-update",
        help="Refresh local knowledge snapshots; downloads source data over the network.",
    )
    knowledge_update_parser.add_argument(
        "source",
        choices=[*KNOWLEDGE_UPDATE_FUNCTIONS, "all"],
        help="Knowledge snapshot source to refresh.",
    )

    return parser


def doctor() -> dict[str, Any]:
    """Return a local-only configuration health check."""
    api_keys = {
        name: {
            "configured": get_api_key(name) is not None,
            "secret_value": "redacted",
        }
        for name in API_KEY_NAMES
    }
    missing_keys = [name for name, status in api_keys.items() if not status["configured"]]

    return success_response(
        "doctor",
        {},
        {
            "timeout_seconds": get_timeout_seconds(),
            "api_keys": api_keys,
            "configured_key_count": len(api_keys) - len(missing_keys),
            "missing_keys": missing_keys,
            "network_checked": False,
        },
    )


def tools(*, compact: bool = False) -> dict[str, Any]:
    """Return the local-only tool catalog."""
    selected_catalog = compact_catalog() if compact else tool_catalog()
    return success_response(
        "tools",
        {},
        {
            "local_only": True,
            "network_checked": False,
            "tool_count": len(selected_catalog),
            "tools": selected_catalog,
        },
    )


def smoke() -> dict[str, Any]:
    """Run live safe-sample fact pack checks."""
    results: dict[str, dict[str, Any]] = {}

    for sample_type, indicator in SMOKE_SAMPLES.items():
        command_function = COMMANDS[sample_type][0]
        try:
            result = command_function(indicator)
        except Exception as exc:  # pragma: no cover - defensive command boundary
            result = {
                "ok": False,
                "tool": sample_type,
                "query": {"value": indicator},
                "data": None,
                "error": {
                    "code": "unexpected_error",
                    "message": f"{type(exc).__name__}: {exc}",
                    "details": None,
                },
            }
        results[sample_type] = result

    failed_samples = [
        sample_type for sample_type, result in results.items() if result.get("ok") is not True
    ]

    return success_response(
        "smoke",
        {},
        {
            "live_network": True,
            "sample_count": len(SMOKE_SAMPLES),
            "failed_sample_count": len(failed_samples),
            "failed_samples": failed_samples,
            "results": results,
        },
    )


def knowledge_update(source: str) -> dict[str, Any]:
    """Download one or more local knowledge snapshots."""
    query = {"source": source}
    if source == "all":
        selected_sources = list(KNOWLEDGE_UPDATE_FUNCTIONS)
    elif source in KNOWLEDGE_UPDATE_FUNCTIONS:
        selected_sources = [source]
    else:
        return error_response(
            "knowledge_update",
            query,
            "invalid_input",
            "Knowledge update source must be attack, d3fend, kev, lolbas, or all.",
        )

    results: dict[str, dict[str, Any]] = {}
    for selected_source in selected_sources:
        update_function = KNOWLEDGE_UPDATE_FUNCTIONS[selected_source][0]
        try:
            results[selected_source] = update_function()
        except Exception as exc:  # pragma: no cover - defensive command boundary
            results[selected_source] = error_response(
                f"{selected_source}_snapshot_update",
                {},
                "unexpected_error",
                f"{type(exc).__name__}: {exc}",
            )

    failed_sources = [
        selected_source
        for selected_source, result in results.items()
        if result.get("ok") is not True
    ]
    data = {
        "live_network": True,
        "network_checked": True,
        "downloads_snapshots": True,
        "source": source,
        "requested_sources": selected_sources,
        "updated_source_count": len(selected_sources) - len(failed_sources),
        "failed_source_count": len(failed_sources),
        "failed_sources": failed_sources,
        "results": results,
    }

    if failed_sources:
        return error_response(
            "knowledge_update",
            query,
            "upstream_error",
            "One or more knowledge snapshot updates failed.",
            data,
        )

    return success_response("knowledge_update", query, data)


def _compact_result(result: dict[str, Any]) -> dict[str, Any]:
    data = result.get("data") if isinstance(result.get("data"), dict) else {}
    error = result.get("error") if isinstance(result.get("error"), dict) else {}
    error_details = error.get("details") if isinstance(error.get("details"), dict) else {}
    provider_results = data.get("provider_results") if isinstance(data, dict) else {}
    provider_errors = data.get("provider_errors") if isinstance(data, dict) else []
    provider_result_count = len(provider_results) if isinstance(provider_results, dict) else None
    provider_error_count = len(provider_errors) if isinstance(provider_errors, list) else None

    return {
        "ok": result.get("ok"),
        "tool": result.get("tool"),
        "query": result.get("query"),
        "error": {
            "code": error.get("code"),
            "message": error.get("message"),
        }
        if error
        else None,
        "summary": {
            "indicator": _first_present(data, ("indicator", "ip", "domain", "url", "hash")),
            "indicator_type": data.get("indicator_type"),
            "routed_tool": data.get("routed_tool"),
            "verdict": data.get("overall_verdict") or data.get("verdict"),
            "confidence": data.get("confidence"),
            "configured_key_count": data.get("configured_key_count"),
            "tool_count": data.get("tool_count"),
            "sample_count": data.get("sample_count"),
            "failed_sample_count": data.get("failed_sample_count"),
            "ready": data.get("ready"),
            "snapshot_count": len(data["snapshots"])
            if isinstance(data.get("snapshots"), dict)
            else None,
            "unavailable_snapshot_count": len(data["unavailable_snapshots"])
            if isinstance(data.get("unavailable_snapshots"), list)
            else None,
            "unavailable_snapshots": data.get("unavailable_snapshots"),
            "updated_source_count": data.get("updated_source_count")
            if data.get("updated_source_count") is not None
            else error_details.get("updated_source_count"),
            "failed_source_count": data.get("failed_source_count")
            if data.get("failed_source_count") is not None
            else error_details.get("failed_source_count"),
            "failed_sources": data.get("failed_sources")
            if data.get("failed_sources") is not None
            else error_details.get("failed_sources"),
            "missing_key_count": len(data["missing_keys"])
            if isinstance(data.get("missing_keys"), list)
            else None,
            "provider_result_count": provider_result_count,
            "provider_error_count": provider_error_count,
            "key_signals": data.get("key_signals", [])[:5]
            if isinstance(data.get("key_signals"), list)
            else [],
        },
    }


def _first_present(data: dict[str, Any], keys: tuple[str, ...]) -> Any:
    for key in keys:
        value = data.get(key)
        if value is not None:
            return value
    return None
