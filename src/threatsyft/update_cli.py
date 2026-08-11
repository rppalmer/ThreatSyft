"""Snapshot updater console command.

The only CLI ThreatSyft keeps. MCP is the interface for everything else, but
snapshot downloads have nowhere else to live: making them an MCP tool would put
a multi-megabyte network write behind a model's decision and break the
read-only posture of the servers.
"""

from __future__ import annotations

import argparse
import json
from collections.abc import Callable, Sequence
from typing import Any

from threatsyft.core import error_response, success_response
from threatsyft.knowledge.update_attack import update_attack_snapshot
from threatsyft.knowledge.update_kev import update_kev_snapshot
from threatsyft.knowledge.update_lolbas import update_lolbas_snapshot
from threatsyft.knowledge.update_maxmind import update_maxmind_snapshot
from threatsyft.logging_setup import configure_logging

TOOL_NAME = "knowledge_update"

UpdateFunction = Callable[[], dict[str, Any]]

UPDATE_FUNCTIONS: dict[str, UpdateFunction] = {
    "attack": update_attack_snapshot,
    "kev": update_kev_snapshot,
    "lolbas": update_lolbas_snapshot,
    # An enrichment snapshot rather than a reference catalog, and the only one
    # here that needs credentials to download. It lives on this command anyway
    # because this is the project's only snapshot downloader, and splitting out
    # a second CLI for one source would be worse than the naming stretch.
    "maxmind": update_maxmind_snapshot,
}


def main(argv: Sequence[str] | None = None) -> int:
    """Refresh local knowledge snapshots and return a process exit code."""
    configure_logging()
    parser = argparse.ArgumentParser(
        prog="threatsyft-update",
        description="Refresh local knowledge snapshots; downloads source data over the network.",
    )
    parser.add_argument(
        "source",
        choices=[*UPDATE_FUNCTIONS, "all"],
        help="Knowledge snapshot source to refresh.",
    )
    args = parser.parse_args(argv)

    result = knowledge_update(args.source)
    print(json.dumps(result, indent=2, sort_keys=True))
    return 0 if result.get("ok") is True else 1


def knowledge_update(source: str) -> dict[str, Any]:
    """Download one or more local knowledge snapshots."""
    query = {"source": source}
    if source == "all":
        selected_sources = list(UPDATE_FUNCTIONS)
    elif source in UPDATE_FUNCTIONS:
        selected_sources = [source]
    else:
        return error_response(
            TOOL_NAME,
            query,
            "invalid_input",
            "Knowledge update source must be attack, kev, lolbas, maxmind, or all.",
        )

    results: dict[str, dict[str, Any]] = {}
    for selected_source in selected_sources:
        try:
            results[selected_source] = UPDATE_FUNCTIONS[selected_source]()
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
            TOOL_NAME,
            query,
            "upstream_error",
            "One or more knowledge snapshot updates failed.",
            data,
        )

    return success_response(TOOL_NAME, query, data)


if __name__ == "__main__":
    raise SystemExit(main())
