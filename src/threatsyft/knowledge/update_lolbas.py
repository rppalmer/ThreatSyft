"""Download the local LOLBAS JSON catalog."""

from __future__ import annotations

import json
import sys
from typing import Any

from threatsyft.config import get_lolbas_path, get_lolbas_url
from threatsyft.core import error_response, success_response
from threatsyft.knowledge.snapshot_cache import write_snapshot
from threatsyft.knowledge.snapshot_fetch import (
    fetch_snapshot,
    record_download,
    unchanged_response,
)

TOOL_NAME = "lolbas_snapshot_update"
LABEL = "LOLBAS"


def update_lolbas_snapshot() -> dict[str, Any]:
    """Download and validate the LOLBAS JSON catalog snapshot."""
    snapshot_path = get_lolbas_path()
    source_url = get_lolbas_url()
    query = {"source_url": source_url, "snapshot_path": str(snapshot_path)}

    outcome = fetch_snapshot(TOOL_NAME, query, LABEL, source_url, snapshot_path)
    if outcome.error:
        return outcome.error
    if outcome.unchanged:
        return unchanged_response(TOOL_NAME, query, snapshot_path, {"source_url": source_url})

    response = outcome.response
    try:
        payload = response.json()
    except ValueError as exc:
        return error_response(
            TOOL_NAME,
            query,
            "parse_error",
            "LOLBAS download did not return valid JSON.",
            {"reason": str(exc)},
        )

    if not isinstance(payload, list):
        return error_response(
            TOOL_NAME,
            query,
            "parse_error",
            "LOLBAS download must be a JSON list.",
        )

    write_snapshot(snapshot_path, payload)
    # LOLBAS entries carry no publish date and the catalog is a bare list with
    # nowhere to put one, so the server's Last-Modified is the only date
    # available. record_download stores it as a validator regardless; naming it
    # the content date here is what makes the age reported honest.
    record_download(snapshot_path, response, response.headers.get("last-modified"))

    return success_response(
        TOOL_NAME,
        query,
        {
            "snapshot_path": str(snapshot_path),
            "source_url": source_url,
            "downloaded": True,
            "content_date": response.headers.get("last-modified"),
            "entry_count": len(payload),
        },
    )


def main() -> int:
    """Run the update command and print a structured JSON result."""
    result = update_lolbas_snapshot()
    print(json.dumps(result, indent=2, sort_keys=True))
    return 0 if result["ok"] else 1


if __name__ == "__main__":
    sys.exit(main())
