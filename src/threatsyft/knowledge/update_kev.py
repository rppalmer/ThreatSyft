"""Download the local CISA Known Exploited Vulnerabilities catalog."""

from __future__ import annotations

import json
import sys
from typing import Any

from threatsyft.config import get_cisa_kev_path, get_cisa_kev_url
from threatsyft.core import error_response, success_response
from threatsyft.knowledge.snapshot_cache import write_snapshot
from threatsyft.knowledge.snapshot_fetch import (
    fetch_snapshot,
    record_download,
    unchanged_response,
)

TOOL_NAME = "kev_snapshot_update"
LABEL = "CISA KEV"


def update_kev_snapshot() -> dict[str, Any]:
    """Download and validate the CISA KEV catalog snapshot."""
    snapshot_path = get_cisa_kev_path()
    source_url = get_cisa_kev_url()
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
            "CISA KEV download did not return valid JSON.",
            {"reason": str(exc)},
        )

    if not isinstance(payload, dict) or not isinstance(payload.get("vulnerabilities"), list):
        return error_response(
            TOOL_NAME,
            query,
            "parse_error",
            "CISA KEV download must contain a vulnerabilities list.",
        )

    write_snapshot(snapshot_path, payload)
    # CISA stamps the catalog with its own release date, which is the honest
    # answer to "how old is this data". The file's mtime only says when this
    # machine wrote it.
    content_date = payload.get("dateReleased")
    record_download(
        snapshot_path, response, content_date if isinstance(content_date, str) else None
    )

    return success_response(
        TOOL_NAME,
        query,
        {
            "snapshot_path": str(snapshot_path),
            "source_url": source_url,
            "downloaded": True,
            "content_date": content_date,
            "catalog_version": payload.get("catalogVersion"),
            "vulnerability_count": len(payload["vulnerabilities"]),
        },
    )


def main() -> int:
    """Run the update command and print a structured JSON result."""
    result = update_kev_snapshot()
    print(json.dumps(result, indent=2, sort_keys=True))
    return 0 if result["ok"] else 1


if __name__ == "__main__":
    sys.exit(main())
