"""Download the local MITRE ATT&CK Enterprise STIX snapshot."""

from __future__ import annotations

import json
import sys
from typing import Any

from threatsyft.config import get_attack_stix_path, get_attack_stix_url
from threatsyft.core import error_response, success_response
from threatsyft.knowledge.snapshot_cache import write_snapshot
from threatsyft.knowledge.snapshot_fetch import (
    fetch_snapshot,
    record_download,
    unchanged_response,
)

TOOL_NAME = "attack_snapshot_update"
LABEL = "ATT&CK STIX"


def update_attack_snapshot() -> dict[str, Any]:
    """Download and validate the ATT&CK Enterprise STIX snapshot."""
    snapshot_path = get_attack_stix_path()
    source_url = get_attack_stix_url()
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
            "ATT&CK STIX download did not return valid JSON.",
            {"reason": str(exc)},
        )

    if not isinstance(payload, dict) or not isinstance(payload.get("objects"), list):
        return error_response(
            TOOL_NAME,
            query,
            "parse_error",
            "ATT&CK STIX download must contain an objects list.",
        )

    write_snapshot(snapshot_path, payload)
    content_date = _newest_modified(payload["objects"])
    record_download(snapshot_path, response, content_date)

    return success_response(
        TOOL_NAME,
        query,
        {
            "snapshot_path": str(snapshot_path),
            "source_url": source_url,
            "downloaded": True,
            "content_date": content_date,
            "object_count": len(payload["objects"]),
        },
    )


def _newest_modified(objects: list[Any]) -> str | None:
    """Date the bundle by its most recently modified object.

    A STIX bundle carries no release date of its own — only ``id`` and ``type``
    sit beside the objects — so the newest ``modified`` timestamp in it is the
    closest thing to "when was this data published". Computed once at download
    rather than on every freshness check, because the bundle is ~47 MB.
    """
    newest: str | None = None
    for item in objects:
        if not isinstance(item, dict):
            continue
        modified = item.get("modified")
        if isinstance(modified, str) and (newest is None or modified > newest):
            newest = modified
    return newest


def main() -> int:
    """Run the update command and print a structured JSON result."""
    result = update_attack_snapshot()
    print(json.dumps(result, indent=2, sort_keys=True))
    return 0 if result["ok"] else 1


if __name__ == "__main__":
    sys.exit(main())
