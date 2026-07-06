"""Download the local MITRE ATT&CK Enterprise STIX snapshot."""

from __future__ import annotations

import json
import sys
from typing import Any

import httpx

from threatsyft.config import get_attack_stix_path, get_attack_stix_url, get_timeout_seconds
from threatsyft.core import error_response, success_response

TOOL_NAME = "attack_snapshot_update"


def update_attack_snapshot() -> dict[str, Any]:
    """Download and validate the ATT&CK Enterprise STIX snapshot."""
    snapshot_path = get_attack_stix_path()
    source_url = get_attack_stix_url()
    query = {"source_url": source_url, "snapshot_path": str(snapshot_path)}

    if not source_url:
        return error_response(
            TOOL_NAME,
            query,
            "invalid_input",
            "ATT&CK STIX source URL must not be empty.",
        )

    try:
        response = httpx.get(source_url, timeout=get_timeout_seconds())
    except httpx.TimeoutException:
        return error_response(TOOL_NAME, query, "timeout", "ATT&CK STIX download timed out.")
    except httpx.RequestError as exc:
        return error_response(
            TOOL_NAME,
            query,
            "network_error",
            "ATT&CK STIX download failed.",
            {"reason": str(exc)},
        )

    if response.status_code >= 400:
        return error_response(
            TOOL_NAME,
            query,
            "upstream_error",
            f"ATT&CK STIX download failed with HTTP {response.status_code}.",
            {"status_code": response.status_code},
        )

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

    snapshot_path.parent.mkdir(parents=True, exist_ok=True)
    snapshot_path.write_text(json.dumps(payload, indent=2, sort_keys=True) + "\n", encoding="utf-8")

    return success_response(
        TOOL_NAME,
        query,
        {
            "snapshot_path": str(snapshot_path),
            "source_url": source_url,
            "object_count": len(payload["objects"]),
        },
    )


def main() -> int:
    """Run the update command and print a structured JSON result."""
    result = update_attack_snapshot()
    print(json.dumps(result, indent=2, sort_keys=True))
    return 0 if result["ok"] else 1


if __name__ == "__main__":
    sys.exit(main())
