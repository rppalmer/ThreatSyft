"""Download the local CISA Known Exploited Vulnerabilities catalog."""

from __future__ import annotations

import json
import sys
from typing import Any

import httpx

from investigatinator.config import get_cisa_kev_path, get_cisa_kev_url, get_timeout_seconds
from investigatinator.enrichment.models import error_response, success_response

TOOL_NAME = "kev_snapshot_update"


def update_kev_snapshot() -> dict[str, Any]:
    """Download and validate the CISA KEV catalog snapshot."""
    snapshot_path = get_cisa_kev_path()
    source_url = get_cisa_kev_url()
    query = {"source_url": source_url, "snapshot_path": str(snapshot_path)}

    if not source_url:
        return error_response(
            TOOL_NAME,
            query,
            "invalid_input",
            "CISA KEV source URL must not be empty.",
        )

    try:
        response = httpx.get(source_url, timeout=get_timeout_seconds())
    except httpx.TimeoutException:
        return error_response(TOOL_NAME, query, "timeout", "CISA KEV download timed out.")
    except httpx.RequestError as exc:
        return error_response(
            TOOL_NAME,
            query,
            "network_error",
            "CISA KEV download failed.",
            {"reason": str(exc)},
        )

    if response.status_code >= 400:
        return error_response(
            TOOL_NAME,
            query,
            "upstream_error",
            f"CISA KEV download failed with HTTP {response.status_code}.",
            {"status_code": response.status_code},
        )

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

    snapshot_path.parent.mkdir(parents=True, exist_ok=True)
    snapshot_path.write_text(json.dumps(payload, indent=2, sort_keys=True) + "\n", encoding="utf-8")

    return success_response(
        TOOL_NAME,
        query,
        {
            "snapshot_path": str(snapshot_path),
            "source_url": source_url,
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
