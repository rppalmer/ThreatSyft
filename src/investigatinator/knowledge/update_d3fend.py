"""Download the local MITRE D3FEND combined JSON snapshot."""

from __future__ import annotations

import json
import sys
from typing import Any

import httpx

from investigatinator.config import (
    get_d3fend_mappings_url,
    get_d3fend_path,
    get_d3fend_tactics_url,
    get_d3fend_techniques_url,
    get_timeout_seconds,
)
from investigatinator.enrichment.models import error_response, success_response

TOOL_NAME = "d3fend_snapshot_update"


def update_d3fend_snapshot() -> dict[str, Any]:
    """Download and validate the D3FEND snapshot pieces."""
    snapshot_path = get_d3fend_path()
    urls = {
        "techniques": get_d3fend_techniques_url(),
        "tactics": get_d3fend_tactics_url(),
        "mappings": get_d3fend_mappings_url(),
    }
    query = {"source_urls": urls, "snapshot_path": str(snapshot_path)}

    for label, url in urls.items():
        if not url:
            return error_response(
                TOOL_NAME,
                query,
                "invalid_input",
                f"D3FEND {label} source URL must not be empty.",
            )

    payload: dict[str, Any] = {}
    for label, url in urls.items():
        result = _download_json(label, url)
        if result["ok"] is not True:
            return error_response(
                TOOL_NAME,
                query,
                result["code"],
                result["message"],
                result.get("details"),
            )
        payload[label] = result["data"]

    validation_error = _validate_snapshot(payload)
    if validation_error is not None:
        return error_response(
            TOOL_NAME,
            query,
            "parse_error",
            validation_error,
        )

    snapshot_path.parent.mkdir(parents=True, exist_ok=True)
    snapshot_path.write_text(json.dumps(payload, indent=2, sort_keys=True) + "\n", encoding="utf-8")

    return success_response(
        TOOL_NAME,
        query,
        {
            "snapshot_path": str(snapshot_path),
            "source_urls": urls,
            "technique_count": len(payload["techniques"]["@graph"]),
            "tactic_count": len(payload["tactics"]["@graph"]),
            "mapping_count": len(payload["mappings"]["results"]["bindings"]),
        },
    )


def _download_json(label: str, url: str) -> dict[str, Any]:
    try:
        response = httpx.get(url, timeout=get_timeout_seconds())
    except httpx.TimeoutException:
        return {"ok": False, "code": "timeout", "message": f"D3FEND {label} download timed out."}
    except httpx.RequestError as exc:
        return {
            "ok": False,
            "code": "network_error",
            "message": f"D3FEND {label} download failed.",
            "details": {"reason": str(exc)},
        }

    if response.status_code >= 400:
        return {
            "ok": False,
            "code": "upstream_error",
            "message": f"D3FEND {label} download failed with HTTP {response.status_code}.",
            "details": {"status_code": response.status_code},
        }

    try:
        return {"ok": True, "data": response.json()}
    except ValueError as exc:
        return {
            "ok": False,
            "code": "parse_error",
            "message": f"D3FEND {label} download did not return valid JSON.",
            "details": {"reason": str(exc)},
        }


def _validate_snapshot(payload: dict[str, Any]) -> str | None:
    techniques = payload.get("techniques")
    tactics = payload.get("tactics")
    mappings = payload.get("mappings")
    if not isinstance(techniques, dict) or not isinstance(techniques.get("@graph"), list):
        return "D3FEND techniques download must contain an @graph list."
    if not isinstance(tactics, dict) or not isinstance(tactics.get("@graph"), list):
        return "D3FEND tactics download must contain an @graph list."
    if not isinstance(mappings, dict):
        return "D3FEND mappings download must be a JSON object."
    results = mappings.get("results")
    bindings = results.get("bindings") if isinstance(results, dict) else None
    if not isinstance(bindings, list):
        return "D3FEND mappings download must contain results.bindings."
    return None


def main() -> int:
    """Run the update command and print a structured JSON result."""
    result = update_d3fend_snapshot()
    print(json.dumps(result, indent=2, sort_keys=True))
    return 0 if result["ok"] else 1


if __name__ == "__main__":
    sys.exit(main())
