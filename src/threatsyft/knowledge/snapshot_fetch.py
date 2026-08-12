"""One conditional download shared by the knowledge snapshot updaters.

Every updater used to refetch on every run. That is not just wasted bandwidth:
``write_snapshot`` replaces the file, which moves its mtime, and the in-process
parse cache is keyed on mtime, so a pointless rewrite makes every running MCP
server drop its parsed catalog and reparse. ATT&CK is ~47 MB parsed, so the
project was paying that to end up with byte-identical data.

All three sources support conditional requests, verified against them directly:
GitHub raw (ATT&CK, LOLBAS) answers 304 to ``If-None-Match``, and CISA ignores
that but answers 304 to ``If-Modified-Since``. So both validators go out and a
304 means there is nothing to do.

A 304 still counts as a successful check, and ``snapshot_meta`` records it. That
is what keeps a skipped download from making a current snapshot look abandoned.
"""

from __future__ import annotations

from dataclasses import dataclass
from pathlib import Path
from typing import Any

import httpx

from threatsyft.config import get_timeout_seconds
from threatsyft.core import error_response, success_response
from threatsyft.snapshot_meta import conditional_headers, read_meta, write_meta


@dataclass(frozen=True)
class FetchOutcome:
    """Exactly one of: nothing changed, a body to process, or an error to return."""

    unchanged: bool = False
    response: httpx.Response | None = None
    error: dict[str, Any] | None = None


def fetch_snapshot(
    tool: str,
    query: dict[str, Any],
    label: str,
    url: str,
    snapshot_path: Path,
) -> FetchOutcome:
    """Ask upstream for a snapshot, sending validators so it can answer 304."""
    if not url:
        return FetchOutcome(
            error=error_response(
                tool, query, "invalid_input", f"{label} source URL must not be empty."
            )
        )

    headers = conditional_headers(snapshot_path)

    try:
        response = httpx.get(
            url, headers=headers, timeout=get_timeout_seconds(), follow_redirects=True
        )
    except httpx.TimeoutException:
        return FetchOutcome(
            error=error_response(tool, query, "timeout", f"{label} download timed out.")
        )
    except httpx.RequestError as exc:
        return FetchOutcome(
            error=error_response(
                tool, query, "network_error", f"{label} download failed.", {"reason": str(exc)}
            )
        )

    if response.status_code == 304:
        # Nothing changed, but we did successfully check. Re-stamp the sidecar so
        # the snapshot's "last checked" moves even though the file does not.
        previous = read_meta(snapshot_path)
        write_meta(
            snapshot_path,
            content_date=previous.get("content_date"),
            etag=previous.get("etag"),
            last_modified=previous.get("last_modified"),
        )
        return FetchOutcome(unchanged=True)

    if response.status_code >= 400:
        return FetchOutcome(
            error=error_response(
                tool,
                query,
                "upstream_error",
                f"{label} download failed with HTTP {response.status_code}.",
                {"status_code": response.status_code},
            )
        )

    return FetchOutcome(response=response)


def record_download(
    snapshot_path: Path,
    response: httpx.Response,
    content_date: str | None,
) -> None:
    """Store the validators and publish date that came back with a fetched body."""
    write_meta(
        snapshot_path,
        content_date=content_date,
        etag=response.headers.get("etag"),
        last_modified=response.headers.get("last-modified"),
    )


def unchanged_response(
    tool: str,
    query: dict[str, Any],
    snapshot_path: Path,
    extra: dict[str, Any] | None = None,
) -> dict[str, Any]:
    """Build the success envelope for a snapshot that needed no download."""
    data = {
        "snapshot_path": str(snapshot_path),
        "downloaded": False,
        "reason": "upstream reports the local copy is current",
        "content_date": read_meta(snapshot_path).get("content_date"),
    }
    data.update(extra or {})
    return success_response(tool, query, data)
