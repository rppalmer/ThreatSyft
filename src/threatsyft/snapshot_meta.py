"""Sidecar metadata for downloaded snapshots.

Two questions get confused when a snapshot's age is taken from its file mtime,
and they need separating:

- *How old is the data?* Answered by the date upstream published it.
- *How long since we checked?* Answered by when the updater last talked to
  upstream, whether or not anything came back changed.

Mtime answers neither reliably. It records when this machine last wrote the
file, which equals the publish date only by accident and equals the check date
only while every update rewrites the file unconditionally. The moment an updater
skips a download because nothing changed, mtime stops moving and a
content-unchanged snapshot starts looking abandoned.

So each snapshot gets a sibling ``<name>.meta.json`` holding the publish date,
the HTTP validators needed to ask "has this changed?", and the timestamp of the
last successful check. Freshness reads it; the updaters write it.

Lives at the top level rather than under ``knowledge`` because the enrichment
package needs it for the GeoLite2 databases and must not import ``knowledge``,
the same reason ``core`` and ``fanout`` sit here.

Every read is defensive. A missing, unreadable or malformed sidecar returns an
empty mapping, and callers fall back to mtime, which is exactly how the project
behaved before this file existed.
"""

from __future__ import annotations

import json
from datetime import datetime
from email.utils import parsedate_to_datetime
from pathlib import Path
from typing import Any
from zoneinfo import ZoneInfo

UTC = ZoneInfo("UTC")

META_SUFFIX = ".meta.json"


def meta_path(snapshot_path: Path) -> Path:
    """Return the sidecar path for one snapshot."""
    return snapshot_path.with_name(f"{snapshot_path.name}{META_SUFFIX}")


def read_meta(snapshot_path: Path) -> dict[str, Any]:
    """Return a snapshot's sidecar, or an empty mapping when there is not a usable one."""
    try:
        raw = meta_path(snapshot_path).read_text(encoding="utf-8")
    except OSError:
        return {}

    try:
        payload = json.loads(raw)
    except ValueError:
        return {}

    return payload if isinstance(payload, dict) else {}


def write_meta(
    snapshot_path: Path,
    *,
    content_date: str | None = None,
    etag: str | None = None,
    last_modified: str | None = None,
    checked_at: datetime | None = None,
) -> None:
    """Record what upstream said and that we just heard it say so.

    ``checked_at`` is stamped on every call, including the call made after a 304,
    because "asked upstream and it said nothing changed" is a successful check.
    That is the whole point: it lets a conditional updater keep a snapshot
    looking current without rewriting a byte of it.

    Failures are swallowed. A sidecar that cannot be written costs one redundant
    download next run and a fall back to mtime for age; neither is worth failing
    an otherwise good update over.
    """
    stamped = (checked_at or datetime.now(UTC)).isoformat()
    payload = {
        "content_date": content_date,
        "etag": etag,
        "last_modified": last_modified,
        "checked_at": stamped,
    }
    try:
        target = meta_path(snapshot_path)
        target.parent.mkdir(parents=True, exist_ok=True, mode=0o700)
        target.write_text(json.dumps(payload, indent=2, sort_keys=True) + "\n", encoding="utf-8")
    except OSError:
        return


def conditional_headers(snapshot_path: Path) -> dict[str, str]:
    """Build the request headers that let upstream answer 304 instead of resending.

    Both validators are sent when both are known. They are not interchangeable in
    practice: GitHub's raw host answers ``If-None-Match`` and CISA ignores it,
    because CISA's ETag varies per content encoding, but CISA does honour
    ``If-Modified-Since``. Sending both covers every source this project uses
    without special-casing any of them.
    """
    meta = read_meta(snapshot_path)
    headers: dict[str, str] = {}
    etag = meta.get("etag")
    last_modified = meta.get("last_modified")
    if isinstance(etag, str) and etag:
        headers["If-None-Match"] = etag
    if isinstance(last_modified, str) and last_modified:
        headers["If-Modified-Since"] = last_modified
    return headers


def parse_timestamp(value: Any) -> datetime | None:
    """Parse a sidecar timestamp, treating anything unreadable as absent.

    Two formats, because the sources differ. CISA stamps the KEV catalog with
    ISO-8601 and ATT&CK's STIX objects do the same, but LOLBAS has no date of
    its own, so its publish date is the server's ``Last-Modified`` header, which
    is an RFC 7231 HTTP date. Both are accepted rather than normalised at write
    time, so a sidecar keeps whatever upstream actually said.
    """
    if not isinstance(value, str) or not value:
        return None

    try:
        parsed = datetime.fromisoformat(value.replace("Z", "+00:00"))
    except ValueError:
        try:
            parsed = parsedate_to_datetime(value)
        except (TypeError, ValueError):
            return None

    return parsed if parsed.tzinfo else parsed.replace(tzinfo=UTC)
