"""Download the local MaxMind GeoLite2 databases.

Two editions, because together they cover what a geolocation lookup is asked
for: City carries country, region, city, postal code, coordinates and timezone;
ASN carries the AS number and the organization behind it.

Unlike the other snapshot updaters, this one asks before it fetches. MaxMind
reserves the right to rate-limit downloads, and a HEAD against the permalink
returns the build date without counting against the daily limit. So an edition
whose build date already matches the local copy is skipped rather than
re-downloaded, which makes running this on a schedule cheap and keeps a
scheduled updater inside MaxMind's terms.

Authentication is HTTP basic with the account ID as the username and the license
key as the password. The older ``/app/geoip_download?license_key=`` endpoint is
deprecated and now fails, so there is no fallback to it.
"""

from __future__ import annotations

import io
import tarfile
from typing import Any

import httpx

from threatsyft.config import (
    get_api_key,
    get_maxmind_account_id,
    get_maxmind_asn_path,
    get_maxmind_base_url,
    get_maxmind_city_path,
    get_timeout_seconds,
)
from threatsyft.core import error_response, success_response
from threatsyft.knowledge.snapshot_cache import write_binary_snapshot
from threatsyft.snapshot_meta import read_meta, write_meta

TOOL_NAME = "maxmind_snapshot_update"
LICENSE_KEY_NAME = "MAXMIND_LICENSE_KEY"
ACCOUNT_ID_NAME = "MAXMIND_ACCOUNT_ID"

# The archive is tens of megabytes, so the download gets a floor well above the
# per-request timeout tuned for small JSON API calls.
MINIMUM_DOWNLOAD_TIMEOUT_SECONDS = 120.0

EDITIONS = {
    "GeoLite2-City": get_maxmind_city_path,
    "GeoLite2-ASN": get_maxmind_asn_path,
}


def update_maxmind_snapshot() -> dict[str, Any]:
    """Download both GeoLite2 databases, skipping editions that are already current."""
    query = {"editions": sorted(EDITIONS)}

    account_id = get_maxmind_account_id()
    license_key = get_api_key(LICENSE_KEY_NAME)
    if account_id is None or license_key is None:
        return error_response(
            TOOL_NAME,
            query,
            "missing_api_key",
            f"{ACCOUNT_ID_NAME} and {LICENSE_KEY_NAME} must both be configured.",
        )

    results: dict[str, Any] = {}
    failures: list[str] = []
    for edition, path_getter in EDITIONS.items():
        result = _update_edition(edition, path_getter(), account_id, license_key)
        results[edition] = result
        if result.get("ok") is not True:
            failures.append(edition)

    data = {
        "editions": results,
        "updated_edition_count": len(EDITIONS) - len(failures),
        "failed_editions": failures,
    }
    if failures:
        return error_response(
            TOOL_NAME,
            query,
            "upstream_error",
            "One or more GeoLite2 edition downloads failed.",
            data,
        )
    return success_response(TOOL_NAME, query, data)


def _update_edition(edition, path, account_id: str, license_key: str) -> dict[str, Any]:
    """Refresh one edition, downloading only when the remote build is newer."""
    query = {"edition": edition, "snapshot_path": str(path)}
    url = f"{get_maxmind_base_url()}/{edition}/download"
    auth = (account_id, license_key)
    params = {"suffix": "tar.gz"}

    # Asked first because it is free of the download quota. A build date that
    # matches what is already on disk means there is nothing to fetch.
    head = _request(
        query,
        lambda: httpx.head(
            url, params=params, auth=auth, timeout=get_timeout_seconds(), follow_redirects=True
        ),
    )
    if head.get("error"):
        return head["error"]

    remote_build = head["response"].headers.get("Last-Modified")
    if remote_build and _local_build(path) == remote_build:
        # A matching build is still a successful check, so the sidecar is
        # re-stamped. Without that, a database kept current by daily skipped
        # downloads would drift toward looking abandoned.
        write_meta(path, content_date=remote_build, last_modified=remote_build)
        return success_response(
            TOOL_NAME,
            query,
            {
                "edition": edition,
                "downloaded": False,
                "reason": "local copy already matches the published build",
                "build": remote_build,
                "snapshot_path": str(path),
            },
        )

    download = _request(
        query,
        lambda: httpx.get(
            url,
            params=params,
            auth=auth,
            timeout=max(get_timeout_seconds(), MINIMUM_DOWNLOAD_TIMEOUT_SECONDS),
            follow_redirects=True,
        ),
    )
    if download.get("error"):
        return download["error"]
    response = download["response"]

    if response.status_code in {401, 403}:
        return error_response(
            TOOL_NAME,
            query,
            "authentication_error",
            "MaxMind rejected the configured account ID and license key.",
            {"status_code": response.status_code},
        )
    if response.status_code == 429:
        return error_response(
            TOOL_NAME,
            query,
            "rate_limited",
            "MaxMind download rate limit was reached.",
            {"status_code": response.status_code},
        )
    if response.status_code >= 400:
        return error_response(
            TOOL_NAME,
            query,
            "upstream_error",
            f"MaxMind download failed with HTTP {response.status_code}.",
            {"status_code": response.status_code},
        )

    try:
        database = _extract_database(response.content, edition)
    except ValueError as exc:
        return error_response(TOOL_NAME, query, "parse_error", str(exc))

    write_binary_snapshot(path, database)
    build = response.headers.get("Last-Modified") or remote_build
    write_meta(path, content_date=build, last_modified=build)

    return success_response(
        TOOL_NAME,
        query,
        {
            "edition": edition,
            "downloaded": True,
            "build": build,
            "byte_count": len(database),
            "snapshot_path": str(path),
        },
    )


def _request(query: dict[str, Any], call) -> dict[str, Any]:
    """Run one httpx call, mapping transport failures onto error envelopes."""
    try:
        return {"response": call()}
    except httpx.TimeoutException:
        return {"error": error_response(TOOL_NAME, query, "timeout", "MaxMind request timed out.")}
    except httpx.RequestError as exc:
        return {
            "error": error_response(
                TOOL_NAME, query, "network_error", "MaxMind request failed.", {"reason": str(exc)}
            )
        }


def _extract_database(archive: bytes, edition: str) -> bytes:
    """Pull the single ``.mmdb`` member out of the downloaded tarball.

    The archive holds a date-stamped directory rather than a bare file, so the
    member is located by extension instead of by a path that changes with every
    build. Members are not extracted to disk, so a crafted archive cannot write
    outside the snapshot directory.
    """
    try:
        with tarfile.open(fileobj=io.BytesIO(archive), mode="r:gz") as bundle:
            for member in bundle.getmembers():
                if not member.isfile() or not member.name.endswith(".mmdb"):
                    continue
                extracted = bundle.extractfile(member)
                if extracted is None:
                    continue
                return extracted.read()
    except tarfile.TarError as exc:
        raise ValueError(f"{edition} download was not a readable tar.gz archive.") from exc

    raise ValueError(f"{edition} archive contained no .mmdb database.")


def _local_build(path) -> str | None:
    """Return the published build recorded for the local copy, if any.

    Read from the sidecar rather than inferred from the file's mtime, because
    mtime records when this machine wrote the file and the comparison needs what
    MaxMind published. A missing sidecar just means the next run downloads once
    and writes one.
    """
    if not path.exists():
        return None
    recorded = read_meta(path).get("last_modified")
    return recorded if isinstance(recorded, str) and recorded else None
