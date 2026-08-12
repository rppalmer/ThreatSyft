"""Local MaxMind GeoLite2 geolocation and ASN lookups.

Replaces the IPGeolocation.io provider. The data is the same shape — country,
region, city, postal code, coordinates, timezone, AS number and organization —
but it comes off a local database file rather than an eleventh network call
inside every IP enrichment, so it costs no latency, no API quota and no key at
lookup time.

The trade is that a local database goes stale silently. A six-month-old GeoLite2
answers confidently and wrongly, so every response carries the build date MaxMind
stamped into the file and how old it is. That is read from the database's own
metadata rather than the file's mtime, which would only say when this machine
wrote it.

Freshness is computed here rather than imported from ``knowledge.freshness``
because enrichment does not depend on the knowledge package. The duplication is
a few lines and the alternative is a dependency edge the architecture rules out.
"""

from __future__ import annotations

import threading
from datetime import datetime, timedelta
from pathlib import Path
from typing import Any
from zoneinfo import ZoneInfo

import maxminddb

from threatsyft.config import (
    get_maxmind_asn_path,
    get_maxmind_city_path,
    knowledge_update_command,
)
from threatsyft.enrichment.models import (
    InputValidationError,
    error_response,
    normalize_ip,
    success_response,
)

TOOL_NAME = "maxmind_ip_lookup"
UTC = ZoneInfo("UTC")

# GeoLite2 is rebuilt twice a week. A month is generous for a free tier and
# still flags a database that stopped refreshing.
STALE_AFTER_DAYS = 30

# Readers are memory-mapped and reused across calls: the MCP servers are
# long-lived, and reopening the City database on every lookup would remap the
# file each time. Keyed by (path, mtime) so an update replacing the file is
# picked up without a restart, the same contract the JSON snapshots have.
_readers: dict[str, tuple[float, Any]] = {}
_readers_lock = threading.Lock()


def maxmind_ip_lookup(ip: str) -> dict[str, Any]:
    """Look up local GeoLite2 geolocation and ASN detail for one IP address."""
    query = {"ip": ip}

    try:
        normalized_ip = normalize_ip(ip)
    except InputValidationError as exc:
        return error_response(TOOL_NAME, query, "invalid_input", str(exc))

    query["ip"] = normalized_ip

    city_path = get_maxmind_city_path()
    if not city_path.exists():
        # Same shape the knowledge snapshots use for this: a not_found carrying
        # the command that fixes it, so a caller is told what to run rather than
        # just that something is absent.
        return error_response(
            TOOL_NAME,
            query,
            "not_found",
            "The GeoLite2 City database snapshot was not found.",
            {
                "snapshot_path": str(city_path),
                "setup_command": knowledge_update_command("maxmind"),
            },
        )

    try:
        city_reader = _reader(city_path)
        city_record = city_reader.get(normalized_ip)
    except (maxminddb.InvalidDatabaseError, OSError, ValueError) as exc:
        return error_response(
            TOOL_NAME,
            query,
            "parse_error",
            "The GeoLite2 City database could not be read.",
            {"reason": f"{type(exc).__name__}: {exc}", "snapshot_path": str(city_path)},
        )

    asn_record, asn_error = _asn_record(normalized_ip)

    data: dict[str, Any] = {
        "ip": normalized_ip,
        "source": "maxmind",
        "source_url": "https://www.maxmind.com/",
        **_location_fields(city_record),
        **_asn_fields(asn_record),
        "database": _database_freshness(city_path, city_reader),
        "note": (
            "GeoLite2 is a local free-tier database; city-level placement is "
            "approximate and country-level is the reliable field."
        ),
    }
    if asn_error:
        # Reported rather than raised: the City answer is still good, and a
        # caller should be able to see exactly which half was unavailable.
        data["asn_unavailable"] = asn_error
    if city_record is None:
        data["note"] = "This address is not present in the GeoLite2 City database."

    # Declared by the source that knows its own age. ``enrich`` collects these
    # into one top-level list without needing to understand any provider's
    # freshness shape, and without enrichment importing knowledge.freshness.
    database = data["database"]
    if database.get("stale") is True:
        data["staleness_warning"] = (
            f"The GeoLite2 database is {database['age_days']} days old "
            f"(stale after {database['stale_after_days']}). "
            f"Run `{knowledge_update_command('maxmind')}` to refresh it. "
            "Geolocation drifts as addresses are reassigned."
        )

    return success_response(TOOL_NAME, query, data)


def _asn_record(normalized_ip: str) -> tuple[dict[str, Any] | None, str | None]:
    """Read the ASN database, treating its absence as a gap rather than a failure."""
    asn_path = get_maxmind_asn_path()
    if not asn_path.exists():
        return None, "The GeoLite2 ASN database has not been downloaded."
    try:
        return _reader(asn_path).get(normalized_ip), None
    except (maxminddb.InvalidDatabaseError, OSError, ValueError) as exc:
        return None, f"The GeoLite2 ASN database could not be read: {type(exc).__name__}"


def _location_fields(record: Any) -> dict[str, Any]:
    """Flatten the City record into the field names the fan-out already uses."""
    if not isinstance(record, dict):
        return {
            "country_name": None,
            "country_code": None,
            "region": None,
            "city": None,
            "zipcode": None,
            "latitude": None,
            "longitude": None,
            "time_zone": None,
        }

    country = _sub(record, "country")
    location = _sub(record, "location")
    subdivisions = record.get("subdivisions")
    region = subdivisions[0] if isinstance(subdivisions, list) and subdivisions else {}

    return {
        "country_name": _english(country.get("names")),
        "country_code": country.get("iso_code"),
        "region": _english(region.get("names")) if isinstance(region, dict) else None,
        "city": _english(_sub(record, "city").get("names")),
        "zipcode": _sub(record, "postal").get("code"),
        "latitude": location.get("latitude"),
        "longitude": location.get("longitude"),
        "time_zone": location.get("time_zone"),
    }


def _asn_fields(record: Any) -> dict[str, Any]:
    if not isinstance(record, dict):
        return {"asn": None, "organization": None}
    return {
        "asn": record.get("autonomous_system_number"),
        "organization": record.get("autonomous_system_organization"),
    }


def _database_freshness(path: Path, reader: Any) -> dict[str, Any]:
    """Report the build date MaxMind stamped into the database, and its age."""
    try:
        build_epoch = reader.metadata().build_epoch
    except (AttributeError, maxminddb.InvalidDatabaseError):
        return {"built_at": None, "age_days": None, "stale": None}

    built_at = datetime.fromtimestamp(build_epoch, UTC)
    age_days = int((datetime.now(UTC) - built_at) // timedelta(days=1))
    return {
        "built_at": built_at.isoformat(),
        "age_days": age_days,
        "stale": age_days > STALE_AFTER_DAYS,
        "stale_after_days": STALE_AFTER_DAYS,
        "snapshot_path": str(path),
    }


def _reader(path: Path) -> Any:
    """Return a cached reader for one database, reopening when the file changes."""
    key = str(path)
    mtime = path.stat().st_mtime

    entry = _readers.get(key)
    if entry is not None and entry[0] == mtime:
        return entry[1]

    with _readers_lock:
        entry = _readers.get(key)
        if entry is not None and entry[0] == mtime:
            return entry[1]

        reader = maxminddb.open_database(path)
        previous = _readers.get(key)
        _readers[key] = (mtime, reader)
        if previous is not None:
            # The replaced reader holds an mmap; closing it releases the handle
            # on the old file, which matters because an update rewrites in place.
            previous[1].close()
        return reader


def _sub(record: dict[str, Any], key: str) -> dict[str, Any]:
    value = record.get(key)
    return value if isinstance(value, dict) else {}


def _english(names: Any) -> str | None:
    if not isinstance(names, dict):
        return None
    return names.get("en")
