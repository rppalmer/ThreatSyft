"""How old each local snapshot is.

The reason this exists: "this CVE is not in KEV" reads as "not known to be
exploited", but on a snapshot that failed to refresh eight months ago the honest
statement is "not exploited as of eight months ago". Those are different claims,
and without an age the caller cannot tell them apart. So freshness rides along
on every response, on the failure path especially.

It reports age rather than refusing to answer past a threshold. Refusing would
break the offline case, which is the whole reason the snapshots exist.
"""

from __future__ import annotations

from datetime import datetime, timedelta
from pathlib import Path
from typing import Any
from zoneinfo import ZoneInfo

from threatsyft.config import get_attack_stix_path, get_cisa_kev_path, get_lolbas_path

UTC = ZoneInfo("UTC")

# Per source, because one global threshold would be wrong in both directions.
# CISA adds to KEV most weeks, so a fortnight-old copy is genuinely behind.
# ATT&CK publishes a few times a year, so the same age means nothing there.
STALE_AFTER_DAYS = {
    "kev": 14,
    "attack": 180,
    "lolbas": 180,
}

SNAPSHOT_PATHS = {
    "kev": get_cisa_kev_path,
    "attack": get_attack_stix_path,
    "lolbas": get_lolbas_path,
}


def snapshot_freshness(source: str) -> dict[str, Any] | None:
    """Return age metadata for one snapshot-backed source, or None if it has no snapshot.

    Reads the file's modified time rather than parsing the catalog, so it costs
    nothing and still works when the snapshot is missing or unreadable, which is
    exactly when a caller most needs to know.
    """
    path_getter = SNAPSHOT_PATHS.get(source)
    if path_getter is None:
        return None

    path = path_getter()
    modified_at = _modified_at(path)
    if modified_at is None:
        return {"as_of": None, "age_days": None, "stale": None, "snapshot_present": False}

    age_days = (datetime.now(UTC) - modified_at) // timedelta(days=1)
    threshold = STALE_AFTER_DAYS[source]
    return {
        "as_of": modified_at.isoformat(),
        "age_days": int(age_days),
        "stale": int(age_days) > threshold,
        "stale_after_days": threshold,
        "snapshot_present": True,
    }


def _modified_at(path: Path) -> datetime | None:
    try:
        return datetime.fromtimestamp(path.stat().st_mtime, UTC)
    except OSError:
        return None
