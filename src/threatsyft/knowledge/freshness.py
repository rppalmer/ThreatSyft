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

from threatsyft.config import (
    get_attack_stix_path,
    get_cisa_kev_path,
    get_lolbas_path,
    knowledge_update_command,
)

UTC = ZoneInfo("UTC")

# One entry per snapshot file, not per source name. The threshold is per source
# because one global value would be wrong in both directions: CISA adds to KEV
# most weeks, so a fortnight-old copy is genuinely behind, while ATT&CK
# publishes a few times a year and the same age means nothing.
SNAPSHOTS = {
    "kev": (get_cisa_kev_path, 14),
    "attack": (get_attack_stix_path, 180),
    "lolbas": (get_lolbas_path, 180),
}

# Which snapshot each source name reads. Several sources resolve against the
# same ATT&CK file, and listing them here rather than duplicating the path and
# threshold means adding one cannot leave it silently without freshness. The
# keys are source names as they appear in a `sources` map, which `lookup` and
# `search` now spell identically.
SOURCE_SNAPSHOTS = {
    "kev": "kev",
    "lolbas": "lolbas",
    "attack_technique": "attack",
    "attack_tactic": "attack",
    "attack_mitigation": "attack",
    "attack_actor": "attack",
    "attack_software": "attack",
}

STALE_AFTER_DAYS = {source: SNAPSHOTS[snapshot][1] for source, snapshot in SOURCE_SNAPSHOTS.items()}


def snapshot_freshness(source: str) -> dict[str, Any] | None:
    """Return age metadata for one snapshot-backed source, or None if it has no snapshot.

    Reads the file's modified time rather than parsing the catalog, so it costs
    nothing and still works when the snapshot is missing or unreadable, which is
    exactly when a caller most needs to know.
    """
    snapshot = SOURCE_SNAPSHOTS.get(source)
    if snapshot is None:
        return None

    path_getter, threshold = SNAPSHOTS[snapshot]
    path = path_getter()
    modified_at = _modified_at(path)
    if modified_at is None:
        return {"as_of": None, "age_days": None, "stale": None, "snapshot_present": False}

    age_days = (datetime.now(UTC) - modified_at) // timedelta(days=1)
    return {
        "as_of": modified_at.isoformat(),
        "age_days": int(age_days),
        "stale": int(age_days) > threshold,
        "stale_after_days": threshold,
        "snapshot_present": True,
    }


def staleness_warnings(source_entries: dict[str, Any]) -> list[str]:
    """Lift stale snapshots into messages a caller cannot miss.

    ``freshness`` already rides on every snapshot-backed source, but it sits one
    level inside the entry beside a dozen other fields, which is exactly where a
    reader stops looking. Age only does its job if the reader notices it, so a
    snapshot past its own threshold is restated at the top of the response.

    Each warning names the command that fixes it. Thresholds stay per source:
    CISA adds to KEV most weeks, while ATT&CK ships a few times a year, so one
    shared number would either miss a stale KEV or warn about ATT&CK constantly.
    A warning that is always on is one nobody reads.

    A missing snapshot is not warned about here. That already surfaces as a
    ``not_found`` naming its setup command, and saying it twice adds nothing.

    Keyed by snapshot rather than by source name, because several sources read
    the same file: a bare-name lookup asks the technique, tactic and actor
    catalogs, and all three are the one ATT&CK snapshot. Warning per source name
    would say the same thing three times.
    """
    stale: dict[str, dict[str, Any]] = {}
    for name, entry in sorted(source_entries.items()):
        freshness = entry.get("freshness") if isinstance(entry, dict) else None
        if not isinstance(freshness, dict) or freshness.get("stale") is not True:
            continue
        snapshot = SOURCE_SNAPSHOTS.get(name)
        if snapshot is not None:
            stale.setdefault(snapshot, freshness)

    return [
        f"The {snapshot} snapshot is {freshness['age_days']} days old "
        f"(stale after {freshness['stale_after_days']}). "
        f"Run `{knowledge_update_command(snapshot)}` to refresh it."
        for snapshot, freshness in sorted(stale.items())
    ]


def _modified_at(path: Path) -> datetime | None:
    try:
        return datetime.fromtimestamp(path.stat().st_mtime, UTC)
    except OSError:
        return None
