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
from threatsyft.snapshot_meta import parse_timestamp, read_meta

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

    Two different ages, because they answer two different questions and conflating
    them is what made the old mtime-only version wrong:

    ``as_of`` and ``age_days`` describe *the data* — when upstream published it.
    That is the number behind "not known to be exploited as of the 7th".

    ``checked_at`` and ``days_since_checked`` describe *us* — when the updater
    last got an answer from upstream, including an answer of "nothing changed".

    ``stale`` keys off the check, not the content. A quiet upstream is not a
    problem and nothing can be done about it; an updater that stopped running is
    a problem with an obvious fix, and that is what the flag should mean. It also
    survives conditional downloads: a 304 refreshes the check timestamp without
    rewriting the file, where an mtime-based answer would drift toward stale
    while the data was in fact current.

    Falls back to the file's modified time for both when there is no sidecar,
    which is how an install predating the sidecar behaves and is still correct
    for a snapshot that was written by an unconditional download.
    """
    snapshot = SOURCE_SNAPSHOTS.get(source)
    if snapshot is None:
        return None

    path_getter, threshold = SNAPSHOTS[snapshot]
    path = path_getter()
    modified_at = _modified_at(path)
    if modified_at is None:
        return {
            "as_of": None,
            "age_days": None,
            "checked_at": None,
            "days_since_checked": None,
            "stale": None,
            "snapshot_present": False,
        }

    meta = read_meta(path)
    now = datetime.now(UTC)
    checked_at = parse_timestamp(meta.get("checked_at")) or modified_at
    content_at = parse_timestamp(meta.get("content_date")) or modified_at

    days_since_checked = _whole_days(now - checked_at)
    return {
        "as_of": content_at.isoformat(),
        "age_days": _whole_days(now - content_at),
        "checked_at": checked_at.isoformat(),
        "days_since_checked": days_since_checked,
        "stale": days_since_checked > threshold,
        "stale_after_days": threshold,
        "snapshot_present": True,
    }


def _whole_days(delta: timedelta) -> int:
    return int(delta // timedelta(days=1))


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
        f"The {snapshot} snapshot has not been checked against upstream for "
        f"{freshness['days_since_checked']} days (stale after "
        f"{freshness['stale_after_days']}). "
        f"Run `{knowledge_update_command(snapshot)}` to refresh it."
        for snapshot, freshness in sorted(stale.items())
    ]


def _modified_at(path: Path) -> datetime | None:
    try:
        return datetime.fromtimestamp(path.stat().st_mtime, UTC)
    except OSError:
        return None
