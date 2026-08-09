"""In-process caching for local knowledge snapshots.

The MCP servers are long-lived processes, so re-reading and re-parsing a
multi-megabyte snapshot on every tool call is pure waste. Each parsed catalog
is cached keyed by ``(path, file-mtime)``; when an explicit ``threatsyft-update``
rewrites a snapshot, its mtime changes and the next lookup reparses, so the
"updates refresh the snapshot" contract keeps working without a restart.
"""

from __future__ import annotations

import json
import os
from collections.abc import Callable
from pathlib import Path
from threading import Lock
from typing import Any

_lock = Lock()


def write_snapshot(path: Path, payload: Any) -> None:
    """Write a snapshot atomically, so a partial write cannot replace a good file.

    Writing straight onto the live path means an interruption — a crash, a full
    disk, a Ctrl-C — leaves truncated JSON behind. Every later lookup then fails
    to parse it, and keeps failing until the update is run again, because a failed
    parse is deliberately never cached. Snapshots are large enough (ATT&CK is
    ~47 MB) that the interruption window is real rather than theoretical.

    Writing to a sibling temporary file and renaming makes the replacement atomic
    on every platform ThreatSyft targets: readers see either the previous
    snapshot or the new one, never a half-written file. Shared by all four update
    commands so the guarantee cannot hold in some of them and not others.
    """
    # 0o700 because this tree lives beside ~/.threatsyft/.env. The catalogs
    # themselves are public, so this is about the directory's neighbours rather
    # than the data. mode applies only to directories this call creates; an
    # existing one keeps its mode.
    path.parent.mkdir(parents=True, exist_ok=True, mode=0o700)
    temporary_path = path.with_name(f"{path.name}.tmp")
    temporary_path.write_text(
        json.dumps(payload, indent=2, sort_keys=True) + "\n",
        encoding="utf-8",
    )
    os.replace(temporary_path, path)


def load_cached[T](cache: dict[str, tuple[float, T]], path: Path, parse: Callable[[], T]) -> T:
    """Return a parsed snapshot, reusing a cached parse when the file is unchanged.

    ``parse`` is only invoked on a cache miss and is responsible for reading and
    parsing ``path``. A parse that raises (missing or malformed snapshot) is never
    cached, so the proper load error surfaces on every call until the file is fixed.
    """
    key = str(path)
    try:
        mtime = path.stat().st_mtime
    except OSError:
        # Missing or unreadable: let parse() raise the domain-specific load error.
        return parse()

    with _lock:
        entry = cache.get(key)
        if entry is not None and entry[0] == mtime:
            return entry[1]

    value = parse()

    with _lock:
        cache[key] = (mtime, value)
    return value
