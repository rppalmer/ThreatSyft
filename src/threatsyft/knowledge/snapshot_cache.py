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

# One lock per snapshot path rather than one global lock. Holding a lock across
# the parse is the point of it (see load_cached), and a single global lock would
# make a cold KEV parse wait behind a cold ATT&CK parse for no reason.
_registry_lock = Lock()
_path_locks: dict[str, Lock] = {}


def _lock_for(key: str) -> Lock:
    with _registry_lock:
        return _path_locks.setdefault(key, Lock())


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


def write_binary_snapshot(path: Path, payload: bytes) -> None:
    """Write a binary snapshot atomically, with the same guarantee as ``write_snapshot``.

    The MaxMind databases are ``.mmdb`` binary search tries rather than JSON, so
    they cannot go through ``write_snapshot``. The reason for the temporary file
    and rename is identical and matters more here: a truncated ``.mmdb`` is not a
    parse error the reader reports cleanly, and the City database is large enough
    that an interrupted write is a realistic outcome rather than a theoretical one.
    """
    path.parent.mkdir(parents=True, exist_ok=True, mode=0o700)
    temporary_path = path.with_name(f"{path.name}.tmp")
    temporary_path.write_bytes(payload)
    os.replace(temporary_path, path)


def load_cached[T](cache: dict[str, tuple[float, T]], path: Path, parse: Callable[[], T]) -> T:
    """Return a parsed snapshot, reusing a cached parse when the file is unchanged.

    ``parse`` is only invoked on a cache miss and is responsible for reading and
    parsing ``path``. A parse that raises (missing or malformed snapshot) is never
    cached, so the proper load error surfaces on every call until the file is fixed.

    The parse runs *inside* the per-path lock, so concurrent misses on the same
    snapshot parse once and the rest wait for the result. Callers fan out: a
    bare-name ``lookup`` asks the tactic and threat-actor catalogs in two threads,
    and both resolve against the same file. Parsing outside the lock let both
    threads read and parse the 47 MB ATT&CK snapshot at once on a cold cache,
    which roughly doubled peak memory for no benefit. A hit stays lock-free —
    the dict read is atomic, and it is the path taken by every call after the
    first.
    """
    key = str(path)
    try:
        mtime = path.stat().st_mtime
    except OSError:
        # Missing or unreadable: let parse() raise the domain-specific load error.
        return parse()

    entry = cache.get(key)
    if entry is not None and entry[0] == mtime:
        return entry[1]

    with _lock_for(key):
        # Re-checked under the lock: whoever held it first may have parsed this
        # very snapshot while this thread was waiting.
        entry = cache.get(key)
        if entry is not None and entry[0] == mtime:
            return entry[1]

        value = parse()
        cache[key] = (mtime, value)
        return value
