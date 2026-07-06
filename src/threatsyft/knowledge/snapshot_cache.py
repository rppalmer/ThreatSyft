"""In-process caching for local knowledge snapshots.

The MCP servers are long-lived processes, so re-reading and re-parsing a
multi-megabyte snapshot on every tool call is pure waste. Each parsed catalog
is cached keyed by ``(path, file-mtime)``; when an explicit ``knowledge-update``
rewrites a snapshot, its mtime changes and the next lookup reparses, so the
"updates refresh the snapshot" contract keeps working without a restart.
"""

from __future__ import annotations

from collections.abc import Callable
from pathlib import Path
from threading import Lock

_lock = Lock()


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
