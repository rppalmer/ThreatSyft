"""Shared concurrent fan-out across several sources for one query.

Every collection tool asks the same question of several independent sources.
Those calls are independent and often network-bound, so they run concurrently
rather than serially: wall-clock latency collapses from the sum of the
per-source timeouts to roughly the slowest single source. Results are assembled
in ``sources`` order regardless of which one finishes first, so a response never
reorders because a source happened to be slow.

Lives in a neutral top-level module rather than under ``enrichment/`` for the
same reason ``core.py`` does: the knowledge tools fan out exactly as enrichment
does, and neither package should have to import the other to do it.
"""

from __future__ import annotations

from collections.abc import Callable, Sequence
from concurrent.futures import ThreadPoolExecutor
from typing import Any

SourceFunction = tuple[str, Callable[[str], dict[str, Any]]]


def run_sources(
    sources: Sequence[SourceFunction],
    target: str,
) -> list[tuple[str, dict[str, Any]]]:
    """Call every source for ``target`` concurrently, in ``sources`` order.

    Returns ``(name, envelope)`` pairs with each source's full response envelope,
    successful or not. Splitting success from failure is the caller's job, and
    the shared ``sources`` map keeps them together anyway.
    """
    if not sources:
        return []

    with ThreadPoolExecutor(max_workers=len(sources)) as pool:
        futures = {name: pool.submit(function, target) for name, function in sources}

    return [(name, futures[name].result()) for name, _ in sources]
