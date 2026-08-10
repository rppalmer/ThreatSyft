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
from concurrent.futures import Future, ThreadPoolExecutor
from typing import Any

from threatsyft.core import error_response

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

    return [(name, _envelope(name, futures[name])) for name, _ in sources]


def _envelope(name: str, future: Future[dict[str, Any]]) -> dict[str, Any]:
    """Return the source's envelope, or build one if it raised instead.

    Sources are expected to return an error envelope rather than raise, and
    nearly all of them do. Without this guard the exception from the one that
    does not propagates out of the whole fan-out: the tool returns no envelope
    at all, the results already collected from every other source are thrown
    away, and the caller sees a protocol-level transport error instead of the
    documented shape. One broken source has to cost one source, which is the
    guarantee every other failure path already gives.
    """
    try:
        return future.result()
    except Exception as exc:
        return error_response(
            name,
            {},
            "unexpected_error",
            f"{name} failed unexpectedly.",
            f"{type(exc).__name__}: {exc}",
        )
