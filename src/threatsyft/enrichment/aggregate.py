"""Shared provider fan-out for aggregate reputation fact packs.

Each aggregate tool queries several independent providers for the same
indicator. Those calls are network-bound and independent, so they run
concurrently rather than serially: wall-clock latency collapses from the sum of
the per-provider timeouts to roughly the slowest single provider. Results and
errors are still assembled in ``providers`` order so output stays deterministic.
"""

from __future__ import annotations

from collections.abc import Callable, Sequence
from concurrent.futures import ThreadPoolExecutor
from typing import Any

ProviderFunction = tuple[str, Callable[[str], dict[str, Any]]]


def run_providers(
    providers: Sequence[ProviderFunction],
    target: str,
) -> tuple[dict[str, dict[str, Any]], list[dict[str, Any]]]:
    """Call every provider for ``target`` concurrently and split results from errors.

    Returns ``(provider_results, provider_errors)`` where ``provider_results`` maps
    provider name to its ``data`` payload for successful lookups, and
    ``provider_errors`` is an ordered list of ``{provider, code, message}`` entries
    for lookups that failed. Ordering follows ``providers`` regardless of which
    provider finishes first.
    """
    if not providers:
        return {}, []

    with ThreadPoolExecutor(max_workers=len(providers)) as pool:
        futures = {name: pool.submit(function, target) for name, function in providers}

    provider_results: dict[str, dict[str, Any]] = {}
    provider_errors: list[dict[str, Any]] = []
    for name, _ in providers:
        result = futures[name].result()
        if result.get("ok") is True and isinstance(result.get("data"), dict):
            provider_results[name] = result["data"]
            continue

        error = result.get("error") if isinstance(result.get("error"), dict) else {}
        provider_errors.append(
            {
                "provider": name,
                "code": error.get("code", "unexpected_error"),
                "message": error.get("message", "Provider lookup failed."),
            }
        )

    return provider_results, provider_errors
