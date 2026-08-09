"""Local enrichment configuration status."""

from __future__ import annotations

from typing import Any

from threatsyft.config import get_api_key
from threatsyft.enrichment.enrich import DISPATCH
from threatsyft.enrichment.models import success_response
from threatsyft.enrichment.providers import PROVIDERS

TOOL_NAME = "enrichment_status"

# Sources enrich calls that need no API key, so a caller can see that some
# coverage survives with nothing configured at all.
KEYLESS_SOURCES = {
    "dns": "DNS records for a domain.",
    "rdap": "RDAP registration data for a domain or IP.",
    "whois": "WHOIS registration data for a domain or IP.",
}

ALL_API_KEYS = sorted({name for keys in PROVIDERS.values() for name in keys})


def enrichment_status() -> dict[str, Any]:
    """Return local enrichment provider configuration without calling providers."""
    providers = {
        provider: {
            "api_keys": {name: get_api_key(name) is not None for name in api_keys},
            "configured": all(get_api_key(name) is not None for name in api_keys),
            "indicator_types": _indicator_types(provider),
        }
        for provider, api_keys in PROVIDERS.items()
    }

    return success_response(
        TOOL_NAME,
        {},
        {
            "local_only": True,
            "network_checked": False,
            "live_network": False,
            "providers": providers,
            "keyless_sources": KEYLESS_SOURCES,
            "configured_api_keys": [name for name in ALL_API_KEYS if get_api_key(name) is not None],
            "missing_api_keys": [name for name in ALL_API_KEYS if get_api_key(name) is None],
            "secret_values_returned": False,
        },
    )


def _indicator_types(provider: str) -> list[str]:
    """Which indicator types enrich will call this provider for.

    Derived from the dispatch table rather than restated, so a provider added to
    or removed from a dispatch row cannot leave this reporting the old answer.
    """
    return [
        indicator_type
        for indicator_type, sources in DISPATCH.items()
        if any(name == provider for name, _ in sources)
    ]
