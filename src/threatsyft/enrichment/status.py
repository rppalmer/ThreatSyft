"""Local enrichment configuration status."""

from __future__ import annotations

from typing import Any

from threatsyft.config import get_api_key
from threatsyft.enrichment.models import success_response
from threatsyft.enrichment.providers import PROVIDERS

TOOL_NAME = "enrichment_status"

LOCAL_TOOLS = {
    "dns_lookup": "Live DNS lookup without a configured API key.",
    "rdap_lookup": "Live RDAP lookup without a configured API key.",
    "whois_lookup": "Live WHOIS lookup without a configured API key.",
}

ALL_API_KEYS = sorted({name for metadata in PROVIDERS.values() for name in metadata["api_keys"]})


def enrichment_status() -> dict[str, Any]:
    """Return local enrichment provider configuration without calling providers."""
    providers = {
        provider: {
            "tools": metadata["tools"],
            "api_keys": _api_key_status(metadata["api_keys"]),
            "configured": all(get_api_key(name) is not None for name in metadata["api_keys"]),
        }
        for provider, metadata in PROVIDERS.items()
    }

    return success_response(
        TOOL_NAME,
        {},
        {
            "local_only": True,
            "network_checked": False,
            "live_network": False,
            "providers": providers,
            "local_tools": LOCAL_TOOLS,
            "configured_api_keys": [name for name in ALL_API_KEYS if get_api_key(name) is not None],
            "missing_api_keys": [name for name in ALL_API_KEYS if get_api_key(name) is None],
            "secret_values_returned": False,
        },
    )


def _api_key_status(api_keys: list[str]) -> dict[str, bool]:
    return {name: get_api_key(name) is not None for name in api_keys}
