"""Local enrichment configuration status."""

from __future__ import annotations

from typing import Any

from threatsyft.config import get_api_key
from threatsyft.enrichment.models import success_response
from threatsyft.tool_catalog import (
    DOMAIN_REPUTATION_KEYS,
    FACT_PACK_KEYS,
    FILE_REPUTATION_KEYS,
    IP_REPUTATION_KEYS,
    PROVIDERS,
    URL_REPUTATION_KEYS,
)

TOOL_NAME = "enrichment_status"

LOCAL_TOOLS = {
    "dns_lookup": "Live DNS lookup without a configured API key.",
    "rdap_lookup": "Live RDAP lookup without a configured API key.",
    "whois_lookup": "Live WHOIS lookup without a configured API key.",
}

FACT_PACKS = {
    "ip_reputation": IP_REPUTATION_KEYS,
    "domain_reputation": DOMAIN_REPUTATION_KEYS,
    "url_reputation": URL_REPUTATION_KEYS,
    "file_reputation": FILE_REPUTATION_KEYS,
}


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
    configured_api_keys = sorted(name for name in FACT_PACK_KEYS if get_api_key(name) is not None)
    missing_api_keys = sorted(name for name in FACT_PACK_KEYS if get_api_key(name) is None)

    return success_response(
        TOOL_NAME,
        {},
        {
            "local_only": True,
            "network_checked": False,
            "live_network": False,
            "providers": providers,
            "local_tools": LOCAL_TOOLS,
            "fact_packs": {
                name: {
                    "required_api_keys": keys,
                    "configured_api_keys": [key for key in keys if get_api_key(key) is not None],
                    "missing_api_keys": [key for key in keys if get_api_key(key) is None],
                }
                for name, keys in FACT_PACKS.items()
            },
            "configured_api_keys": configured_api_keys,
            "missing_api_keys": missing_api_keys,
            "secret_values_returned": False,
        },
    )


def _api_key_status(api_keys: list[str]) -> dict[str, bool]:
    return {name: get_api_key(name) is not None for name in api_keys}
