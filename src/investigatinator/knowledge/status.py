"""Local knowledge snapshot status checks."""

from __future__ import annotations

from collections.abc import Callable
from datetime import datetime
from pathlib import Path
from typing import Any
from zoneinfo import ZoneInfo

from investigatinator.config import (
    get_api_key,
    get_attack_stix_path,
    get_cisa_kev_path,
    get_d3fend_path,
    get_lolbas_path,
    get_nvd_base_url,
    knowledge_update_command,
)
from investigatinator.enrichment.models import success_response
from investigatinator.knowledge.attack import KnowledgeLoadError, load_attack_knowledge
from investigatinator.knowledge.d3fend import load_d3fend_catalog
from investigatinator.knowledge.kev import load_kev_catalog
from investigatinator.knowledge.lolbas import load_lolbas_catalog

TOOL_NAME = "knowledge_status"
NVD_API_KEY_NAME = "NVD_API_KEY"

Loader = Callable[[Path | None], Any]


def knowledge_status() -> dict[str, Any]:
    """Return local knowledge snapshot status without calling external providers."""
    snapshots = {
        "attack": _snapshot_status(
            get_attack_stix_path(),
            load_attack_knowledge,
            _attack_counts,
            knowledge_update_command("attack"),
        ),
        "d3fend": _snapshot_status(
            get_d3fend_path(),
            load_d3fend_catalog,
            _d3fend_counts,
            knowledge_update_command("d3fend"),
        ),
        "kev": _snapshot_status(
            get_cisa_kev_path(),
            load_kev_catalog,
            _kev_counts,
            knowledge_update_command("kev"),
        ),
        "lolbas": _snapshot_status(
            get_lolbas_path(),
            load_lolbas_catalog,
            _lolbas_counts,
            knowledge_update_command("lolbas"),
        ),
    }
    unavailable = [
        name for name, snapshot in snapshots.items() if snapshot["status"] != "available"
    ]

    return success_response(
        TOOL_NAME,
        {},
        {
            "local_only": True,
            "network_checked": False,
            "ready": not unavailable,
            "unavailable_snapshots": unavailable,
            "snapshots": snapshots,
            "live_tools": {
                "cve_lookup": {
                    "provider": "nvd",
                    "base_url": get_nvd_base_url(),
                    "api_key_name": NVD_API_KEY_NAME,
                    "api_key_configured": get_api_key(NVD_API_KEY_NAME) is not None,
                    "live_network": True,
                }
            },
        },
    )


def _snapshot_status(
    path: Path,
    loader: Loader,
    count_builder: Callable[[Any], dict[str, int]],
    setup_command: str,
) -> dict[str, Any]:
    base = {
        "path": str(path),
        "exists": path.exists(),
        "file_modified_at": _file_modified_at(path),
        "live_network": False,
        "setup_command": setup_command,
    }
    try:
        catalog = loader(path)
    except KnowledgeLoadError as exc:
        return {
            **base,
            "status": exc.code,
            "ok": False,
            "error": {
                "code": exc.code,
                "message": exc.message,
                "details": exc.details,
            },
            "counts": {},
        }

    return {
        **base,
        "status": "available",
        "ok": True,
        "error": None,
        "counts": count_builder(catalog),
        "source_updated_at": _source_updated_at(catalog),
    }


def _file_modified_at(path: Path) -> str | None:
    try:
        timestamp = path.stat().st_mtime
    except OSError:
        return None
    return datetime.fromtimestamp(timestamp, ZoneInfo("UTC")).isoformat()


def _source_updated_at(catalog: Any) -> str | None:
    for attribute in ["date_released", "catalog_version"]:
        value = getattr(catalog, attribute, None)
        if isinstance(value, str) and value:
            return value
    return None


def _attack_counts(catalog: Any) -> dict[str, int]:
    return {
        "techniques": len(catalog.techniques_by_id),
        "tactics": len(catalog.tactics_by_short_name),
    }


def _d3fend_counts(catalog: Any) -> dict[str, int]:
    return {
        "defensive_techniques": len(catalog.techniques_by_id),
        "defensive_tactics": len(catalog.tactics_by_name),
        "mappings": len(catalog.mappings),
    }


def _kev_counts(catalog: Any) -> dict[str, int]:
    return {"vulnerabilities": catalog.count}


def _lolbas_counts(catalog: Any) -> dict[str, int]:
    return {"entries": catalog.count}
