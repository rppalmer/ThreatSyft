"""RDAP enrichment lookups."""

from __future__ import annotations

from typing import Any

import httpx

from investigatinator.config import get_timeout_seconds
from investigatinator.enrichment.models import (
    InputValidationError,
    classify_target,
    error_response,
    success_response,
)

TOOL_NAME = "rdap_lookup"
RDAP_BASE_URL = "https://rdap.org"


def rdap_lookup(target: str) -> dict[str, Any]:
    """Look up compact RDAP details for a domain or IP address."""
    query = {"target": target}

    try:
        target_type, normalized_target = classify_target(target)
    except InputValidationError as exc:
        return error_response(TOOL_NAME, query, "invalid_input", str(exc))

    query.update({"target": normalized_target, "target_type": target_type})
    url = f"{RDAP_BASE_URL}/{target_type}/{normalized_target}"

    try:
        response = httpx.get(url, timeout=get_timeout_seconds(), follow_redirects=True)
        if response.status_code == 404:
            return error_response(TOOL_NAME, query, "not_found", "RDAP record was not found.")
        response.raise_for_status()
        payload = response.json()
    except httpx.TimeoutException:
        return error_response(TOOL_NAME, query, "timeout", "RDAP lookup timed out.")
    except httpx.HTTPStatusError as exc:
        return error_response(
            TOOL_NAME,
            query,
            "upstream_error",
            "RDAP provider returned an error.",
            {"status_code": exc.response.status_code},
        )
    except httpx.RequestError as exc:
        return error_response(TOOL_NAME, query, "network_error", "RDAP lookup failed.", str(exc))
    except ValueError as exc:
        return error_response(
            TOOL_NAME,
            query,
            "parse_error",
            "RDAP response was not JSON.",
            str(exc),
        )

    if not isinstance(payload, dict):
        return error_response(TOOL_NAME, query, "parse_error", "RDAP response was not an object.")

    return success_response(
        TOOL_NAME,
        query,
        {
            "target": normalized_target,
            "target_type": target_type,
            "handle": payload.get("handle"),
            "name": payload.get("name") or payload.get("ldhName"),
            "country": payload.get("country"),
            "status": _as_string_list(payload.get("status")),
            "entities": _extract_entity_names(payload.get("entities")),
            "nameservers": _extract_nameservers(payload.get("nameservers")),
            "events": _extract_events(payload.get("events")),
            "source_url": url,
        },
    )


def _as_string_list(value: object) -> list[str]:
    if not isinstance(value, list):
        return []
    return [item for item in value if isinstance(item, str)]


def _extract_entity_names(value: object) -> list[str]:
    if not isinstance(value, list):
        return []

    names: list[str] = []
    for entity in value:
        if not isinstance(entity, dict):
            continue
        name = _entity_name(entity)
        if name:
            names.append(name)
    return names


def _entity_name(entity: dict[str, Any]) -> str | None:
    vcard = entity.get("vcardArray")
    if not isinstance(vcard, list) or len(vcard) < 2 or not isinstance(vcard[1], list):
        return entity.get("handle") if isinstance(entity.get("handle"), str) else None

    for item in vcard[1]:
        if (
            isinstance(item, list)
            and len(item) >= 4
            and item[0] in {"fn", "org"}
            and isinstance(item[3], str)
        ):
            return item[3]

    return entity.get("handle") if isinstance(entity.get("handle"), str) else None


def _extract_nameservers(value: object) -> list[str]:
    if not isinstance(value, list):
        return []

    nameservers: list[str] = []
    for nameserver in value:
        if not isinstance(nameserver, dict):
            continue
        name = nameserver.get("ldhName") or nameserver.get("unicodeName")
        if isinstance(name, str):
            nameservers.append(name.rstrip(".").lower())
    return nameservers


def _extract_events(value: object) -> list[dict[str, str]]:
    if not isinstance(value, list):
        return []

    events: list[dict[str, str]] = []
    for event in value:
        if not isinstance(event, dict):
            continue
        action = event.get("eventAction")
        date = event.get("eventDate")
        if isinstance(action, str) and isinstance(date, str):
            events.append({"action": action, "date": date})
    return events
