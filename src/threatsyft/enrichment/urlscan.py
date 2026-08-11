"""urlscan.io lookups over scans that already exist.

Answers "what is this page", which the other URL sources do not. Safe Browsing
says whether a URL is on a blocklist and VirusTotal counts vendors; neither says
where the URL finally lands after redirects, what the page calls itself, or
which host actually served it. A urlscan record carries all three.

Search only, never submit. urlscan's submit endpoint sends a scanner to visit
the target, and its default visibility is public, so submitting from inside the
``enrich`` fan-out would both take an active action against the target and
publish the fact that this URL is being investigated. Adversaries watch that
feed. Reading existing scans is passive and has neither consequence, so this
module has no code path that can submit.

The API key is optional here, unlike every other keyed provider. Unauthenticated
search works at a lower quota, so a missing key degrades the rate limit rather
than removing the source.
"""

from __future__ import annotations

from typing import Any

import httpx

from threatsyft.config import get_api_key, get_timeout_seconds, get_urlscan_base_url
from threatsyft.enrichment.http import (
    auth_or_rate_error,
    guarded_get,
    parse_json_object,
)
from threatsyft.enrichment.models import (
    InputValidationError,
    error_response,
    normalize_url,
    success_response,
)

TOOL_NAME = "urlscan_search"
API_KEY_NAME = "URLSCAN_API_KEY"
PROVIDER = "urlscan.io"

# A popular URL has thousands of scans and they repeat the same page. The most
# recent few carry the answer; the rest are history no triage question asks for.
MAX_RESULTS = 10

PAGE_FIELDS = (
    # The URL actually loaded, which is the redirect destination rather than the
    # URL submitted. This is the field the other URL sources cannot produce.
    "url",
    "domain",
    "ip",
    "asn",
    "asnname",
    "country",
    "server",
    "title",
    "tlsIssuer",
    "mimeType",
    "status",
)

TASK_FIELDS = ("url", "time", "visibility", "method", "source")

STATS_FIELDS = ("uniqIPs", "uniqCountries", "dataLength", "requests", "malicious")


def urlscan_search(url: str) -> dict[str, Any]:
    """Look up existing urlscan.io scans for one URL."""
    query = {"url": url}

    try:
        normalized_url = normalize_url(url)
    except InputValidationError as exc:
        return error_response(TOOL_NAME, query, "invalid_input", str(exc))

    query["url"] = normalized_url

    request_url = f"{get_urlscan_base_url()}/search/"
    params = {"q": f'page.url:"{_escape_query_value(normalized_url)}"', "size": MAX_RESULTS}

    # Sent only when configured. urlscan accepts anonymous search, so an absent
    # key is a smaller quota rather than a failed lookup.
    api_key = get_api_key(API_KEY_NAME)
    headers = {"Accept": "application/json"}
    if api_key is not None:
        headers["API-Key"] = api_key

    result = guarded_get(
        TOOL_NAME,
        query,
        PROVIDER,
        lambda: httpx.get(
            request_url, params=params, headers=headers, timeout=get_timeout_seconds()
        ),
    )
    if result.error:
        return result.error
    response = result.response

    auth_error = auth_or_rate_error(TOOL_NAME, query, PROVIDER, response)
    if auth_error:
        return auth_error

    parsed = parse_json_object(TOOL_NAME, query, PROVIDER, response)
    if parsed.error:
        return parsed.error
    payload = parsed.payload

    results = payload.get("results")
    results = results if isinstance(results, list) else []

    return success_response(
        TOOL_NAME,
        query,
        {
            "url": normalized_url,
            # urlscan's own total for the query, which can exceed the rows below.
            "total": payload.get("total"),
            "scan_count": len(results),
            "scans": [_scan(entry) for entry in results[:MAX_RESULTS]],
            "authenticated": api_key is not None,
            "source": "urlscan",
            "source_url": "https://urlscan.io/",
            "note": (
                "Existing public scans only; no scan was submitted. "
                "No results means nobody has scanned this URL, not that it is safe."
            ),
        },
    )


def _scan(entry: Any) -> dict[str, Any]:
    """Reduce one scan record to page identity and its permalinks.

    A search row embeds the full task, page, stats and lists of every contacted
    domain. The lists are the bulk of it and belong to the individual scan
    report, which ``result_url`` points at.
    """
    if not isinstance(entry, dict):
        return {}

    scan = {
        "scan_id": entry.get("_id"),
        "task": _subset(entry.get("task"), TASK_FIELDS),
        "page": _subset(entry.get("page"), PAGE_FIELDS),
        "stats": _subset(entry.get("stats"), STATS_FIELDS),
        # Pro-tier field naming the impersonated brand; absent on free keys.
        "brand": entry.get("brand"),
        "result_url": entry.get("result"),
        "screenshot_url": entry.get("screenshot"),
    }
    return {key: value for key, value in scan.items() if value not in (None, {}, [])}


def _subset(value: Any, fields: tuple[str, ...]) -> dict[str, Any] | None:
    if not isinstance(value, dict):
        return None
    return {field: value[field] for field in fields if field in value}


def _escape_query_value(value: str) -> str:
    """Escape a value for interpolation into a quoted Elasticsearch phrase.

    urlscan's ``q`` is a query string, so a URL containing a quote would close
    the phrase early and the rest of it would be read as query syntax. Only the
    backslash and the double quote can do that inside a quoted phrase, and the
    backslash has to go first so it does not double-escape the quotes added
    after it.
    """
    return value.replace("\\", "\\\\").replace('"', '\\"')
