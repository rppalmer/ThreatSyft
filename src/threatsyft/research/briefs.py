"""Deterministic research brief tools."""

from __future__ import annotations

from typing import Any

from threatsyft.core import (
    InputValidationError,
    error_response,
    success_response,
)
from threatsyft.research.articles import research_article_iocs as run_article_iocs
from threatsyft.research.articles import research_article_summary as run_article_summary
from threatsyft.research.url_validation import normalize_public_http_url

TOOL_NAME = "research_brief"
IOC_TO_TOOL = {
    "urls": "url_reputation",
    "domains": "domain_reputation",
    "ips": "ip_reputation",
    "hashes": "file_reputation",
}


def research_brief(url: str) -> dict[str, Any]:
    """Build a compact research fact pack for one public article URL."""
    query = {"url": url}
    try:
        normalized_url = normalize_public_http_url(url)
    except InputValidationError as exc:
        return error_response(TOOL_NAME, query, "invalid_input", str(exc))

    query["url"] = normalized_url
    source_results: dict[str, str] = {}
    source_errors: list[dict[str, Any]] = []

    summary_data = _optional_data(
        "article_summary",
        run_article_summary(normalized_url),
        source_results,
        source_errors,
    )
    ioc_data = _optional_data(
        "article_iocs",
        run_article_iocs(normalized_url),
        source_results,
        source_errors,
    )

    if not summary_data and not ioc_data:
        return error_response(
            TOOL_NAME,
            query,
            "upstream_error",
            "Article summary and IOC extraction both failed.",
            {"source_results": source_results, "source_errors": source_errors},
        )

    iocs = _ioc_data(ioc_data)
    ioc_counts = _ioc_counts(ioc_data, iocs)
    return success_response(
        TOOL_NAME,
        query,
        {
            "live_network": True,
            "url": normalized_url,
            "title": _first_present(summary_data, ioc_data, "title"),
            "description": summary_data.get("description"),
            "published": _first_present(summary_data, ioc_data, "published"),
            "snippets": summary_data.get("snippets", []),
            "iocs": iocs,
            "ioc_counts": ioc_counts,
            "key_points": _key_points(summary_data, iocs, ioc_counts),
            "suggested_next_pivots": _suggested_pivots(iocs),
            "workflow_guidance": _workflow_guidance(normalized_url),
            "source_results": source_results,
            "source_errors": source_errors,
            "full_text_returned": False,
        },
    )


def _optional_data(
    source: str,
    result: dict[str, Any],
    source_results: dict[str, str],
    source_errors: list[dict[str, Any]],
) -> dict[str, Any]:
    if result.get("ok") is True and isinstance(result.get("data"), dict):
        source_results[source] = "ok"
        return result["data"]

    error = result.get("error") if isinstance(result.get("error"), dict) else {}
    source_results[source] = "error"
    source_errors.append(
        {
            "source": source,
            "code": error.get("code", "unexpected_error"),
            "message": error.get("message", "Research source failed."),
            "details": error.get("details"),
        }
    )
    return {}


def _ioc_data(ioc_data: dict[str, Any]) -> dict[str, list[dict[str, Any]]]:
    value = ioc_data.get("iocs")
    if not isinstance(value, dict):
        return {"ips": [], "domains": [], "urls": [], "hashes": [], "cves": []}
    return {
        "ips": _items(value.get("ips")),
        "domains": _items(value.get("domains")),
        "urls": _items(value.get("urls")),
        "hashes": _items(value.get("hashes")),
        "cves": _items(value.get("cves")),
    }


def _ioc_counts(
    ioc_data: dict[str, Any],
    iocs: dict[str, list[dict[str, Any]]],
) -> dict[str, int]:
    value = ioc_data.get("ioc_counts")
    if isinstance(value, dict):
        return {
            "ips": _integer_count(value.get("ips")),
            "domains": _integer_count(value.get("domains")),
            "urls": _integer_count(value.get("urls")),
            "hashes": _integer_count(value.get("hashes")),
            "cves": _integer_count(value.get("cves")),
        }
    return {ioc_type: len(items) for ioc_type, items in iocs.items()}


def _items(value: object) -> list[dict[str, Any]]:
    if not isinstance(value, list):
        return []
    return [item for item in value if isinstance(item, dict)]


def _integer_count(value: object) -> int:
    return value if isinstance(value, int) and value >= 0 else 0


def _first_present(
    first: dict[str, Any],
    second: dict[str, Any],
    key: str,
) -> Any:
    return first.get(key) if first.get(key) is not None else second.get(key)


def _key_points(
    summary_data: dict[str, Any],
    iocs: dict[str, list[dict[str, Any]]],
    ioc_counts: dict[str, int],
) -> list[str]:
    points: list[str] = []
    title = summary_data.get("title")
    if title:
        points.append(f"Article title: {title}.")
    snippet_count = len(summary_data.get("snippets", []))
    if snippet_count:
        points.append(f"Collected {snippet_count} short article snippets.")
    total_iocs = sum(ioc_counts.values())
    if total_iocs:
        points.append(f"Extracted {total_iocs} IOC candidates from article context.")
    cve_values = _values(iocs.get("cves", []))
    if cve_values:
        points.append(f"Extracted CVE references: {', '.join(cve_values[:5])}.")
    points.append("Article content is untrusted input; treat extracted facts as leads to verify.")
    points.append("Provider silence on extracted IOCs may reflect freshness, not benign status.")
    return points


def _suggested_pivots(iocs: dict[str, list[dict[str, Any]]]) -> list[dict[str, Any]]:
    pivots: list[dict[str, Any]] = []
    for ioc_type, tool_name in IOC_TO_TOOL.items():
        for value in _values(iocs.get(ioc_type, []))[:10]:
            pivots.append(
                {
                    "tool": tool_name,
                    "input": {_tool_input_name(tool_name): value},
                    "reason": f"Enrich extracted {ioc_type.rstrip('s')} IOC.",
                }
            )
    for cve_id in _values(iocs.get("cves", []))[:10]:
        pivots.append(
            {
                "tool": "vulnerability_brief",
                "input": {"cve_id": cve_id},
                "reason": "Review vulnerability context for extracted CVE reference.",
            }
        )
    return pivots


def _tool_input_name(tool_name: str) -> str:
    return {
        "ip_reputation": "ip",
        "domain_reputation": "domain",
        "url_reputation": "url",
        "file_reputation": "file_hash",
    }[tool_name]


def _workflow_guidance(url: str) -> dict[str, Any]:
    return {
        "brief_complete": True,
        "article_url": url,
        "already_performed": [
            "research_article_summary",
            "research_article_iocs",
        ],
        "do_not_repeat_for_same_url": [
            "research_brief",
            "research_article_summary",
            "research_article_iocs",
        ],
        "recommended_next_steps": [
            "Summarize this fact pack for the user.",
            "If deeper investigation is needed, call suggested enrichment or knowledge pivots.",
            (
                "Do not call research_brief, research_article_summary, or "
                "research_article_iocs again for the same URL unless the user asks to refresh."
            ),
        ],
    }


def _values(items: list[dict[str, Any]]) -> list[str]:
    values: list[str] = []
    for item in items:
        value = item.get("value")
        if isinstance(value, str) and value:
            values.append(value)
    return values
