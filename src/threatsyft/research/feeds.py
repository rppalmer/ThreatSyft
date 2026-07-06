"""Curated RSS and Atom feed search for public threat reporting."""

from __future__ import annotations

from dataclasses import dataclass
from datetime import UTC, datetime, timedelta
from email.utils import parsedate_to_datetime
from typing import Any
from xml.etree import ElementTree

import httpx

from threatsyft.config import (
    get_research_feeds,
    get_research_user_agent,
    get_timeout_seconds,
    research_feeds_source,
)
from threatsyft.core import (
    InputValidationError,
    error_response,
    success_response,
)
from threatsyft.research.url_validation import MAX_FETCH_BYTES, normalize_public_http_url

TOOL_NAME = "research_feed_search"
STATUS_TOOL_NAME = "research_feed_status"
MAX_LIMIT = 25
MAX_DAYS = 365


@dataclass(frozen=True)
class FeedEntry:
    """Normalized feed entry used for local filtering."""

    source_url: str
    feed_title: str | None
    title: str | None
    url: str | None
    summary: str | None
    published: datetime | None


def research_feed_search(query: str = "", limit: int = 10, days: int = 14) -> dict[str, Any]:
    """Search configured public research feeds for recent entries."""
    normalized_query = query.strip()
    request_query = {"query": normalized_query, "limit": limit, "days": days}

    if limit < 1 or limit > MAX_LIMIT:
        return error_response(
            TOOL_NAME,
            request_query,
            "invalid_input",
            f"Limit must be between 1 and {MAX_LIMIT}.",
        )
    if days < 1 or days > MAX_DAYS:
        return error_response(
            TOOL_NAME,
            request_query,
            "invalid_input",
            f"Days must be between 1 and {MAX_DAYS}.",
        )

    feed_urls = get_research_feeds()
    if not feed_urls:
        return error_response(
            TOOL_NAME,
            request_query,
            "invalid_input",
            "At least one research feed URL must be configured.",
        )

    entries: list[FeedEntry] = []
    source_errors: list[dict[str, Any]] = []
    for feed_url in feed_urls:
        try:
            normalized_feed_url = normalize_public_http_url(feed_url)
        except InputValidationError as exc:
            source_errors.append(_source_error(feed_url, "invalid_input", str(exc)))
            continue

        result = _fetch_feed(normalized_feed_url)
        if result["ok"] is not True:
            source_errors.append(
                _source_error(
                    normalized_feed_url,
                    result["code"],
                    result["message"],
                    result.get("details"),
                )
            )
            continue
        entries.extend(result["entries"])

    if not entries and source_errors:
        return error_response(
            TOOL_NAME,
            request_query,
            "upstream_error",
            "All configured research feeds failed.",
            {"source_errors": source_errors},
        )

    cutoff = datetime.now(UTC) - timedelta(days=days)
    matched_entries = [
        entry
        for entry in entries
        if _is_recent(entry.published, cutoff) and _matches_query(entry, normalized_query)
    ]
    matched_entries.sort(key=lambda item: item.published or datetime.min.replace(tzinfo=UTC))
    matched_entries.reverse()

    return success_response(
        TOOL_NAME,
        request_query,
        {
            "live_network": True,
            "feeds": feed_urls,
            "source_error_count": len(source_errors),
            "source_errors": source_errors,
            "result_count": min(len(matched_entries), limit),
            "interpretation": _search_interpretation(
                len(matched_entries),
                normalized_query,
                days,
            ),
            "entries": [_entry_data(entry, normalized_query) for entry in matched_entries[:limit]],
        },
    )


def research_feed_status() -> dict[str, Any]:
    """Return configured research feeds without fetching them."""
    feed_urls = get_research_feeds()
    return success_response(
        STATUS_TOOL_NAME,
        {},
        {
            "local_only": True,
            "network_checked": False,
            "live_network": False,
            "configured_feeds": feed_urls,
            "feed_count": len(feed_urls),
            "configuration_source": research_feeds_source(),
        },
    )


def _fetch_feed(feed_url: str) -> dict[str, Any]:
    try:
        response = httpx.get(
            feed_url,
            headers={"User-Agent": get_research_user_agent(), "Accept": "application/xml,text/xml"},
            timeout=get_timeout_seconds(),
        )
        response.raise_for_status()
    except httpx.TimeoutException:
        return {"ok": False, "code": "timeout", "message": "Research feed fetch timed out."}
    except httpx.HTTPStatusError as exc:
        return {
            "ok": False,
            "code": "upstream_error",
            "message": "Research feed returned an HTTP error.",
            "details": {"status_code": exc.response.status_code},
        }
    except httpx.RequestError as exc:
        return {
            "ok": False,
            "code": "network_error",
            "message": "Research feed fetch failed.",
            "details": str(exc),
        }

    try:
        root = ElementTree.fromstring(response.content[:MAX_FETCH_BYTES])
    except ElementTree.ParseError as exc:
        return {
            "ok": False,
            "code": "parse_error",
            "message": "Research feed was not valid XML.",
            "details": str(exc),
        }

    return {"ok": True, "entries": _parse_feed(root, feed_url)}


def _search_interpretation(match_count: int, query: str, days: int) -> str:
    if match_count:
        return "Matching entries were found in the configured feeds for this query window."
    if query:
        return (
            "No matching entries were found in the configured feeds for this query and "
            f"{days}-day window. This does not prove the topic is absent publicly."
        )
    return (
        "No recent entries were found in the configured feeds for this query window. "
        "This does not prove the sources are inactive or that public reporting is absent."
    )


def _parse_feed(root: ElementTree.Element, feed_url: str) -> list[FeedEntry]:
    root_name = _local_name(root.tag)
    if root_name == "rss":
        return _parse_rss(root, feed_url)
    if root_name == "feed":
        return _parse_atom(root, feed_url)
    return []


def _parse_rss(root: ElementTree.Element, feed_url: str) -> list[FeedEntry]:
    channel = _first_child(root, "channel")
    if channel is None:
        return []
    feed_title = _child_text(channel, "title")
    entries: list[FeedEntry] = []
    for item in [child for child in channel if _local_name(child.tag) == "item"]:
        title = _child_text(item, "title")
        link = _child_text(item, "link")
        summary = _child_text(item, "description")
        published = _parse_date(_child_text(item, "pubDate") or _child_text(item, "date"))
        if title or link:
            entries.append(
                FeedEntry(
                    source_url=feed_url,
                    feed_title=feed_title,
                    title=_clean_text(title),
                    url=_clean_text(link),
                    summary=_clean_text(summary),
                    published=published,
                )
            )
    return entries


def _parse_atom(root: ElementTree.Element, feed_url: str) -> list[FeedEntry]:
    feed_title = _child_text(root, "title")
    entries: list[FeedEntry] = []
    for entry in [child for child in root if _local_name(child.tag) == "entry"]:
        title = _child_text(entry, "title")
        link = _atom_link(entry)
        summary = _child_text(entry, "summary") or _child_text(entry, "content")
        published = _parse_date(_child_text(entry, "published") or _child_text(entry, "updated"))
        if title or link:
            entries.append(
                FeedEntry(
                    source_url=feed_url,
                    feed_title=_clean_text(feed_title),
                    title=_clean_text(title),
                    url=_clean_text(link),
                    summary=_clean_text(summary),
                    published=published,
                )
            )
    return entries


def _atom_link(entry: ElementTree.Element) -> str | None:
    for child in entry:
        if _local_name(child.tag) != "link":
            continue
        href = child.attrib.get("href")
        if href:
            return href
    return None


def _entry_data(entry: FeedEntry, query: str) -> dict[str, Any]:
    return {
        "title": entry.title,
        "url": entry.url,
        "source": entry.feed_title,
        "source_url": entry.source_url,
        "published": entry.published.isoformat() if entry.published else None,
        "summary": _truncate(entry.summary, 500),
        "matched_context": _matched_context(entry, query),
    }


def _matches_query(entry: FeedEntry, query: str) -> bool:
    if not query:
        return True
    haystack = " ".join(
        item for item in [entry.title, entry.summary, entry.url, entry.feed_title] if item
    ).lower()
    return all(term.lower() in haystack for term in query.split())


def _matched_context(entry: FeedEntry, query: str) -> str | None:
    text = " ".join(item for item in [entry.title, entry.summary] if item)
    if not text:
        return None
    if not query:
        return _truncate(text, 240)
    lower_text = text.lower()
    positions = [lower_text.find(term.lower()) for term in query.split()]
    positions = [position for position in positions if position >= 0]
    if not positions:
        return _truncate(text, 240)
    start = max(min(positions) - 80, 0)
    return _truncate(text[start:], 240)


def _is_recent(published: datetime | None, cutoff: datetime) -> bool:
    return published is None or published >= cutoff


def _parse_date(value: str | None) -> datetime | None:
    if not value:
        return None
    cleaned_value = value.strip()
    try:
        parsed = parsedate_to_datetime(cleaned_value)
    except (TypeError, ValueError):
        parsed = None
    if parsed is None:
        try:
            parsed = datetime.fromisoformat(cleaned_value.replace("Z", "+00:00"))
        except ValueError:
            return None
    if parsed.tzinfo is None:
        parsed = parsed.replace(tzinfo=UTC)
    return parsed.astimezone(UTC)


def _source_error(
    source_url: str,
    code: str,
    message: str,
    details: Any | None = None,
) -> dict[str, Any]:
    return {
        "source_url": source_url,
        "code": code,
        "message": message,
        "details": details,
    }


def _first_child(element: ElementTree.Element, name: str) -> ElementTree.Element | None:
    return next((child for child in element if _local_name(child.tag) == name), None)


def _child_text(element: ElementTree.Element, name: str) -> str | None:
    child = _first_child(element, name)
    if child is None:
        return None
    return "".join(child.itertext())


def _local_name(tag: str) -> str:
    return tag.rsplit("}", 1)[-1]


def _clean_text(value: str | None) -> str | None:
    if value is None:
        return None
    cleaned = " ".join(value.split())
    return cleaned or None


def _truncate(value: str | None, limit: int) -> str | None:
    if value is None or len(value) <= limit:
        return value
    return value[: limit - 3].rstrip() + "..."
