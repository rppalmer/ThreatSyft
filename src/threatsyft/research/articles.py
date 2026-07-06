"""Public article context and IOC extraction tools."""

from __future__ import annotations

from dataclasses import dataclass
from html import unescape
from html.parser import HTMLParser
from typing import Any

import httpx

from threatsyft.config import get_research_user_agent, get_timeout_seconds
from threatsyft.core import (
    InputValidationError,
    error_response,
    success_response,
)
from threatsyft.research.iocs import extract_iocs
from threatsyft.research.url_validation import MAX_FETCH_BYTES, normalize_public_http_url

SUMMARY_TOOL_NAME = "research_article_summary"
IOCS_TOOL_NAME = "research_article_iocs"
MAX_SNIPPETS = 5
MAX_SNIPPET_LENGTH = 500


@dataclass(frozen=True)
class Article:
    """Cleaned article metadata and snippets."""

    url: str
    title: str | None
    description: str | None
    published: str | None
    text: str
    snippets: list[str]


class ArticleHTMLParser(HTMLParser):
    """Small HTML parser for metadata and visible text."""

    def __init__(self) -> None:
        super().__init__(convert_charrefs=True)
        self.title: str | None = None
        self.meta: dict[str, str] = {}
        self.paragraphs: list[str] = []
        self._title_parts: list[str] = []
        self._block_parts: list[str] = []
        self._capture_title = False
        self._capture_block = False
        self._skip_depth = 0

    def handle_starttag(self, tag: str, attrs: list[tuple[str, str | None]]) -> None:
        normalized_tag = tag.lower()
        attr_map = {name.lower(): value or "" for name, value in attrs}
        if normalized_tag in {"script", "style", "noscript"}:
            self._skip_depth += 1
            return
        if self._skip_depth:
            return
        if normalized_tag == "title":
            self._capture_title = True
            self._title_parts = []
        elif normalized_tag == "meta":
            self._store_meta(attr_map)
        elif normalized_tag in {"p", "li"}:
            self._capture_block = True
            self._block_parts = []

    def handle_endtag(self, tag: str) -> None:
        normalized_tag = tag.lower()
        if normalized_tag in {"script", "style", "noscript"} and self._skip_depth:
            self._skip_depth -= 1
            return
        if self._skip_depth:
            return
        if normalized_tag == "title" and self._capture_title:
            self.title = _clean_text(" ".join(self._title_parts))
            self._capture_title = False
        elif normalized_tag in {"p", "li"} and self._capture_block:
            paragraph = _clean_text(" ".join(self._block_parts))
            if paragraph and len(paragraph) >= 30:
                self.paragraphs.append(paragraph)
            self._capture_block = False

    def handle_data(self, data: str) -> None:
        if self._skip_depth:
            return
        if self._capture_title:
            self._title_parts.append(data)
        if self._capture_block:
            self._block_parts.append(data)

    def _store_meta(self, attrs: dict[str, str]) -> None:
        key = attrs.get("property") or attrs.get("name")
        content = attrs.get("content")
        if key and content:
            self.meta[key.lower()] = content


def research_article_summary(url: str) -> dict[str, Any]:
    """Fetch a public article URL and return metadata plus short snippets."""
    query = {"url": url}
    try:
        article = _fetch_article(url)
    except InputValidationError as exc:
        return error_response(SUMMARY_TOOL_NAME, query, "invalid_input", str(exc))
    except httpx.TimeoutException:
        return error_response(SUMMARY_TOOL_NAME, query, "timeout", "Article fetch timed out.")
    except httpx.HTTPStatusError as exc:
        return error_response(
            SUMMARY_TOOL_NAME,
            query,
            "upstream_error",
            "Article fetch returned an HTTP error.",
            {"status_code": exc.response.status_code},
        )
    except httpx.RequestError as exc:
        return error_response(
            SUMMARY_TOOL_NAME,
            query,
            "network_error",
            "Article fetch failed.",
            str(exc),
        )

    return success_response(
        SUMMARY_TOOL_NAME,
        {"url": article.url},
        {
            "live_network": True,
            "url": article.url,
            "title": article.title,
            "description": article.description,
            "published": article.published,
            "snippets": article.snippets,
            "snippet_count": len(article.snippets),
            "full_text_returned": False,
        },
    )


def research_article_iocs(url: str) -> dict[str, Any]:
    """Fetch a public article URL and return locally extracted IOCs."""
    query = {"url": url}
    try:
        article = _fetch_article(url)
    except InputValidationError as exc:
        return error_response(IOCS_TOOL_NAME, query, "invalid_input", str(exc))
    except httpx.TimeoutException:
        return error_response(IOCS_TOOL_NAME, query, "timeout", "Article fetch timed out.")
    except httpx.HTTPStatusError as exc:
        return error_response(
            IOCS_TOOL_NAME,
            query,
            "upstream_error",
            "Article fetch returned an HTTP error.",
            {"status_code": exc.response.status_code},
        )
    except httpx.RequestError as exc:
        return error_response(
            IOCS_TOOL_NAME,
            query,
            "network_error",
            "Article fetch failed.",
            str(exc),
        )

    iocs = extract_iocs(article.text)
    counts = {ioc_type: len(values) for ioc_type, values in iocs.items()}

    return success_response(
        IOCS_TOOL_NAME,
        {"url": article.url},
        {
            "live_network": True,
            "url": article.url,
            "title": article.title,
            "published": article.published,
            "ioc_counts": counts,
            "iocs": iocs,
            "full_text_returned": False,
        },
    )


def _fetch_article(url: str) -> Article:
    normalized_url = normalize_public_http_url(url)
    response = httpx.get(
        normalized_url,
        headers={
            "User-Agent": get_research_user_agent(),
            "Accept": "text/html,application/xhtml+xml",
        },
        timeout=get_timeout_seconds(),
    )
    response.raise_for_status()
    # Bound the text handed to the HTML parser and IOC regexes against oversized bodies.
    return _parse_article(normalized_url, response.text[:MAX_FETCH_BYTES])


def _parse_article(url: str, html: str) -> Article:
    parser = ArticleHTMLParser()
    parser.feed(html)
    parser.close()

    title = _first_text(
        parser.meta.get("og:title"),
        parser.meta.get("twitter:title"),
        parser.title,
    )
    description = _first_text(
        parser.meta.get("description"),
        parser.meta.get("og:description"),
        parser.meta.get("twitter:description"),
    )
    published = _first_text(
        parser.meta.get("article:published_time"),
        parser.meta.get("date"),
        parser.meta.get("pubdate"),
    )
    snippets = [
        _truncate(paragraph, MAX_SNIPPET_LENGTH) for paragraph in parser.paragraphs[:MAX_SNIPPETS]
    ]
    text_parts = [item for item in [title, description, *parser.paragraphs] if item]

    return Article(
        url=url,
        title=title,
        description=description,
        published=published,
        text=" ".join(text_parts),
        snippets=snippets,
    )


def _first_text(*values: str | None) -> str | None:
    for value in values:
        cleaned = _clean_text(value)
        if cleaned:
            return cleaned
    return None


def _clean_text(value: str | None) -> str | None:
    if value is None:
        return None
    cleaned = " ".join(unescape(value).split())
    return cleaned or None


def _truncate(value: str, limit: int) -> str:
    if len(value) <= limit:
        return value
    return value[: limit - 3].rstrip() + "..."
