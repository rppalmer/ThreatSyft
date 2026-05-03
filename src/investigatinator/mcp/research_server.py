"""MCP server exposing public Investigatinator research tools."""

from __future__ import annotations

from typing import Any

from mcp.server.fastmcp import FastMCP

from investigatinator.research.articles import (
    research_article_iocs as run_research_article_iocs,
)
from investigatinator.research.articles import (
    research_article_summary as run_research_article_summary,
)
from investigatinator.research.briefs import research_brief as run_research_brief
from investigatinator.research.feeds import research_feed_search as run_research_feed_search

mcp = FastMCP(
    "Investigatinator Research",
    instructions=(
        "Public threat-report research tools. Tools use live network access, are read-only, "
        "return snippets instead of full article bodies, and produce structured JSON. "
        "When research_brief succeeds for a URL, treat the article summary and IOC extraction "
        "as complete for that URL; do not repeat the same research calls unless the user asks "
        "to refresh."
    ),
)


@mcp.tool()
def research_feed_search(query: str = "", limit: int = 10, days: int = 14) -> dict[str, Any]:
    """Search configured public security RSS feeds."""
    return run_research_feed_search(query, limit, days)


@mcp.tool()
def research_article_summary(url: str) -> dict[str, Any]:
    """Fetch one public article URL and return metadata plus short snippets."""
    return run_research_article_summary(url)


@mcp.tool()
def research_article_iocs(url: str) -> dict[str, Any]:
    """Fetch one public article URL and extract IOCs from short article context."""
    return run_research_article_iocs(url)


@mcp.tool()
def research_brief(url: str) -> dict[str, Any]:
    """Build a compact research fact pack for one public article URL."""
    return run_research_brief(url)


def main() -> None:
    """Run the research MCP server over stdio."""
    mcp.run(transport="stdio")


if __name__ == "__main__":
    main()
