"""MCP server exposing public ThreatSyft research tools."""

from __future__ import annotations

from typing import Any

from mcp.server.fastmcp import FastMCP

from threatsyft.research.articles import (
    research_article_iocs as run_research_article_iocs,
)
from threatsyft.research.articles import (
    research_article_summary as run_research_article_summary,
)
from threatsyft.research.briefs import research_brief as run_research_brief
from threatsyft.research.feeds import research_feed_search as run_research_feed_search
from threatsyft.research.feeds import research_feed_status as run_research_feed_status

mcp = FastMCP(
    "ThreatSyft Research",
    instructions=(
        "Public threat-report research tools. Use this server for RSS/news/blog searches, "
        "current public write-ups, article summaries, IOC extraction, and fresh vulnerability "
        "reporting. Tools are read-only, return snippets instead of full article bodies, and "
        "produce structured JSON. Use research_feed_status to inspect configured RSS feeds. "
        "If research_feed_search returns zero results, say the configured feeds had no matches "
        "for the query/window; do not claim the topic does not exist publicly. "
        "When research_brief succeeds for a URL, treat the article summary and IOC extraction "
        "as complete for that URL; do not repeat the same research calls unless the user asks "
        "to refresh."
    ),
)


@mcp.tool()
def research_feed_search(query: str = "", limit: int = 10, days: int = 14) -> dict[str, Any]:
    """Search configured RSS/Atom security feeds for recent public reporting."""
    return run_research_feed_search(query, limit, days)


@mcp.tool()
def research_feed_status() -> dict[str, Any]:
    """List configured research feed URLs without fetching them."""
    return run_research_feed_status()


@mcp.tool()
def research_article_summary(url: str) -> dict[str, Any]:
    """Fetch one public article URL and return metadata plus short safe snippets."""
    return run_research_article_summary(url)


@mcp.tool()
def research_article_iocs(url: str) -> dict[str, Any]:
    """Fetch one public article URL and extract IOC candidates from short context."""
    return run_research_article_iocs(url)


@mcp.tool()
def research_brief(url: str) -> dict[str, Any]:
    """Build a compact article fact pack with summary, IOCs, and suggested pivots."""
    return run_research_brief(url)


def main() -> None:
    """Run the research MCP server over stdio."""
    mcp.run(transport="stdio")


if __name__ == "__main__":
    main()
