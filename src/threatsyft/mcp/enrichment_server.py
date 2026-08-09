"""MCP server exposing ThreatSyft enrichment tools."""

from __future__ import annotations

from typing import Any

from mcp.server.fastmcp import FastMCP

from threatsyft.enrichment.enrich import enrich as run_enrich
from threatsyft.enrichment.status import enrichment_status as run_enrichment_status

mcp = FastMCP(
    "ThreatSyft Enrichment",
    instructions=(
        "Read-only indicator enrichment. enrich(indicator) takes an IP, domain, URL "
        "or file hash, works out which it is, and collects context from every source "
        "that supports that type in one call, reporting per-source success or "
        "failure. It returns no verdict and no confidence score - judgement is the "
        "caller's. Use enrichment_status to check which API keys are configured, "
        "without exposing secrets or calling external APIs."
    ),
)


@mcp.tool()
def enrichment_status() -> dict[str, Any]:
    """Check local enrichment provider configuration without network calls or secret values."""
    return run_enrichment_status()


@mcp.tool()
def enrich(indicator: str) -> dict[str, Any]:
    """Collect context on one IP, domain, URL, or file hash from every source that has it."""
    return run_enrich(indicator)


def main() -> None:
    """Run the enrichment MCP server over stdio."""
    mcp.run(transport="stdio")


if __name__ == "__main__":
    main()
