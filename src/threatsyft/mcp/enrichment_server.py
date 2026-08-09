"""MCP server exposing ThreatSyft enrichment tools."""

from __future__ import annotations

from typing import Any

from mcp.server.fastmcp import FastMCP
from mcp.types import ToolAnnotations

from threatsyft.enrichment.enrich import enrich as run_enrich
from threatsyft.enrichment.status import enrichment_status as run_enrichment_status
from threatsyft.logging_setup import configure_logging

# Reading external services changes nothing, but the answers move between calls
# and the set of reachable services is open, so this is neither idempotent nor
# closed-world.
READ_ONLY_LIVE = ToolAnnotations(
    readOnlyHint=True,
    destructiveHint=False,
    idempotentHint=False,
    openWorldHint=True,
)

mcp = FastMCP(
    "ThreatSyft Enrichment",
    instructions=(
        "Read-only indicator enrichment. enrich(indicator) takes an IP, domain, URL "
        "or file hash, works out which it is, and collects context from every source "
        "that supports that type in one call, reporting per-source success or "
        "failure. It returns no verdict and no confidence score - judgement is the "
        "caller's. Use enrichment_status to check which API keys are configured, "
        "without exposing secrets or calling external APIs. "
        "Every failure arrives as ok:false inside a normal successful response, with a "
        "code and message in the error field. The protocol-level isError flag is only "
        "set by an unhandled exception, so read the envelope, not isError."
    ),
)


@mcp.tool(annotations=READ_ONLY_LIVE)
def enrichment_status() -> dict[str, Any]:
    """Check local enrichment provider configuration without network calls or secret values."""
    return run_enrichment_status()


@mcp.tool(annotations=READ_ONLY_LIVE)
def enrich(indicator: str) -> dict[str, Any]:
    """Collect context on one IP, domain, URL, or file hash from every source that has it."""
    return run_enrich(indicator)


def main() -> None:
    """Run the enrichment MCP server over stdio."""
    configure_logging()
    mcp.run(transport="stdio")


if __name__ == "__main__":
    main()
