"""MCP server exposing local ThreatSyft knowledge tools."""

from __future__ import annotations

from typing import Any

from mcp.server.fastmcp import FastMCP

from threatsyft.knowledge.iocs import extract_iocs as run_extract_iocs
from threatsyft.knowledge.lookup import lookup as run_lookup
from threatsyft.knowledge.lookup import search as run_search
from threatsyft.knowledge.status import knowledge_status as run_knowledge_status
from threatsyft.logging_setup import configure_logging

mcp = FastMCP(
    "ThreatSyft Knowledge",
    instructions=(
        "Defensive security knowledge tools for stable references and vulnerability context. "
        "Prefer lookup(reference) for one CVE, ATT&CK technique or LOLBAS name: it "
        "collects every local source covering it in one call. Prefer search(query) "
        "to find candidates across ATT&CK, KEV and LOLBAS, grouped by source. Most "
        "lookups are local-only; the NVD CVE API is the one live call. "
        "extract_iocs pulls typed IOC candidates out of text you already have; it does "
        "no network access and does not fetch URLs. This server does not discover or "
        "retrieve public reporting. "
        "Setup: the ATT&CK, KEV and LOLBAS lookups read local snapshots that must be "
        "downloaded once with `threatsyft-update all`. Until then those sources return "
        "not_found with the command in details.setup_command. Call knowledge_status to "
        "check what is ready without making a lookup fail first."
    ),
)


@mcp.tool()
def lookup(reference: str) -> dict[str, Any]:
    """Collect every local source covering one CVE, ATT&CK technique, or LOLBAS name."""
    return run_lookup(reference)


@mcp.tool()
def search(query: str, source: str = "all", limit: int = 10) -> dict[str, Any]:
    """Search ATT&CK, KEV, and LOLBAS, grouped by source. limit applies per source."""
    return run_search(query, source, limit)


@mcp.tool()
def extract_iocs(text: str) -> dict[str, Any]:
    """Extract typed IOC candidates from text you already have. No network access."""
    return run_extract_iocs(text)


@mcp.tool()
def knowledge_status() -> dict[str, Any]:
    """Check ATT&CK, KEV, LOLBAS, and NVD snapshot readiness."""
    return run_knowledge_status()


def main() -> None:
    """Run the knowledge MCP server over stdio."""
    configure_logging()
    mcp.run(transport="stdio")


if __name__ == "__main__":
    main()
