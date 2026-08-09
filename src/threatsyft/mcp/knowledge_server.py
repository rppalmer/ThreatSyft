"""MCP server exposing local ThreatSyft knowledge tools."""

from __future__ import annotations

from typing import Any

from mcp.server.fastmcp import FastMCP

from threatsyft.knowledge.attack import attack_search as run_attack_search
from threatsyft.knowledge.attack import (
    attack_tactic_lookup as run_attack_tactic_lookup,
)
from threatsyft.knowledge.attack import (
    attack_technique_lookup as run_attack_technique_lookup,
)
from threatsyft.knowledge.cve import cve_lookup as run_cve_lookup
from threatsyft.knowledge.iocs import extract_iocs as run_extract_iocs
from threatsyft.knowledge.kev import kev_lookup as run_kev_lookup
from threatsyft.knowledge.kev import kev_search as run_kev_search
from threatsyft.knowledge.lolbas import lolbas_lookup as run_lolbas_lookup
from threatsyft.knowledge.lolbas import lolbas_search as run_lolbas_search
from threatsyft.knowledge.lookup import lookup as run_lookup
from threatsyft.knowledge.lookup import search as run_search
from threatsyft.knowledge.status import knowledge_status as run_knowledge_status

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
        "retrieve public reporting."
    ),
)


@mcp.tool()
def attack_technique_lookup(technique_id: str) -> dict[str, Any]:
    """Look up one MITRE ATT&CK Enterprise technique by ID."""
    return run_attack_technique_lookup(technique_id)


@mcp.tool()
def attack_search(query: str, limit: int = 10) -> dict[str, Any]:
    """Search local MITRE ATT&CK Enterprise techniques."""
    return run_attack_search(query, limit)


@mcp.tool()
def attack_tactic_lookup(tactic: str) -> dict[str, Any]:
    """Look up one MITRE ATT&CK Enterprise tactic and its techniques."""
    return run_attack_tactic_lookup(tactic)


@mcp.tool()
def cve_lookup(cve_id: str) -> dict[str, Any]:
    """Look up official metadata for one CVE using the live NVD CVE API."""
    return run_cve_lookup(cve_id)


@mcp.tool()
def kev_lookup(cve_id: str) -> dict[str, Any]:
    """Check whether one CVE appears in the local CISA KEV catalog."""
    return run_kev_lookup(cve_id)


@mcp.tool()
def kev_search(query: str, limit: int = 10) -> dict[str, Any]:
    """Search the local CISA KEV catalog."""
    return run_kev_search(query, limit)


@mcp.tool()
def lolbas_lookup(name: str) -> dict[str, Any]:
    """Look up one LOLBAS entry by name."""
    return run_lolbas_lookup(name)


@mcp.tool()
def lolbas_search(query: str, limit: int = 10) -> dict[str, Any]:
    """Search the local LOLBAS catalog."""
    return run_lolbas_search(query, limit)


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
    mcp.run(transport="stdio")


if __name__ == "__main__":
    main()
