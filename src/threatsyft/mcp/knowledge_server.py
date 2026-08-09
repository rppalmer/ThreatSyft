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
from threatsyft.knowledge.briefs import technique_brief as run_technique_brief
from threatsyft.knowledge.briefs import vulnerability_brief as run_vulnerability_brief
from threatsyft.knowledge.cve import cve_lookup as run_cve_lookup
from threatsyft.knowledge.d3fend import attack_defense_mapping as run_attack_defense_mapping
from threatsyft.knowledge.d3fend import d3fend_lookup as run_d3fend_lookup
from threatsyft.knowledge.d3fend import d3fend_search as run_d3fend_search
from threatsyft.knowledge.iocs import extract_iocs as run_extract_iocs
from threatsyft.knowledge.kev import kev_lookup as run_kev_lookup
from threatsyft.knowledge.kev import kev_search as run_kev_search
from threatsyft.knowledge.lolbas import lolbas_lookup as run_lolbas_lookup
from threatsyft.knowledge.lolbas import lolbas_search as run_lolbas_search
from threatsyft.knowledge.status import knowledge_status as run_knowledge_status

mcp = FastMCP(
    "ThreatSyft Knowledge",
    instructions=(
        "Defensive security knowledge tools for stable references and vulnerability context. "
        "Use this server for ATT&CK techniques and tactics, D3FEND defensive mappings, "
        "CISA KEV, LOLBAS, targeted CVE metadata, and compact defensive briefs. Most "
        "runtime lookups are local-only; cve_lookup uses the live NVD CVE API. "
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
def d3fend_lookup(defense_id_or_name: str) -> dict[str, Any]:
    """Look up one MITRE D3FEND defensive technique by ID or name."""
    return run_d3fend_lookup(defense_id_or_name)


@mcp.tool()
def d3fend_search(query: str, limit: int = 10) -> dict[str, Any]:
    """Search local MITRE D3FEND defensive techniques."""
    return run_d3fend_search(query, limit)


@mcp.tool()
def attack_defense_mapping(technique_id: str) -> dict[str, Any]:
    """Map one ATT&CK technique ID to related D3FEND defensive techniques."""
    return run_attack_defense_mapping(technique_id)


@mcp.tool()
def technique_brief(technique_id: str) -> dict[str, Any]:
    """Build a compact defensive knowledge bundle for one ATT&CK technique."""
    return run_technique_brief(technique_id)


@mcp.tool()
def cve_lookup(cve_id: str) -> dict[str, Any]:
    """Look up official metadata for one CVE using the live NVD CVE API."""
    return run_cve_lookup(cve_id)


@mcp.tool()
def vulnerability_brief(cve_id: str) -> dict[str, Any]:
    """Build a compact CVE bundle from NVD and local KEV knowledge sources."""
    return run_vulnerability_brief(cve_id)


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
def extract_iocs(text: str) -> dict[str, Any]:
    """Extract typed IOC candidates from text you already have. No network access."""
    return run_extract_iocs(text)


@mcp.tool()
def knowledge_status() -> dict[str, Any]:
    """Check ATT&CK, D3FEND, KEV, LOLBAS, and NVD snapshot readiness."""
    return run_knowledge_status()


def main() -> None:
    """Run the knowledge MCP server over stdio."""
    mcp.run(transport="stdio")


if __name__ == "__main__":
    main()
