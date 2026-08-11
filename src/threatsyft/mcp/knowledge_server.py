"""MCP server exposing local ThreatSyft knowledge tools."""

from __future__ import annotations

from typing import Any

from mcp.server.fastmcp import FastMCP

from threatsyft.knowledge.iocs import extract_iocs as run_extract_iocs
from threatsyft.knowledge.lookup import lookup as run_lookup
from threatsyft.knowledge.lookup import search as run_search
from threatsyft.knowledge.status import knowledge_status as run_knowledge_status
from threatsyft.logging_setup import configure_logging
from threatsyft.mcp.annotations import LIVE_NETWORK, LOCAL_ONLY

mcp = FastMCP(
    "ThreatSyft Knowledge",
    instructions=(
        "Defensive security knowledge tools for stable references and vulnerability context. "
        "Prefer lookup(reference) for one CVE, ATT&CK technique or LOLBAS name: it "
        "collects every local source covering it in one call. Prefer search(query) "
        "to find candidates across ATT&CK, KEV and LOLBAS, grouped by source. Most "
        "lookups are local-only; the NVD CVE API is the one live call. "
        "Every failure arrives as ok:false inside a normal successful response, with a "
        "code and message in the error field. The protocol-level isError flag is only "
        "set by an unhandled exception, so read the envelope, not isError. "
        "extract_iocs pulls typed IOC candidates out of text you already have; it does "
        "no network access and does not fetch URLs. This server does not discover or "
        "retrieve public reporting. "
        "Setup: the ATT&CK, KEV and LOLBAS lookups read local snapshots that must be "
        "downloaded once with `threatsyft-update all`. Until then those sources return "
        "not_found with the command in details.setup_command. Call knowledge_status to "
        "check what is ready without making a lookup fail first."
    ),
)


# The one tool on this server that can leave the process: a CVE reference asks
# NVD as well as the local KEV catalog.
@mcp.tool(annotations=LIVE_NETWORK)
def lookup(reference: str) -> dict[str, Any]:
    """Collect every local source covering one reference.

    Accepts a CVE (CVE-2024-3400), an ATT&CK technique (T1059.001), tactic
    (TA0002), mitigation (M1038), group (G0016) or software (S0002), or a bare
    name such as a LOLBAS binary or a threat actor alias like "Cozy Bear".
    A group lists the techniques and the malware and tooling attributed to it;
    software lists the groups recorded using it.
    """
    return run_lookup(reference)


@mcp.tool(annotations=LOCAL_ONLY)
def search(query: str, source: str = "all", limit: int = 10) -> dict[str, Any]:
    """Search ATT&CK techniques and groups, KEV, and LOLBAS, grouped by source.

    Matches terms literally rather than by meaning, so a whole question returns
    nothing: search one canonical term such as "credential dumping", "T1055" or
    "certutil.exe". limit applies per source.
    """
    return run_search(query, source, limit)


@mcp.tool(annotations=LOCAL_ONLY)
def extract_iocs(text: str) -> dict[str, Any]:
    """Extract typed IOC candidates from text you already have. No network access."""
    return run_extract_iocs(text)


@mcp.tool(annotations=LOCAL_ONLY)
def knowledge_status() -> dict[str, Any]:
    """Check ATT&CK, KEV, LOLBAS, and NVD snapshot readiness."""
    return run_knowledge_status()


def main() -> None:
    """Run the knowledge MCP server over stdio."""
    configure_logging()
    mcp.run(transport="stdio")


if __name__ == "__main__":
    main()
