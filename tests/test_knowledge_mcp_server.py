import anyio

from threatsyft.mcp.knowledge_server import mcp


def test_knowledge_mcp_server_registers_expected_tools() -> None:
    tools = anyio.run(mcp.list_tools)

    assert [tool.name for tool in tools] == [
        "attack_technique_lookup",
        "attack_search",
        "attack_tactic_lookup",
        "cve_lookup",
        "kev_lookup",
        "kev_search",
        "lolbas_lookup",
        "lolbas_search",
        "lookup",
        "search",
        "extract_iocs",
        "knowledge_status",
    ]
