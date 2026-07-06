import anyio

from threatsyft.mcp.knowledge_server import mcp


def test_knowledge_mcp_server_registers_expected_tools() -> None:
    tools = anyio.run(mcp.list_tools)

    assert [tool.name for tool in tools] == [
        "attack_technique_lookup",
        "attack_search",
        "attack_tactic_lookup",
        "d3fend_lookup",
        "d3fend_search",
        "attack_defense_mapping",
        "technique_brief",
        "cve_lookup",
        "vulnerability_brief",
        "kev_lookup",
        "kev_search",
        "lolbas_lookup",
        "lolbas_search",
        "knowledge_status",
    ]
