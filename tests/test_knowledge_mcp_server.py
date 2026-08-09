import anyio

from threatsyft.mcp.knowledge_server import mcp


def test_knowledge_mcp_server_registers_expected_tools() -> None:
    tools = anyio.run(mcp.list_tools)

    assert [tool.name for tool in tools] == [
        "lookup",
        "search",
        "extract_iocs",
        "knowledge_status",
    ]
