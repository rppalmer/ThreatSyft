import anyio

from threatsyft.mcp.enrichment_server import mcp


def test_mcp_server_registers_expected_tools() -> None:
    tools = anyio.run(mcp.list_tools)

    assert [tool.name for tool in tools] == [
        "enrichment_status",
        "enrich",
    ]
