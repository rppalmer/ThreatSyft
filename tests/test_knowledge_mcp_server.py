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


def test_knowledge_tools_are_annotated_read_only_and_closed_world() -> None:
    tools = anyio.run(mcp.list_tools)

    for tool in tools:
        assert tool.annotations is not None, tool.name
        assert tool.annotations.readOnlyHint is True, tool.name
        assert tool.annotations.destructiveHint is False, tool.name
        # Local snapshots: same question, same answer, closed set of sources.
        assert tool.annotations.idempotentHint is True, tool.name
        assert tool.annotations.openWorldHint is False, tool.name


def test_knowledge_instructions_name_the_envelope_as_the_error_channel() -> None:
    assert "ok:false" in mcp.instructions
    assert "isError" in mcp.instructions
