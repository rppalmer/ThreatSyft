import anyio

from threatsyft.mcp.enrichment_server import mcp


def test_mcp_server_registers_expected_tools() -> None:
    tools = anyio.run(mcp.list_tools)

    assert [tool.name for tool in tools] == [
        "enrichment_status",
        "enrich",
    ]


def test_enrichment_tools_are_annotated_read_only_and_open_world() -> None:
    """Annotations are the signal hosts use to decide what to auto-approve."""
    tools = anyio.run(mcp.list_tools)

    for tool in tools:
        assert tool.annotations is not None, tool.name
        assert tool.annotations.readOnlyHint is True, tool.name
        assert tool.annotations.destructiveHint is False, tool.name
        # Third-party answers move between calls, and the reachable set is open.
        assert tool.annotations.idempotentHint is False, tool.name
        assert tool.annotations.openWorldHint is True, tool.name


def test_enrichment_instructions_name_the_envelope_as_the_error_channel() -> None:
    assert "ok:false" in mcp.instructions
    assert "isError" in mcp.instructions
