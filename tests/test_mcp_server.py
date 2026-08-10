import anyio

from threatsyft.mcp.enrichment_server import mcp

# `enrichment_status` reads the process environment for key presence and calls
# nothing, despite living on the server that holds the keys.
LIVE_TOOLS = {"enrich"}


def test_mcp_server_registers_expected_tools() -> None:
    tools = anyio.run(mcp.list_tools)

    assert [tool.name for tool in tools] == [
        "enrichment_status",
        "enrich",
    ]


def test_every_enrichment_tool_is_read_only_and_non_destructive() -> None:
    """Annotations are the signal hosts use to decide what to auto-approve."""
    tools = anyio.run(mcp.list_tools)

    for tool in tools:
        assert tool.annotations is not None, tool.name
        assert tool.annotations.readOnlyHint is True, tool.name
        assert tool.annotations.destructiveHint is False, tool.name


def test_tools_are_annotated_open_world_only_if_they_call_out() -> None:
    """Which server a tool sits on does not decide this; what it reaches does."""
    tools = anyio.run(mcp.list_tools)

    for tool in tools:
        live = tool.name in LIVE_TOOLS
        assert tool.annotations.openWorldHint is live, tool.name
        assert tool.annotations.idempotentHint is not live, tool.name


def test_enrichment_status_makes_no_network_call(monkeypatch) -> None:
    """The fact behind its local-only annotation."""
    import httpx

    from threatsyft.enrichment.status import enrichment_status

    def forbidden(*args, **kwargs):
        raise AssertionError("enrichment_status attempted a network call")

    monkeypatch.setattr(httpx, "get", forbidden)
    monkeypatch.setattr(httpx, "post", forbidden)

    assert enrichment_status()["ok"] is True


def test_enrichment_instructions_name_the_envelope_as_the_error_channel() -> None:
    assert "ok:false" in mcp.instructions
    assert "isError" in mcp.instructions
