import anyio

from investigatinator.mcp.research_server import mcp


def test_research_mcp_server_registers_expected_tools() -> None:
    tools = anyio.run(mcp.list_tools)

    assert [tool.name for tool in tools] == [
        "research_feed_search",
        "research_article_summary",
        "research_article_iocs",
        "research_brief",
    ]
