from pathlib import Path

import anyio
import pytest

from threatsyft.knowledge import cve
from threatsyft.knowledge.lookup import lookup
from threatsyft.mcp.knowledge_server import mcp

# Which tools can leave the process. `lookup` can: a CVE reference asks NVD as
# well as the local KEV catalog. The rest read local files only.
LIVE_TOOLS = {"lookup"}


@pytest.fixture(autouse=True)
def local_snapshots(monkeypatch):
    """Never touch a real snapshot, so a machine without them runs the same."""
    monkeypatch.setenv("THREATSYFT_ATTACK_STIX_PATH", "tests/fixtures/attack-enterprise-mini.json")
    monkeypatch.setenv("THREATSYFT_CISA_KEV_PATH", "tests/fixtures/cisa-kev-mini.json")
    monkeypatch.setenv("THREATSYFT_LOLBAS_PATH", "tests/fixtures/lolbas-mini.json")
    assert Path("tests/fixtures/attack-enterprise-mini.json").exists()


def test_knowledge_mcp_server_registers_expected_tools() -> None:
    tools = anyio.run(mcp.list_tools)

    assert [tool.name for tool in tools] == [
        "lookup",
        "search",
        "extract_iocs",
        "knowledge_status",
    ]


def test_every_knowledge_tool_is_read_only_and_non_destructive() -> None:
    tools = anyio.run(mcp.list_tools)

    for tool in tools:
        assert tool.annotations is not None, tool.name
        assert tool.annotations.readOnlyHint is True, tool.name
        assert tool.annotations.destructiveHint is False, tool.name


def test_tools_are_annotated_open_world_only_if_they_call_out() -> None:
    """Annotations decide what a host auto-approves, so they must match behaviour.

    Annotating the whole server closed-world read as "this never leaves the
    machine", which is not true of a CVE lookup.
    """
    tools = anyio.run(mcp.list_tools)

    for tool in tools:
        live = tool.name in LIVE_TOOLS
        assert tool.annotations.openWorldHint is live, tool.name
        assert tool.annotations.idempotentHint is not live, tool.name


def test_lookup_of_a_cve_really_does_call_out(monkeypatch) -> None:
    """The fact behind lookup's open-world annotation, asserted rather than assumed."""
    attempted = []

    def fake_get(*args, **kwargs):
        attempted.append(args)
        raise RuntimeError("no network in tests")

    monkeypatch.setattr(cve.httpx, "get", fake_get)

    lookup("CVE-2021-44228")

    assert attempted, "lookup(CVE) is annotated open-world but reached no network"


@pytest.mark.parametrize("reference", ["T1059", "Certutil.exe"])
def test_a_local_reference_makes_no_network_call(reference, monkeypatch) -> None:
    """The other half: everything that is not a CVE stays on local snapshots."""

    def forbidden(*args, **kwargs):
        raise AssertionError(f"lookup({reference!r}) attempted a network call")

    monkeypatch.setattr(cve.httpx, "get", forbidden)

    assert lookup(reference)["ok"] is True


def test_knowledge_instructions_name_the_envelope_as_the_error_channel() -> None:
    assert "ok:false" in mcp.instructions
    assert "isError" in mcp.instructions
