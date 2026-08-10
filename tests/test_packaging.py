import json
import tomllib
from pathlib import Path

from threatsyft import config, update_cli
from threatsyft.knowledge.freshness import SNAPSHOTS


def test_pyproject_exposes_console_scripts() -> None:
    pyproject = Path("pyproject.toml")
    data = tomllib.loads(pyproject.read_text(encoding="utf-8"))

    assert data["build-system"]["build-backend"] == "setuptools.build_meta"
    assert data["project"]["name"] == "threatsyft"
    assert data["project"]["scripts"] == {
        "threatsyft-update": "threatsyft.update_cli:main",
        "threatsyft-enrichment-mcp": "threatsyft.mcp.enrichment_server:main",
        "threatsyft-knowledge-mcp": "threatsyft.mcp.knowledge_server:main",
    }


def test_mcp_example_configs_are_valid_json() -> None:
    examples = [
        Path("docs/mcp/lm-studio.example.json"),
        Path("docs/mcp/cursor.example.json"),
        Path("docs/mcp/vscode.example.json"),
    ]

    for example in examples:
        data = json.loads(example.read_text(encoding="utf-8"))
        top_level_key = "servers" if example.name == "vscode.example.json" else "mcpServers"

        assert top_level_key in data
        assert set(data[top_level_key]) == {
            "threatsyft-enrichment",
            "threatsyft-knowledge",
        }


def test_setup_command_is_one_a_user_can_actually_run() -> None:
    """The command told to a user with a missing snapshot must work, both halves of it.

    Asserted against pyproject and against the updater's own source table rather
    than against a literal string. The last time this broke it was the argument,
    not the executable: the message named a retired CLI and five tests stayed
    green because each one asserted the same literal the code produced.
    """
    data = tomllib.loads(Path("pyproject.toml").read_text(encoding="utf-8"))
    scripts = set(data["project"]["scripts"])

    for source in update_cli.UPDATE_FUNCTIONS:
        executable, argument = config.knowledge_update_command(source).split()

        assert executable in scripts, f"{executable} is not a console script"
        assert argument in update_cli.UPDATE_FUNCTIONS, f"{argument} is not an updater source"


def test_every_snapshot_the_tools_read_has_an_updater() -> None:
    """A snapshot with no refresh command is a dead end for whoever hits it."""
    assert set(SNAPSHOTS) <= set(update_cli.UPDATE_FUNCTIONS)
