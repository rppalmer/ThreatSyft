import json
import tomllib
from pathlib import Path

from threatsyft import config


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


def test_setup_command_names_a_console_script_that_exists() -> None:
    """The command told to a user with a missing snapshot must be one they can run.

    It named the retired `threatsyft knowledge-update` after the CLI was
    replaced, and five tests asserted the stale string rather than catching it.
    """
    data = tomllib.loads(Path("pyproject.toml").read_text(encoding="utf-8"))
    scripts = set(data["project"]["scripts"])

    for source in ["attack", "kev", "lolbas"]:
        command = config.knowledge_update_command(source)
        assert command.split()[0] in scripts, command
