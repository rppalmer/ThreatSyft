import json
import tomllib
from pathlib import Path


def test_pyproject_exposes_console_scripts() -> None:
    pyproject = Path("pyproject.toml")
    data = tomllib.loads(pyproject.read_text(encoding="utf-8"))

    assert data["build-system"]["build-backend"] == "setuptools.build_meta"
    assert data["project"]["name"] == "investigatinator"
    assert data["project"]["scripts"] == {
        "investigatinator": "investigatinator.cli:main",
        "investigatinator-enrichment-mcp": "investigatinator.mcp.enrichment_server:main",
        "investigatinator-knowledge-mcp": "investigatinator.mcp.knowledge_server:main",
        "investigatinator-research-mcp": "investigatinator.mcp.research_server:main",
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
            "investigatinator-enrichment",
            "investigatinator-knowledge",
            "investigatinator-research",
        }
