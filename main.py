"""Console entrypoint for ThreatSyft enrichment tools."""

from __future__ import annotations

import sys
from pathlib import Path


def main() -> int:
    """Run the local console interface without starting the MCP server."""
    _add_src_to_path()

    from threatsyft.cli import main as cli_main

    return cli_main()


def _add_src_to_path() -> None:
    src_path = Path(__file__).resolve().parent / "src"
    if str(src_path) not in sys.path:
        sys.path.insert(0, str(src_path))


if __name__ == "__main__":
    raise SystemExit(main())
