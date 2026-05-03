from __future__ import annotations

import os
import subprocess
import sys
import time
from pathlib import Path

import pytest

SERVER_MODULES = [
    "investigatinator.mcp.enrichment_server",
    "investigatinator.mcp.knowledge_server",
    "investigatinator.mcp.research_server",
]


@pytest.mark.parametrize("module_name", SERVER_MODULES)
def test_mcp_server_module_can_start_as_stdio_process(module_name: str) -> None:
    process = subprocess.Popen(
        [sys.executable, "-m", module_name],
        stdin=subprocess.PIPE,
        stdout=subprocess.PIPE,
        stderr=subprocess.PIPE,
        env=_subprocess_env(),
        text=True,
    )

    try:
        time.sleep(0.5)
        assert process.poll() is None
    finally:
        _stop_process(process)


def _subprocess_env() -> dict[str, str]:
    env = os.environ.copy()
    src_path = str(Path.cwd() / "src")
    existing_pythonpath = env.get("PYTHONPATH")
    env["PYTHONPATH"] = (
        f"{src_path}{os.pathsep}{existing_pythonpath}" if existing_pythonpath else src_path
    )
    return env


def _stop_process(process: subprocess.Popen[str]) -> None:
    process.terminate()
    try:
        process.communicate(timeout=5)
    except subprocess.TimeoutExpired:
        process.kill()
        process.communicate(timeout=5)
