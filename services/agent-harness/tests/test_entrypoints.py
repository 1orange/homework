from __future__ import annotations

import os
import shutil
import subprocess
import sys
from pathlib import Path


PROJECT_ROOT = Path(__file__).parents[1]


def _run(command: list[str], *arguments: str) -> subprocess.CompletedProcess[str]:
    environment = os.environ.copy()
    current_pythonpath = environment.get("PYTHONPATH")
    environment["PYTHONPATH"] = (
        f"{PROJECT_ROOT}{os.pathsep}{current_pythonpath}"
        if current_pythonpath
        else str(PROJECT_ROOT)
    )
    return subprocess.run(
        [*command, *arguments],
        cwd=PROJECT_ROOT,
        env=environment,
        capture_output=True,
        text=True,
        check=False,
    )


def test_module_and_script_entrypoints_forward_help_to_canonical_cli() -> None:
    module = _run([sys.executable, "-m", "agent_harness"], "--help")
    script = _run([sys.executable, "run.py"], "--help")

    assert module.returncode == 0
    assert script.returncode == module.returncode
    assert script.stdout == module.stdout
    assert script.stderr == module.stderr

    installed = shutil.which("agent-harness")
    if installed:
        console = _run([installed], "--help")
        assert console.returncode == module.returncode
        assert console.stdout == module.stdout
        assert console.stderr == module.stderr


def test_module_and_script_entrypoints_forward_invalid_invocation_status() -> None:
    module = _run([sys.executable, "-m", "agent_harness"])
    script = _run([sys.executable, "run.py"])

    assert module.returncode == 2
    assert script.returncode == module.returncode
    assert script.stdout == module.stdout
    assert script.stderr == module.stderr
