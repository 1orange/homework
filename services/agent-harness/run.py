"""Small development entrypoint for the canonical harness CLI.

This file intentionally contains no orchestration or policy logic.  It exists
so the harness can be run directly from its project directory with
``python run.py``.
"""

from agent_harness.cli import main


if __name__ == "__main__":
    raise SystemExit(main())
