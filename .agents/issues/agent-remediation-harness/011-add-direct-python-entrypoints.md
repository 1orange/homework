---
title: Add direct Python entrypoints
status: ready-for-agent
labels:
  - ready-for-agent
type: AFK
---

## Parent

[Deterministic dependency-remediation agent harness](../../prds/agent-remediation-harness.md)

## What to build

Provide obvious development entrypoints in addition to the installed console command. From the harness project directory, a developer using Poetry should be able to invoke the same CLI through Python module execution or a small Python start script, with all paths, arguments, output, and exit statuses delegated to the canonical CLI implementation.

## Acceptance criteria

- [ ] `poetry run python -m agent_harness --help` invokes the canonical harness CLI.
- [ ] `poetry run python run.py --help` invokes the same CLI from the harness project directory.
- [ ] Both entrypoints forward arguments and return the same exit status as the installed `agent-harness` command.
- [ ] Neither entrypoint duplicates orchestration or policy logic.
- [ ] Root and harness documentation include the direct Python invocation options.
- [ ] Automated tests cover module and script invocation without contacting external services.

## Blocked by

None - can start immediately.
