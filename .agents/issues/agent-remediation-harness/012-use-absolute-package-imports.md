---
title: Use absolute package imports
status: ready-for-agent
labels:
  - ready-for-agent
type: AFK
---

## Parent

[Deterministic dependency-remediation agent harness](../../prds/agent-remediation-harness.md)

## What to build

Replace package-internal relative imports with explicit absolute imports rooted at `agent_harness`. The package should present one consistent import style that remains clear during review and works identically when invoked through the console command, module entrypoint, tests, or the direct start script.

## Acceptance criteria

- [ ] Python modules under the harness package import sibling modules through `agent_harness.*` paths.
- [ ] No package-internal `from .` or `from ..` imports remain.
- [ ] Public exports continue to resolve without changing their external names.
- [ ] Console, module, and direct-script entrypoints import the same canonical CLI implementation.
- [ ] The full harness test suite passes after the import conversion.

## Blocked by

None - can start immediately.
