---
title: Run all components with Docker Compose
status: ready-for-agent
labels:
  - ready-for-agent
type: AFK
user_stories: [68, 69, 70, 71]
---

## Parent

[Deterministic dependency-remediation agent harness](../../prds/agent-remediation-harness.md)

## What to build

Provide reproducible developer containers for the two supplied services and the harness. Compose is a convenient command surface for building and running each component, not an orchestration dependency of the harness. The vulnerable dependency baseline and existing CI workflow must remain unchanged.

## Acceptance criteria

- [ ] A developer can build all three component images with one documented Compose command.
- [ ] The inventory API can run as a long-lived service and its Maven tests can run as a separate one-shot Compose task without requiring host Maven.
- [ ] Report-worker tests and a representative smoke execution run as separate one-shot Compose tasks.
- [ ] Harness unit/integration tests and fixture evaluation run as separate one-shot Compose tasks.
- [ ] Container commands work from the repository root and produce the same harness decisions and evidence contracts as the host CLI.
- [ ] The harness container receives neither the Docker socket nor host credentials and does not start or control other services.
- [ ] Images use appropriately pinned runtime/toolchain bases and non-root execution where practical for the assignment.
- [ ] Containerization does not modify vulnerable target dependency declarations, the original findings, or the existing CI workflow.

## Blocked by

- [001 — Evaluate one safe remediation end to end](001-evaluate-safe-remediation-end-to-end.md)
