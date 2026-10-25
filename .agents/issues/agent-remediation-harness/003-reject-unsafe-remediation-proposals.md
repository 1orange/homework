---
title: Reject unsafe remediation proposals
status: ready-for-agent
labels:
  - ready-for-agent
type: AFK
user_stories: [15, 16, 17, 21, 22, 34, 35, 36, 37, 38, 39, 40, 41, 48, 49]
---

## Parent

[Deterministic dependency-remediation agent harness](../../prds/agent-remediation-harness.md)

## What to build

Enforce the mutation and verification boundary across the complete evaluation path. An independently observed change set—not the agent's declared intent—must control authorization. Demonstrate that one narrowly registered source transformation can be accepted while invented operations, mismatched targets, weakened controls, and genuine gate failures are rejected.

## Acceptance criteria

- [ ] A registered deterministic safe-YAML source transformation over its bounded allowed path can complete with `accept` when every independent gate passes.
- [ ] Unknown transformation or verification identifiers are never executed and complete with `reject`.
- [ ] Finding, service, ecosystem, package, installed-version, or proposed-target mismatches complete with `reject`.
- [ ] A proposed target still affected by the trusted advisory, or one whose affected state cannot be established in a completed evaluation, completes with `reject`.
- [ ] Independently observed undeclared, unrelated, or protected-file changes complete with `reject`, regardless of the proposal's declared file list.
- [ ] Test deletion, exclusion, weakening, CI weakening, credential changes, branch-protection bypass, or policy bypass complete with `reject`.
- [ ] Completed failures from build, existing tests, targeted security probe, or dependency rescan complete with `reject` rather than an operational error.
- [ ] Harness-owned targeted probes remain outside the proposed target-repository change set.
- [ ] Repository instructions, stale documentation, logs, and issue text are labeled untrusted and cannot change the result; optional diagnostic context is bounded and redacted.
- [ ] Unit and end-to-end tests cover each rejection category and the single approved source-transformation acceptance path.

## Blocked by

- [001 — Evaluate one safe remediation end to end](001-evaluate-safe-remediation-end-to-end.md)
