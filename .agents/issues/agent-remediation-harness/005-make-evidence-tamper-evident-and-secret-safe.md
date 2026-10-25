---
title: Make evidence tamper-evident and secret-safe
status: ready-for-agent
labels:
  - ready-for-agent
type: AFK
user_stories: [10, 11, 18, 19, 20, 50, 51, 52, 53, 54, 55, 56]
---

## Parent

[Deterministic dependency-remediation agent harness](../../prds/agent-remediation-harness.md)

## What to build

Turn the initial evidence output into a deterministic, tamper-evident authorization record. Canonical event hashes must link the full decision history, and the summary attestation must bind any approval to the exact inputs and policy evaluation. Evidence and diagnostics must remain useful without storing raw source, untrusted logs, or secrets.

## Acceptance criteria

- [ ] Canonical JSON serialization yields stable hashes for semantically identical normalized inputs.
- [ ] Each ledger event records sequence, run and finding identifiers, event type, injected timestamp, structured payload, previous-event hash, and its own hash.
- [ ] A verifier detects modified, removed, reordered, inserted, or incorrectly relinked ledger events.
- [ ] Each per-finding attestation contains the decision or processing error, primary reason, complete ordered rule evaluations, lifecycle state, and hashes for the finding, advisory, repository commit, proposal, observed diff, verification, policy, and artifact facts that apply.
- [ ] Changing any approval-bound input invalidates the prior approval rather than silently reusing it.
- [ ] Revised proposals are distinct immutable evaluations and are never merged into the earlier proposal history.
- [ ] Raw source, raw logs, issue text, and credential values are absent from ledger and attestation payloads.
- [ ] Secret-bearing fields are masked in model representations and structured logs, excluded where possible, and protected by a final redaction filter.
- [ ] Validation errors do not echo rejected secret input.
- [ ] Unit and integration tests use injected identifiers and clocks to prove determinism, chain verification, approval invalidation, and secret redaction.

## Blocked by

- [001 — Evaluate one safe remediation end to end](001-evaluate-safe-remediation-end-to-end.md)
