---
title: Isolate processing errors in batch runs
status: ready-for-agent
labels:
  - ready-for-agent
type: AFK
user_stories: [42, 43, 44, 45, 65, 66]
---

## Parent

[Deterministic dependency-remediation agent harness](../../prds/agent-remediation-harness.md)

## What to build

Make batch processing safely distinguish authorization outcomes from failures to obtain a valid decision. A malformed or operationally blocked finding must receive an isolated error record with no disposition while later findings continue in deterministic order. Expose the distinction through evidence, console output, and process exit status.

## Acceptance criteria

- [ ] Missing advisory enrichment, invalid provenance, unknown fixture IDs, unavailable infrastructure, timeouts, corrupt verification responses, and missing fixture records produce `run_status: error` with a null decision.
- [ ] Genuine completed test, build, probe, or rescan failures remain policy rejections and are not reclassified as processing errors.
- [ ] One finding's processing error does not stop later findings from being evaluated or prevent their attestations from being written.
- [ ] Batch order is stable by finding ID regardless of source input order.
- [ ] The CLI exits 0 when all findings are processed, including review and reject outcomes; exits 1 when any finding has an operational processing error; and exits 2 for invalid invocation or invalid top-level input.
- [ ] Console summaries and evidence clearly distinguish a null decision caused by processing failure from a completed rejection.
- [ ] Integration and CLI tests exercise mixed-result batches, all exit codes, and per-finding isolation.

## Blocked by

- [001 — Evaluate one safe remediation end to end](001-evaluate-safe-remediation-end-to-end.md)
