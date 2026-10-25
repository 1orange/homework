---
title: Exercise the complete deterministic demo matrix
status: ready-for-agent
labels:
  - ready-for-agent
type: AFK
user_stories: [23, 24, 25, 28, 29, 30, 32, 33, 34, 35, 36, 37, 38, 39, 40, 41, 42, 43, 45, 62, 63]
---

## Parent

[Deterministic dependency-remediation agent harness](../../prds/agent-remediation-harness.md)

## What to build

Assemble the complete offline demo corpus and run every scenario through the same public CLI path. The aggregate dataset must make the decision matrix inspectable, prove per-finding isolation and determinism, and provide expected outputs for safe upgrades, review cases, unsafe mutations, and infrastructure failures.

## Acceptance criteria

- [ ] The curated corpus contains approximately fourteen cases covering a safe direct update, an approved deterministic source transformation, major-upgrade review, downgrade review, transitive review, advisory-conflict review, source-migration review, target mismatch, affected target, test weakening, undeclared diff, protected path, missing advisory, and invalid provenance.
- [ ] Findings, advisories, proposals, observed changes, verification results, and expected decisions are separate fixture inputs joined by stable finding identity.
- [ ] The three supplied findings produce the agreed matrix: PyYAML accept, SnakeYAML review, and Commons Collections review with `ADVISORY_CONFLICT`.
- [ ] The aggregate CLI run evaluates every finding sequentially, continues after operational errors, and writes one independently verifiable attestation per finding.
- [ ] Reordering source fixtures cannot change a finding's disposition, primary reason, ordered rule evaluations, or normalized evidence hashes when the injected clock and identifiers are fixed.
- [ ] No test makes a real model, network, scanner, source-control, deployment, runtime, or container-control request.
- [ ] Expected-result fixtures fail the test suite when any disposition, primary reason, rule order, lifecycle state, or run status regresses.
- [ ] A stubbed end-to-end test invokes the public CLI, validates its summary and exit status, checks all expected attestations, and verifies every ledger hash chain.

## Blocked by

- [002 — Route ambiguous remediations to review](002-route-ambiguous-remediations-to-review.md)
- [003 — Reject unsafe remediation proposals](003-reject-unsafe-remediation-proposals.md)
- [004 — Isolate processing errors in batch runs](004-isolate-processing-errors-in-batch-runs.md)
- [006 — Verify and regress production remediation state](006-verify-and-regress-production-remediation-state.md)
