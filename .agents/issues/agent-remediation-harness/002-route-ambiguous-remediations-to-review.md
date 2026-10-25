---
title: Route ambiguous remediations to review
status: ready-for-agent
labels:
  - ready-for-agent
type: AFK
user_stories: [5, 6, 24, 25, 27, 28, 29, 31, 32, 33, 35, 38]
---

## Parent

[Deterministic dependency-remediation agent harness](../../prds/agent-remediation-harness.md)

## What to build

Extend the end-to-end evaluator with explicit review routes for plausible remediations that require human judgment. Preserve conflicting claims and compatibility context in the evidence rather than choosing whichever input permits automation. Demonstrate the behavior through the supplied SnakeYAML and Commons Collections findings plus focused synthetic fixtures.

## Acceptance criteria

- [ ] The SnakeYAML 1.30-to-2.0 fixture completes with `review` because it is an unapproved transitive major override with behavior-sensitive excluded coverage.
- [ ] The Commons Collections 3.2.1-to-3.2.2 fixture completes with `review` and primary reason `ADVISORY_CONFLICT`, preserving both the scanner claim and trusted advisory claim.
- [ ] Downgrades, major upgrades, unapproved transitive overrides, unapproved source migrations, and ambiguous Maven ranges or qualifiers deterministically route to review.
- [ ] CVSS and reachability influence priority metadata but cannot autonomously authorize or suppress a remediation.
- [ ] A non-reachability exception requires explicit human review, expiry, tool identity, repository commit, and coverage context.
- [ ] Agent-authored test additions or strengthening route to review unless produced by a registered deterministic transformation.
- [ ] Every review result contains one stable primary reason and all ordered rule evaluations in its ledger and attestation.
- [ ] Unit and end-to-end fixture tests verify the exact review outcomes and prove input reordering does not change per-finding results.

## Blocked by

- [001 — Evaluate one safe remediation end to end](001-evaluate-safe-remediation-end-to-end.md)
