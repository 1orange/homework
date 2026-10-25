---
title: Document trust boundaries and submission
status: ready-for-agent
labels:
  - ready-for-agent
type: AFK
user_stories: [8, 46, 47, 48, 49, 60, 72, 73, 74, 75]
---

## Parent

[Deterministic dependency-remediation agent harness](../../prds/agent-remediation-harness.md)

## What to build

Complete the submission documentation around the implemented behavior. Explain the authorization boundary, evidence model, autonomous/review/reject criteria, important trade-offs, failure analysis, developer workflow, and a credible path from the exercise to hundreds of repositories. Keep significant decisions short and rationale-led, and disclose AI assistance without inventing the candidate's elapsed time.

## Acceptance criteria

- [ ] The design document explains proposal-versus-policy separation, authenticated inputs, bounded context, decision semantics, verification gates, evidence lifecycle, and why acceptance is not a production-remediation claim.
- [ ] The design explicitly identifies repository instructions about auto-merge, branch-protection bypass, test exclusion, and credential refresh as untrusted and unsafe authorization inputs.
- [ ] Four concise ADRs record: deterministic authorization separated from proposals; declarative allow-listed transformations; untrusted repository context with authenticated security inputs; and hash-linked evidence plus runtime verification before remediation claims.
- [ ] Each ADR uses a consistent template, emphasizes why, and records meaningful alternatives or trade-offs.
- [ ] The three primary failure modes cover unavailable enrichment, malicious or malformed proposal bypass, and deployment/runtime divergence, including whether each failure is safe or unsafe and how it is detected.
- [ ] The production provenance section describes a future Sigstore/in-toto verifier with workload identity and transparency-log validation without pretending it is implemented.
- [ ] The scaling paragraph covers durable queues, idempotency and retries, ownership routing, per-repository locks, centrally signed policy rollout, bounded caches, isolated execution, durable evidence, SLA prioritization, metrics, canaries, rollback, and continuous runtime reconciliation.
- [ ] Root and harness guidance document host and Compose commands, fixture semantics, CLI exit codes, output artifacts, and the fact that the target services remain intentionally vulnerable.
- [ ] The evidence example is clearly labeled as a simulated fixture scenario and does not claim anything about this checkout or a real deployment.
- [ ] The submission note accurately describes AI assistance and contains a conspicuous placeholder for the candidate to enter actual elapsed time.
- [ ] Documentation matches the final tested behavior and contains no instruction to change the existing CI workflow.

## Blocked by

- [002 — Route ambiguous remediations to review](002-route-ambiguous-remediations-to-review.md)
- [003 — Reject unsafe remediation proposals](003-reject-unsafe-remediation-proposals.md)
- [004 — Isolate processing errors in batch runs](004-isolate-processing-errors-in-batch-runs.md)
- [006 — Verify and regress production remediation state](006-verify-and-regress-production-remediation-state.md)
- [007 — Exercise the complete deterministic demo matrix](007-exercise-complete-deterministic-demo-matrix.md)
- [008 — Run all components with Docker Compose](008-run-all-components-with-docker-compose.md)
