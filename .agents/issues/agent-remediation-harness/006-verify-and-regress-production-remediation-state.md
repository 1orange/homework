---
title: Verify and regress production remediation state
status: ready-for-agent
labels:
  - ready-for-agent
type: AFK
user_stories: [57, 58, 59, 60]
---

## Parent

[Deterministic dependency-remediation agent harness](../../prds/agent-remediation-harness.md)

## What to build

Extend the evidence model beyond authorization to demonstrate the production-remediation proof required by the assignment. A fixture-backed scenario may advance through the full lifecycle only when independently recorded artifact, deployment, runtime, SBOM, and scan facts agree. A later rollback or vulnerable runtime observation must append a regression event and reopen the finding without rewriting history.

## Acceptance criteria

- [ ] The lifecycle distinguishes proposed, authorized, merged, built, deployed, and verified-remediated states; acceptance alone cannot skip to a production claim.
- [ ] `verified_remediated` requires the fixed commit and artifact digest, successful authorized gates, SBOM confirmation that the vulnerable artifact is absent, completed deployment, every runtime replica on the fixed digest, a clean post-deployment scan, and no vulnerable rollback.
- [ ] Missing, conflicting, or stale lifecycle evidence prevents transition to `verified_remediated`.
- [ ] The complete fixture-backed PyYAML scenario reaches `verified_remediated` without changing either target service.
- [ ] Fixture placement, example labeling, and documentation make clear that this demonstrates harness behavior and is not an attestation about the checkout or a real environment.
- [ ] A rollback, old replica, vulnerable digest, or new positive scan appends an immutable remediation-regressed event, reopens the finding, invalidates current compliant status, and retains earlier history.
- [ ] Integration tests cover every required lifecycle fact, invalid transition attempts, the successful fixture path, and regression reopening.

## Blocked by

- [005 — Make evidence tamper-evident and secret-safe](005-make-evidence-tamper-evident-and-secret-safe.md)
