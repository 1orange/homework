# ADR-0004: Bind evidence and production claims by hashes

Status: Accepted

## Context

An accepted proposal is not proof that a merge, artifact, deployment, or runtime is fixed. Evidence
can be changed, omitted, or become stale, and a rollback can reintroduce a vulnerable digest after a
successful deployment.

## Decision

Write canonical append-only JSONL events linked by previous and current hashes. Per-finding
attestations bind the decision to the exact finding, advisory, repository commit, proposal, observed
diff, verification, policy, and artifact facts. Advance through proposed, authorized, merged, built,
deployed, and verified-remediated states only when the required independent facts agree. Require a
fixed artifact digest, authorized gates, SBOM absence, completed deployment, fixed digests on every
replica, a clean post-deployment scan, and no vulnerable rollback. Append a regression event and
reopen the finding when runtime evidence diverges.

## Alternatives and trade-offs

A mutable status row would be easier to query, but would obscure history and make tampering harder to
detect. Declaring remediation at merge would be faster, but would conflate source intent with runtime
state. Hashes and reconciliation add storage and operational work, yet preserve reconstructable
history and make production claims evidence-based.

## Consequences

Changing an approval-bound input invalidates the old authorization rather than silently reusing it.
Fixture evidence can demonstrate the complete workflow while documentation keeps its simulated status
explicit. Continuous runtime reconciliation remains necessary after the initial claim.
