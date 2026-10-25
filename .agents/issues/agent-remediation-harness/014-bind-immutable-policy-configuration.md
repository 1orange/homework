---
title: Bind immutable policy configuration into evidence
status: ready-for-agent
labels:
  - ready-for-agent
type: AFK
---

## Parent

[Deterministic dependency-remediation agent harness](../../prds/agent-remediation-harness.md)

## What to build

Represent authorization allowlists as a strict, immutable policy configuration loaded explicitly by fixture composition. The evaluator should receive this configuration rather than depending on module-level authorization sets, and every completed decision should bind the exact canonical policy digest into its evidence. Keep decision algorithms and security-validation regexes in code; only bounded policy data belongs in the external policy document.

## Acceptance criteria

- [ ] A strict immutable policy model covers registered transformations, required verification gates, review-only transformations, and bounded source paths.
- [ ] The checked-in default policy is stored under the harness policy directory in a deterministic, reviewable format.
- [ ] Policy evaluation receives its configuration explicitly and contains no module-level authorization frozensets.
- [ ] The orchestrator and CLI load policy through explicit composition rather than hidden import-time state.
- [ ] The canonical policy digest is included in the approval binding, policy evidence event, and per-finding attestation.
- [ ] Unknown, malformed, or incomplete policy configuration fails closed before proposal authorization.
- [ ] Tests prove that changing policy data changes its digest and invalidates reuse of an old approval binding.
- [ ] Redaction, identifier, digest, and path-validation regular expressions remain implementation details beside their owning behavior.
- [ ] Documentation explains that the checked-in policy is demo configuration and that production policy authenticity requires a separately controlled signed source.

## Blocked by

None - can start immediately.
