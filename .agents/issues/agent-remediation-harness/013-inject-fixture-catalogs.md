---
title: Inject fixture catalogs into harness adapters
status: ready-for-agent
labels:
  - ready-for-agent
type: AFK
---

## Parent

[Deterministic dependency-remediation agent harness](../../prds/agent-remediation-harness.md)

## What to build

Move all recorded demo proposals, advisories, change observations, and verification reports out of runtime adapter and orchestration modules into validated fixture catalogs. Fixture-mode composition should explicitly inject those catalogs into the deterministic FunctionModel agent and adapter boundaries, while the harness itself remains unaware of where records were stored. Reuse the existing aggregate corpus concepts rather than introducing a second unrelated loading mechanism.

## Acceptance criteria

- [ ] The deterministic proposal agent receives a typed proposal provider or catalog and contains no finding-specific proposal table.
- [ ] The fixture advisory adapter receives a typed advisory provider or catalog and contains no CVE-specific fact table.
- [ ] Recorded change observations and verification reports no longer live as finding-specific constants in the orchestrator.
- [ ] The supplied three-finding CLI demo loads its complete scenario data from a checked-in, non-executable fixture corpus.
- [ ] The larger aggregate matrix continues to use the same catalog abstractions and retains deterministic ordering and provenance validation.
- [ ] Fixture-mode composition is explicit through a small factory or composition root; production-facing interfaces do not silently construct demo dependencies.
- [ ] The PydanticAI FunctionModel remains deterministic, local, and limited to returning one immutable typed proposal.
- [ ] Existing CLI outcomes, evidence contracts, per-finding isolation, and complete tests remain valid.

## Blocked by

None - can start immediately.
