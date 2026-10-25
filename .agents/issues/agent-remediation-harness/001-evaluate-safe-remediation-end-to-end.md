---
title: Evaluate one safe remediation end to end
status: ready-for-agent
labels:
  - ready-for-agent
type: AFK
user_stories: [1, 2, 3, 4, 7, 9, 10, 11, 12, 13, 14, 18, 19, 20, 21, 22, 23, 26, 30, 40, 44, 45, 47, 51, 56, 61, 64, 67]
---

## Parent

[Deterministic dependency-remediation agent harness](../../prds/agent-remediation-harness.md)

## What to build

Deliver the first complete harness path for the safe PyYAML fixture. A CLI invocation must validate a finding, verify fixture provenance, enrich it with trusted advisory facts, ask a deterministic PydanticAI function model for exactly one declarative proposal, authorize the proposal with policy independent of the agent, and emit readable evidence. This slice establishes the installable Python project and its stable domain contracts while leaving both target services and the supplied findings unchanged.

## Acceptance criteria

- [ ] The harness installs on Python 3.11 or newer from the canonical project metadata and pinned runtime/development requirement files, using `pydantic-ai-slim` without provider extras.
- [ ] Strict boundary models reject unknown input fields and distinguish findings, advisories, proposals, observed changes, verification reports, rule evaluations, and run results.
- [ ] Checked-in fixture provenance is validated through a replaceable verifier boundary; no repository file is treated as production-authenticated input.
- [ ] Advisory enrichment returns normalized ecosystem identity, affected status, fixed versions, CVSS metadata, provenance, and source claims through a replaceable adapter boundary.
- [ ] The simulated agent receives only a bounded typed context and returns exactly one immutable typed proposal selected by finding ID, without filesystem, shell, Git, network, Docker, or credential access.
- [ ] Real model requests are disabled in tests and no proposal field can carry an executable command.
- [ ] The policy accepts the PyYAML 5.3.1-to-5.4 fixture only when identity, direct non-major target, unaffected status, allowed dependency-only change, and all required verification gates match.
- [ ] The completed result contains `accept`, a stable primary reason, and the complete ordered rule evaluations; acceptance is described only as eligibility for an automated pull request.
- [ ] The CLI processes findings in stable finding-ID order, prints a concise structured summary, writes a per-finding attestation plus event ledger, and exits 0 for the safe fixture.
- [ ] Unit, integration, and CLI tests cover the entire finding-to-evidence path and prove that neither the original findings nor vulnerable service dependency files are modified.

## Blocked by

None - can start immediately.
