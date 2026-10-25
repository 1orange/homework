---
title: Deterministic dependency-remediation agent harness
status: ready-for-agent
labels:
  - ready-for-agent
---

## Problem Statement

The repository contains dependency findings for a Java inventory service and a Python report worker, but it does not contain a trustworthy mechanism for deciding whether an automated remediation proposal is safe to advance. A language model or repository instruction can suggest a version change, source migration, test exclusion, or shell command, but none of those suggestions are sufficient authorization to modify or merge code. The exercise needs a small, reviewable harness that demonstrates how an organization could simulate an agent, enrich findings with security-advisory facts, enforce deterministic safety policy, isolate failures, and produce an evidence trail showing why each proposal was accepted, routed to review, rejected, or not processed.

The harness must also demonstrate what evidence would be required to claim that a vulnerability is remediated in production. Real source-control, CI, scanner, deployment, and runtime integrations are outside this assignment, so those boundaries may be represented by deterministic fixtures. The existing vulnerable dependency files must remain unchanged: the repository is the test subject, not a production remediation target.

## Solution

Build a Python CLI harness using Pydantic and `pydantic-ai-slim`. For each validated scanner finding, a deterministic simulated agent produces one typed, declarative remediation proposal. A separate policy engine—not the agent—combines the finding, authenticated advisory enrichment, independently observed changes, and verification results to make an ordered, reproducible decision.

The harness will process findings sequentially in stable finding-ID order and isolate the result of each finding. Completed evaluations receive `accept`, `review`, or `reject`; infrastructure, provenance, or malformed-boundary failures receive `processing_error` with no decision. Accepted proposals are only eligible for an automated pull-request workflow. They never authorize direct pushes, branch-protection bypasses, deployments, arbitrary commands, or a production-remediation claim by themselves.

Every decision-relevant event will be written to a canonical JSONL ledger linked by hashes, with a per-finding summary attestation containing the decision, primary reason, complete ordered rule evaluations, input hashes, and lifecycle state. One fixture scenario may reach `verified_remediated` by supplying stubbed build, deployment, runtime-digest, SBOM, and post-deployment scan evidence. Its documentation must state plainly that the scenario demonstrates the workflow and does not attest to this checkout or a real environment.

The implementation will include a larger curated fixture dataset alongside the original findings, short architecture decision records, developer Docker tooling for both existing services and the harness, and documentation of the design, failure modes, scaling approach, AI assistance, and elapsed-time placeholder.

## User Stories

1. As a security engineer, I want every scanner finding validated at the harness boundary, so that malformed or unexpected input cannot silently influence authorization.
2. As a security engineer, I want scanner provenance verified independently of repository content, so that a checked-in JSON file cannot masquerade as an authenticated production finding.
3. As a demo operator, I want the provided findings file backed by clearly labelled checked-in fixtures, so that the trust shortcut is visible and cannot be confused with production behavior.
4. As a security engineer, I want advisory metadata enriched before proposal evaluation, so that affected ranges, fixed versions, CVSS data, and ecosystem identity inform the decision.
5. As a security engineer, I want conflicting scanner and advisory claims preserved and surfaced, so that the harness does not select whichever claim makes automation easier.
6. As a security engineer, I want advisory conflicts routed to human review with `ADVISORY_CONFLICT`, so that inconsistencies can be corrected without unsafe automation.
7. As a platform engineer, I want advisory and scanner adapters separated from policy, so that trusted production sources can replace fixtures without rewriting authorization rules.
8. As a platform engineer, I want production provenance represented by a verifier interface, so that a future Sigstore/in-toto implementation can validate signed attestations and workload identity.
9. As a demo operator, I want a deterministic fixture provenance verifier, so that the complete flow can run offline and repeatably.
10. As a security engineer, I want exactly one immutable proposal per finding evaluation, so that alternatives are never combined implicitly.
11. As an auditor, I want revised proposals treated as distinct evaluations, so that the history of authorization decisions remains understandable.
12. As a harness developer, I want the simulated agent to receive a bounded, typed proposal context, so that repository files, shell access, credentials, and network access are not exposed to it.
13. As a harness developer, I want PydanticAI's deterministic function model to select recorded fixture proposals by finding ID, so that tests do not make real model requests.
14. As a security engineer, I want proposals to be declarative typed data rather than shell commands, so that model output is not executable authority.
15. As a security engineer, I want unknown transformation or verification identifiers rejected, so that an agent cannot invent a privileged operation.
16. As a security engineer, I want repository instructions, logs, issues, and stale documentation labeled as untrusted context, so that prompt injection cannot override policy.
17. As a security engineer, I want optional logs or issue context bounded and redacted by a broker, so that useful diagnostics do not become authorization or evidence.
18. As a maintainer, I want the policy engine to be deterministic and ordered, so that identical normalized inputs always produce the same disposition, primary reason, and rule evaluations.
19. As an auditor, I want every rule evaluation retained in order, so that I can see all policy checks without a redundant aggregate reason list.
20. As an auditor, I want one primary reason selected by explicit precedence, so that downstream routing and reporting are stable.
21. As a maintainer, I want target package, ecosystem, service, installed version, and finding identity to match exactly, so that a proposal cannot remediate a different dependency.
22. As a maintainer, I want the chosen target version proven unaffected by trusted advisory data, so that a numerically newer version is not assumed safe.
23. As a maintainer, I want target selection to prefer the lowest-risk unaffected compatible release, so that automation does not blindly choose either the minimum fixed or latest version.
24. As a maintainer, I want downgrades routed to review, so that a valid but unusual remediation receives compatibility scrutiny.
25. As a Java maintainer, I want unknown Maven qualifiers, version ranges, or ambiguous coordinate migrations routed to review, so that simplistic version comparison cannot authorize them.
26. As a maintainer, I want direct non-major dependency updates eligible for acceptance only when all safety conditions pass, so that low-risk automation remains narrow.
27. As a maintainer, I want transitive dependency overrides routed to review unless an approved compatibility recipe exists, so that framework-managed dependency behavior is respected.
28. As an inventory-service maintainer, I want the SnakeYAML 2.0 proposal routed to review, so that its transitive nature and legacy tagged-YAML behavior receive human attention.
29. As an inventory-service maintainer, I want the Commons Collections 3.2.2 proposal routed to review for advisory conflict, so that disagreement with the supplied finding is visible.
30. As a report-worker maintainer, I want the PyYAML 5.4 dependency-only fixture proposal accepted when all recorded gates pass, so that the harness demonstrates a narrow safe path.
31. As a security engineer, I want CVSS used for priority rather than authorization, so that severity cannot waive safety requirements.
32. As a security engineer, I want reachability used for prioritization but not autonomous suppression, so that an affected artifact is not called remediated merely because current reachability appears absent.
33. As a security engineer, I want non-reachability exceptions to require human approval and expiry, so that temporary risk acceptance remains accountable.
34. As a maintainer, I want source changes accepted only through an allow-listed deterministic transformation over bounded paths, so that small safe migrations can be automated without granting general editing power.
35. As a maintainer, I want unapproved source migrations routed to review, so that plausible but behavior-changing changes receive scrutiny.
36. As a maintainer, I want unrelated, undeclared, or protected-file changes rejected, so that a narrow remediation cannot hide broader mutations.
37. As a maintainer, I want test deletion, exclusion, or weakening rejected, so that a dependency update cannot manufacture a green build.
38. As a maintainer, I want agent-authored test additions or strengthening routed to review unless produced by an approved deterministic recipe, so that new assertions are not mistaken for independent verification.
39. As a security engineer, I want harness-owned targeted security probes kept outside the proposed repository diff, so that the proposal cannot weaken its own security gate.
40. As a maintainer, I want current tests, build checks, a finding-specific security probe, and a dependency rescan to pass, so that acceptance requires more than an existing green suite.
41. As a maintainer, I want genuine completed verification failures rejected, so that a failing build, test, probe, or rescan cannot advance.
42. As an operator, I want verification timeouts, unavailable infrastructure, corrupt results, and missing fixtures reported as processing errors, so that operational uncertainty is not mislabeled as a security decision.
43. As an operator, I want a failed finding isolated from later findings, so that one bad input does not prevent the remainder of the batch from being evaluated.
44. As an auditor, I want a completed evaluation distinguished from an operational error, so that a null decision is never confused with rejection.
45. As an operator, I want findings processed sequentially in stable ID order, so that the demo ledger is reproducible.
46. As a future platform owner, I want the design to describe per-repository locking and conflict checks, so that parallel scale does not create competing changes to one service.
47. As a maintainer, I want `accept` to mean eligible for an automated remediation pull request, so that it is not confused with direct production mutation.
48. As a maintainer, I want accepted changes to wait for independent protected CI and security gates, so that the proposing agent cannot approve its own work.
49. As a maintainer, I want branch protection honored without bypasses, so that repository text cannot authorize auto-merge around required controls.
50. As an approver, I want approval bound to exact finding, advisory, repository commit, proposal, observed diff, verification, policy, and artifact hashes, so that any changed input invalidates the approval.
51. As an auditor, I want every decision-relevant event recorded in a canonical append-only ledger, so that the evaluation can be reconstructed.
52. As an auditor, I want ledger events linked by previous and current hashes, so that local deletion or mutation is detectable.
53. As an auditor, I want event payloads to contain hashes and structured facts rather than raw source, logs, or secrets, so that evidence is useful without becoming a data leak.
54. As a security engineer, I want secret-bearing model fields redacted in representations and logs, so that accidental diagnostics do not expose credentials.
55. As a security engineer, I want validation errors configured not to echo sensitive input, so that rejected payloads do not leak through error handling.
56. As an auditor, I want a per-finding summary attestation, so that the final disposition and evidence references are easy to consume without replaying the ledger.
57. As an auditor, I want lifecycle states from proposal through verified remediation, so that an accepted proposal is not prematurely described as fixed in production.
58. As an auditor, I want `verified_remediated` to require artifact digest, SBOM absence, authorized gates, completed deployment, fixed runtime digests on all replicas, a post-deployment scan, and no vulnerable rollback, so that production claims are evidence-based.
59. As an operator, I want rollback represented by a new immutable regression event that reopens the finding, so that history is preserved while current compliance changes.
60. As a reviewer, I want the demo remediation evidence clearly documented as fixture-generated, so that it is not presented as proof about this checkout or a real deployment.
61. As a reviewer, I want the original findings file unchanged, so that the supplied exercise input remains auditable.
62. As a reviewer, I want a larger curated fixture corpus covering acceptance, review, rejection, and operational errors, so that the policy can be demonstrated beyond three findings.
63. As a reviewer, I want expected outcomes stored with the fixtures, so that regressions are immediately visible.
64. As a CLI user, I want one command that evaluates a findings file and writes artifacts, so that the demo is easy to run.
65. As a CLI user, I want exit code 0 when all findings are processed even if some require review or are rejected, so that policy outcomes are not mistaken for program failures.
66. As a CLI user, I want exit code 1 for operational processing errors and exit code 2 for invalid invocation or top-level input, so that automation can distinguish failure classes.
67. As a CLI user, I want concise structured output summarizing each finding, so that I can see dispositions and evidence locations quickly.
68. As a developer without local Maven, I want containerized commands for the Java service tests, so that I can validate the repository consistently.
69. As a developer, I want separate one-shot containers for report-worker tests, report-worker smoke execution, harness tests, and harness evaluation, so that developer tasks remain explicit.
70. As a developer, I want the inventory API container to support a long-running service mode, so that its basic runtime behavior can be exercised.
71. As a security engineer, I want the harness container to run without a Docker socket or host credentials, so that the demo does not imply privileged orchestration.
72. As a reviewer, I want short focused architecture decision records explaining significant choices and trade-offs, so that the rationale survives beyond the code.
73. As a reviewer, I want a design document describing autonomy boundaries, review and rejection criteria, failure modes, and production evidence, so that trust assumptions are explicit.
74. As a reviewer, I want a concise scale-up paragraph covering growth from two to roughly 300 repositories, so that operational maturity is considered without overbuilding the assignment.
75. As an assessor, I want an honest AI-assistance statement and a placeholder for the candidate's actual elapsed time, so that the submission meets the assignment requirements without fabricated data.

## Implementation Decisions

- Use a flat Python package named `agent_harness`, targeting Python 3.11 or newer.
- Use `pydantic-ai-slim` without provider extras. The demo agent uses a deterministic function model and never makes a real model request.
- Make Pydantic boundary models strict with unknown fields forbidden. Adapt external formats explicitly; unsupported schema versions or fields become processing errors.
- Treat the proposal generator and authorization engine as separate trust domains. The agent proposes; only deterministic policy authorizes.
- Define a boundary-model module as the stable contract for findings, advisories, proposals, observed changes, verification reports, decisions, lifecycle facts, and run results.
- Define a context-collection module that exposes only bounded structured facts. It does not provide the agent direct filesystem, shell, Git, network, Docker, credential, log, or issue access.
- Define advisory enrichment as a deep module with a small interface returning normalized affected-state, fixed releases, severity metadata, provenance, and conflicts. Use deterministic fixtures now and document a trusted production adapter.
- Define provenance verification as a deep module. Supply a fixture verifier for the exercise and a documented production boundary based on signed Sigstore/in-toto attestations, OIDC workload identity, and transparency-log verification.
- Define the proposal agent as a deep module that accepts a typed canonical context and returns one typed immutable proposal. Unknown fixture finding IDs produce a processing error.
- Proposals may reference only registered transformation and verification identifiers. They cannot contain executable commands.
- Define a trusted change-observation boundary that independently reports actual changed files and content hashes. Agent-declared files represent intent only.
- Define the policy engine as a deep, pure module over normalized inputs. Rules run in a fixed order and emit a complete ordered list of evaluations plus one precedence-selected primary reason.
- Do not implement a weighted risk score. Use explicit rules and reason codes; CVSS influences priority only.
- Use `accept`, `review`, and `reject` only for completed evaluations. Represent operational failure separately as `run_status: error` with no decision.
- Apply this outcome model: accept only when every autonomous condition succeeds; review plausible changes requiring judgment or exception; reject invalid, unsafe, policy-bypassing, or genuinely failed proposals.
- Autonomous acceptance requires an exact finding/target match, a trusted unaffected target, a direct non-major dependency update or approved deterministic recipe, an allowed bounded diff, no weakening of controls, and complete successful verification.
- Downgrades, major upgrades, unapproved transitive overrides, unapproved source migrations, and supported exceptions route to review.
- Mismatches, affected or unverifiable targets, test or CI weakening, protected or unrelated changes, repository-prompt obedience, fabricated evidence, policy bypasses, and genuine gate failures are rejected.
- Conflicting authoritative advisory facts route to review with `ADVISORY_CONFLICT`, preserving each claim for human correction.
- Evaluate Python versions with standard packaging semantics. Normalize Maven coordinates and support simple numeric versions for the exercise; ambiguous ranges or qualifiers route to review.
- Use an allow-list of deterministic transformations with bounded file patterns. Keep policy in the harness for the assignment, while documenting that production policy should be released from a separately secured repository and authenticated independently of target repositories.
- Allow runtime configuration to make policy stricter, never weaker.
- Process findings sequentially in stable finding-ID order. Each finding has an isolated result and evidence chain; one processing error does not terminate subsequent evaluations.
- Do not implement output-directory collision, resume, or overwrite behavior. The demo assumes a fresh destination.
- Canonicalize JSON before hashing. Inject time and identifiers so deterministic tests can control them.
- Write an append-only JSONL event ledger containing sequence, run and finding identifiers, event type, timestamp, structured payload, previous hash, and event hash.
- Write one summary attestation per finding containing the decision or processing error, primary reason, ordered rule evaluations, lifecycle state, and referenced input/evidence hashes.
- Keep raw source, raw logs, issue text, and secrets out of evidence. Use Pydantic secret types as defense in depth, exclude secret fields where practical, use structured logging, and apply a final redaction filter.
- Model the remediation lifecycle as proposed, authorized, merged, built, deployed, and verified remediated. Acceptance alone advances only to authorization eligibility.
- Permit a fixture-backed scenario to reach `verified_remediated` when all required production facts are present. Communicate simulation through fixture placement, example labeling, and documentation.
- Represent rollback or vulnerable runtime reappearance as a new append-only regression event that reopens the finding and invalidates current compliant status.
- Provide a CLI as the initial interface. A future FastAPI layer should be a thin adapter over the same orchestration and domain modules.
- The CLI accepts a findings input and output destination. It returns 0 for a fully processed batch regardless of policy dispositions, 1 if any per-finding operational error occurs, and 2 for invalid invocation or top-level input.
- Preserve the supplied findings and vulnerable service dependency files unchanged. All proposal, diff, verification, deployment, runtime, and rescan activity is simulated through fixtures.
- Add a curated dataset of approximately fourteen cases spanning safe direct acceptance, an approved deterministic source transformation, major upgrade review, downgrade review, transitive review, advisory conflict, source-migration review, mismatch rejection, affected-target rejection, test weakening, undeclared diff, protected paths, missing advisory data, and invalid provenance.
- Use the three supplied findings for the principal outcome matrix: PyYAML routes to accept with recorded gates passing; SnakeYAML routes to review due to transitive compatibility and excluded legacy behavior; Commons Collections routes to review due to advisory conflict.
- Keep the existing CI workflow unchanged. Explicitly document that repository instructions suggesting test exclusion, credential refresh, branch-protection bypass, or unconditional dependency auto-merge are untrusted and cannot alter harness policy.
- Maintain a canonical project definition and generated, pinned runtime and development requirement files so standard virtual environments, uv, and Poetry-style project consumers can install the project without Poetry-specific configuration.
- Provide Docker images and a root Compose file as developer tooling only. The harness does not orchestrate containers or receive a Docker socket.
- Provide short ADRs for: deterministic authorization separated from proposals; declarative allow-listed transformations; untrusted repository context and authenticated security inputs; and hash-linked evidence with runtime verification before a remediation claim.
- Provide root design and submission documentation, a focused harness README, developer commands, an example evidence artifact, three required failure-mode analyses, and a concise production-scale discussion.
- The three primary failure modes are: unavailable advisory enrichment causing a safe processing error; a malicious or malformed proposal attempting policy or diff-verification bypass, which is unsafe if controls fail; and deployment evidence diverging from runtime state through old replicas or rollback, which is unsafe until runtime reconciliation detects it.
- The scale design should cover durable queues, idempotency and retries, ownership routing, per-repository locks, centrally signed policy rollout, bounded advisory caches, isolated execution, durable searchable evidence, SLA prioritization, metrics, canary rollout, rollback handling, and continuous production reconciliation.

## Testing Decisions

- Tests assert externally visible contracts and policy behavior rather than private implementation details. A useful policy test supplies normalized inputs and verifies disposition, primary reason, ordered rule evaluations, and evidence facts; it does not assert which helper method ran.
- Unit-test all strict boundary models, external adapters, ecosystem identity checks, Python and simplified Maven version handling, canonical serialization, hashing, ledger chaining, redaction, lifecycle validation, reason precedence, and individual policy rules.
- Unit-test the deterministic policy engine with table-driven cases for every accepted, reviewed, rejected, and processing-error fixture.
- Unit-test that input ordering cannot change a finding's decision or ordered rule evaluations.
- Unit-test that unknown transformation and verification identifiers never execute and are rejected.
- Unit-test that repository instructions, logs, stale docs, and issue text have no authority to change policy outcomes.
- Unit-test the distinction between a completed genuine verification failure and unavailable, timed-out, corrupt, or missing verification infrastructure.
- Unit-test that secrets are masked in model representations, validation errors, structured logs, and evidence serialization.
- Unit-test canonical ledger hashes and detection of modified, removed, reordered, or relinked events.
- Integration-test the complete deterministic flow from function-model proposal generation through advisory enrichment, provenance checks, independent change observation, policy evaluation, ledger creation, and summary attestation.
- Integration-test per-finding isolation by mixing successful decisions and processing errors in one batch and confirming later findings are still evaluated.
- Integration-test the supplied three-finding outcome matrix and every curated fixture case against expected results.
- Integration-test the `verified_remediated` fixture lifecycle, including artifact digest, SBOM absence, authorized gates, completed rollout, runtime digest agreement, post-deployment scan, and absence of vulnerable rollback.
- Integration-test regression handling by appending a rollback or vulnerable-runtime event and confirming the finding reopens without rewriting earlier evidence.
- Add a stubbed end-to-end CLI test that runs the aggregate fixture dataset, checks exit status and concise output, validates all expected attestations, and verifies the JSONL hash chain.
- Add CLI end-to-end tests for invalid invocation or top-level input returning 2 and per-finding processing errors returning 1.
- Ensure all agent tests deny real model requests and require the deterministic function model.
- Keep container smoke and service tests separate from policy tests. Validate that each documented Compose command starts or completes with its intended role.
- Use the repository's existing service tests only as prior art for how the sample services run; do not treat their sparse coverage as sufficient remediation evidence and do not modify them for the harness.

## Out of Scope

- Applying any proposed dependency or source-code remediation to the inventory service or report worker.
- Direct pushes, branch creation, pull-request creation, merging, deployment, scanner invocation, or runtime-cluster access.
- Real LLM/provider calls or evaluation of model quality.
- Executing shell commands supplied by an agent.
- Allowing the harness to control Docker or mount a Docker socket.
- Production implementation of Sigstore/in-toto verification, transparency-log lookup, scanner APIs, Git hosting, CI, artifact registries, SBOM services, deployment platforms, or runtime inventory.
- A web or FastAPI interface.
- Multi-proposal ranking, implicit proposal composition, or agent negotiation.
- Parallel evaluation, distributed locks, durable job queues, retries, resume, output overwrite handling, or artifact retention enforcement.
- Enforcing advisory freshness windows; timestamps and provenance are recorded for a future production control.
- A full Maven version-range and qualifier solver.
- Automatic reachability-based suppression.
- A production policy repository, signing service, or policy distribution mechanism.
- Modifying the existing CI workflow, stale runbook, conflicting contribution guidance, or original findings.
- Claiming that this checkout or any real deployment has been remediated.

## Further Notes

- The assignment rewards decision quality, trust boundaries, evidence, and failure handling more than breadth of infrastructure. The implementation should stay intentionally small and readable.
- The supplied repository includes adversarial or unsafe operational guidance. It is useful test data: dependency-only auto-merge, branch-protection bypass, excluded failing tests, and credential-refresh instructions must never become authorization inputs.
- The SnakeYAML case illustrates why a high-severity fixed version is not automatically safe: the proposed transitive major upgrade changes tagged-object behavior used by an excluded integration test.
- The Commons Collections case intentionally exposes advisory disagreement. The supplied scanner text says no patched 3.x release, while trusted public advisory data identifies 3.2.2 as fixed; the correct automated result is review, not silent conflict resolution.
- The accepted PyYAML scenario is a fixture only. Its evidence demonstrates what a complete automated workflow would require while leaving the vulnerable baseline untouched.
- The submission note should describe AI assistance honestly and leave the elapsed time for the candidate to enter after completing the exercise.
