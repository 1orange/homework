# Submission notes

## Reviewer quick start

Run these commands from the repository root. The harness test suite takes about 2 seconds after
dependencies are installed; the fixture evaluation takes under 1 second.

```sh
poetry -P services/agent-harness install
poetry -P services/agent-harness run pytest services/agent-harness/tests -q
poetry -P services/agent-harness run python -m agent_harness \
  --findings ./findings/findings.json \
  --output-dir ./artifacts/harness-demo
```

Expected test result at submission time: `80 passed`.

Expected fixture decisions:

| Finding | Decision | Primary reason |
| --- | --- | --- |
| `F-40218` | `review` | `TRANSITIVE_OVERRIDE` |
| `F-40219` | `accept` | `ELIGIBLE_FOR_AUTOMATED_PULL_REQUEST` |
| `F-40220` | `review` | `ADVISORY_CONFLICT` |

## What is included

1. A deterministic offline harness around the supplied dependency findings.
2. Strict typed boundaries for findings, advisories, proposals, observed changes, and verification.
3. An ordered policy engine that separates `accept`, `review`, `reject`, and processing errors.
4. A hash-linked JSONL evidence ledger plus one summary attestation per finding.
5. Tests for policy, boundaries, orchestration, lifecycle, evidence, entrypoints, and failure isolation.

The proposal agent is intentionally constrained. It receives bounded facts, returns one declarative
proposal, and cannot use the filesystem, shell, Git, network, Docker, credentials, raw logs, or
issue content. Independent adapters supply the observed diff and verification facts. Only the
deterministic policy engine can authorize a proposal.

## Result meanings

| Result | Meaning |
| --- | --- |
| `accept` | Eligible for an automated pull request; not approved to merge or deploy |
| `review` | Plausible remediation requiring human judgment |
| `reject` | Completed evaluation found an unsafe or invalid proposal |
| `run_status: error` | A boundary failed, so no safe decision was possible and `decision` is `null` |

Repository instructions that recommend bypassing branch protection, excluding failed tests, or
refreshing credentials are treated as adversarial context. They cannot modify policy.

## Deliberate limits

- The original findings and vulnerable dependency declarations are unchanged.
- The harness does not apply patches, open pull requests, merge, or deploy.
- External systems are represented by deterministic fixtures; no real model or service is called.
- Fixture provenance is a demonstration shortcut, not production authentication.
- The PyYAML `verified_remediated` lifecycle is simulated and makes no claim about this checkout,
  a built artifact, or a real environment.

Production integrations would need authenticated scanner and advisory inputs, signed policy,
independent CI and artifact/SBOM evidence, deployment and runtime inventory, and signed
Sigstore/in-toto provenance. See [DESIGN.md](DESIGN.md) for the trust model and failure behavior.

## Container verification

Use Docker Compose when the host does not have the required toolchains:

```sh
docker compose build harness-evaluate
docker compose run --rm harness-test
docker compose run --rm harness-evaluate
```

The harness container is a non-privileged one-shot task. It has no Docker socket, host credentials,
or network access. Generated evidence is stored in the `patch-harness-evidence` named volume under a
new container-ID directory for each run.

## AI assistance disclosure

AI assistance was used to inspect the repository and assignment, draft documentation, and help
implement and review changes. I reviewed the resulting work and remain responsible for the scope,
design decisions, security analysis, tests, and submission accuracy.

## Time spent

Approximate implementation and documentation time: **4.5 hours**.
