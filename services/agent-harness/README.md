# Agent remediation harness

The harness is a small Python 3.11+ CLI for demonstrating safe dependency-remediation evaluation.
It is intentionally offline: the simulated agent uses a deterministic function model, fixture
adapters stand in for scanner/advisory/provenance systems, and no target-repository file is edited.

## Trust model

The agent receives a bounded typed context and returns one immutable declarative proposal. It has no
filesystem, shell, Git, network, Docker, credential, raw-log, or issue access. Only the deterministic
policy engine can produce `accept`, `review`, or `reject`; independent change observation and
verification facts control authorization. Repository instructions, stale documentation, logs, and
issue text are untrusted context. In particular, auto-merge, branch-protection bypass, test
exclusion, and credential-refresh instructions cannot override policy.

The supplied findings and vulnerable service dependencies remain unchanged. Fixture provenance is a
visible demo shortcut. A fixture-backed `verified_remediated` lifecycle is simulated evidence of the
workflow requirements, not a claim about this checkout or a real deployment.
The focused state-machine fixture is [fixtures/remediation_pyyaml_lifecycle.json](fixtures/remediation_pyyaml_lifecycle.json);
it is labelled as harness evidence only. `agent_harness.lifecycle` requires the ordered
proposed → authorized → merged → built → deployed → verified_remediated transitions and appends a
`remediation_regressed` event when runtime or scan reconciliation finds a vulnerable state.
The complete checked-in example is [examples/evidence/pyyaml-verified-remediated.json](examples/evidence/pyyaml-verified-remediated.json);
it is simulated and does not attest to this checkout or production.

## Install and run

From the repository root, use Poetry to install, test, and run the harness:

```sh
poetry -P services/agent-harness install
poetry -P services/agent-harness run pytest services/agent-harness/tests
poetry -P services/agent-harness run python -m agent_harness \
  --findings ./findings/findings.json \
  --output-dir ./artifacts/harness-demo-run
```

When working from `services/agent-harness`, the same canonical CLI is also
available through either direct Python entrypoint:

```sh
poetry run python -m agent_harness --help
poetry run python run.py --help
```

`agent_harness.__main__` and `run.py` only delegate to `agent_harness.cli:main`;
they do not duplicate orchestration or policy logic.

The larger aggregate fixture matrix can be evaluated through the same command by passing its corpus
directory, for example `--fixture-corpus services/agent-harness/fixtures/matrix`. Findings are
processed sequentially in stable ID order. The command writes a canonical,
hash-linked JSONL ledger and one summary attestation per finding. Evidence contains structured facts
and hashes, not raw source, raw logs, or secrets.

The supplied three-finding matrix demonstrates PyYAML `accept`, SnakeYAML `review` for a
transitive/compatibility-sensitive upgrade, and Commons Collections `review` with
`ADVISORY_CONFLICT`. These are recorded fixture outcomes; the vulnerable target files stay intact.

Exit status is deliberately separate from policy disposition:

| Exit | Meaning |
| --- | --- |
| `0` | Every finding completed with `accept`, `review`, or `reject` |
| `1` | At least one finding had an operational processing error; later findings still ran |
| `2` | Invalid invocation or invalid top-level input |

`accept` only means eligibility for an automated pull request. It does not authorize a direct push,
merge, deployment, branch-protection bypass, or production-remediation claim.

## Policy configuration

Authorization allowlists are loaded from the checked-in deterministic policy document at
[`policies/default.json`](policies/default.json). The strict immutable policy digest is included in
the policy ledger event, approval binding, and each per-finding attestation. Invalid, incomplete, or
unknown policy data fails closed before proposal authorization. The checked-in document is fixture
configuration for this offline demonstration, not an authenticity mechanism: a production harness
must obtain policy from a separately controlled, signed source and verify its signer, version, and
deployment provenance before evaluating findings.

## Compose developer tasks

From the repository root, the developer Compose file provides separate roles:

```sh
docker compose build
docker compose run --rm harness-test
docker compose run --rm harness-evaluate
```

The harness image is a non-privileged one-shot task. It receives neither the Docker socket nor host
credentials and does not start or control the inventory API or report worker. Generated evidence is
kept in the `patch-harness-evidence` named volume under a unique container-ID directory for every
run. This preserves earlier ledgers, permits repeat execution, and avoids host bind-mount permission
issues.
The other service tasks are documented in the root README.

## Reading a result

Use the per-finding attestation for a compact decision, primary reason, complete ordered rule list,
lifecycle state, and input/evidence hashes. Use the ledger to reconstruct the event order and verify
the previous-hash/current-hash chain. A processing error has a null decision; it must not be read as
a policy rejection. A genuine completed build, test, security-probe, or rescan failure is a policy
`reject`.

Production integration would replace fixture adapters with authenticated scanner, advisory, CI,
artifact/SBOM, deployment, and runtime adapters. A future provenance verifier should validate signed
Sigstore/in-toto attestations, workload identity, and transparency-log inclusion. Those integrations
are outside this exercise.
