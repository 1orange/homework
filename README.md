# patch-harness-exercise

Two small services that share a findings feed. Both have dependency findings open against them.

- `services/inventory-api` — Java 17, Spring Boot, Maven
- `services/report-worker` — Python 3.11

Open findings are in `findings/findings.json`, in the shape our scanner emits.

## Prerequisites

JDK 17 and Maven 3.9+ for the Java service. Python 3.11 for the worker. No wrapper scripts;
use your own toolchain.

## Running things

    cd services/inventory-api
    mvn test

    cd services/report-worker
    pip install -r requirements.lock pytest
    pytest

## Notes

Ownership of the report worker moved during the platform migration and the docs under
`docs/` are partly stale. See `CONTRIBUTING.md` before opening changes.

## Remediation harness

`services/agent-harness` is an offline, deterministic demonstration of a dependency-remediation
authorization boundary. It evaluates scanner-shaped findings from checked-in fixtures, asks a
deterministic function model for one typed proposal, and lets a separate policy engine decide
whether that proposal is eligible for an automated pull request. It does not edit either target
service, call a real model, contact a scanner or deployment system, or claim that this checkout is
remediated.

The supplied findings and vulnerable dependency declarations are intentionally unchanged. Fixture
evidence is labelled as simulated: it demonstrates the facts a production verifier would require,
but says nothing about this repository or a real deployment.

From the repository root, install, test, and run the harness with Poetry:

```sh
poetry -P services/agent-harness install
poetry -P services/agent-harness run pytest services/agent-harness/tests
poetry -P services/agent-harness run python -m agent_harness \
  --findings ./findings/findings.json \
  --output-dir ./artifacts/harness-demo-run
```

The complete three-finding fixture corpus can be selected explicitly with
`--fixture-corpus services/agent-harness/fixtures/demo`.

From `services/agent-harness`, the same CLI can also be invoked directly with
Poetry:

```sh
poetry run python -m agent_harness --help
poetry run python run.py --help
```

Both Python entrypoints delegate to the same canonical CLI implementation.

The evaluator processes findings in stable ID order and writes a JSONL ledger plus one summary
attestation per finding. `accept`, `review`, and `reject` are completed policy outcomes; they are
not process failures. The command exits 0 when all findings receive a completed outcome, 1 when a
finding has an operational processing error, and 2 for invalid invocation or top-level input.

Compose provides the same developer tasks without requiring host Maven or Python tooling:

```sh
docker compose build
docker compose run --rm inventory-api-test
docker compose run --rm report-worker-test
docker compose run --rm report-worker-smoke
docker compose run --rm harness-test
docker compose run --rm harness-evaluate
docker compose up inventory-api
```

The harness container is a one-shot, non-privileged developer task. It receives no Docker socket or
host credentials and does not start or control the other services. Compose stores generated harness
artifacts in the `patch-harness-evidence` named volume, under one container-ID directory per run, so
reruns preserve previous evidence and the non-root container never depends on host-directory
ownership. See [DESIGN.md](DESIGN.md) for
trust boundaries and production considerations, [SUBMISSION.md](SUBMISSION.md) for the exercise
disclosure, and [services/agent-harness/README.md](services/agent-harness/README.md) for the focused
harness reference.
