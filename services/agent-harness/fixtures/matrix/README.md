# Deterministic aggregate fixture matrix

This directory is an offline harness corpus, not a scan of this checkout. The
scanner envelope and each decision input are intentionally separate:

* `findings.json` — scanner findings, joined by `finding_id`;
* `advisories.json` — normalized advisory claims, joined by CVE/package/ecosystem;
* `proposals.json` — one immutable declarative proposal per finding;
* `changes.json` — independently observed file changes and hashes;
* `verification.json` — independent verification-gate results (build, tests,
  security probe, and dependency rescan); and
* `expected.json` — disposition, primary reason, lifecycle state, and rule order.

The complete six-file corpus is normalized by finding/advisory identity and
authenticated against the verifier's canonical allow-listed digest. Reordering
records is therefore deterministic, while changing any record fails the
provenance boundary and is reported as an isolated processing error for each
finding. The Commons Collections conflict also carries a structured trusted
source claim, so scanner and advisory identities remain auditable separately.

The corpus has fourteen cases. `F-40219`, `F-40217`, `F-40218`, and `F-40220`
are the safe/source-transform/SnakeYAML/Commons Collections examples from the
exercise matrix. The two processing errors are intentional and demonstrate
that later findings still run and receive attestations. Run it with:

```sh
poetry -P services/agent-harness run python -m agent_harness \
  --findings services/agent-harness/fixtures/matrix \
  --output-dir artifacts/harness-matrix
```

The command is offline and uses no model provider, network, scanner,
source-control, deployment, runtime, or container-control integration.
