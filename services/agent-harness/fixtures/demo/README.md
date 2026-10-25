# Three-finding deterministic fixture corpus

This checked-in JSON corpus is the complete offline scenario used by the
supplied CLI demonstration. It contains scanner findings, trusted advisory
claims, immutable proposals, independent change observations, verification
reports, and expected outcomes. Records are data only; the fixture loader
validates and joins them before explicitly injecting one catalog into the
harness adapters.

Run it with:

```sh
poetry -P services/agent-harness run python -m agent_harness \
  --fixture-corpus services/agent-harness/fixtures/demo \
  --output-dir artifacts/harness-demo
```
