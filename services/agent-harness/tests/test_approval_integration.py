from __future__ import annotations

import json
from pathlib import Path

from agent_harness.boundaries import FixtureProvenanceVerifier, load_feed
from agent_harness.evidence import validate_ledger, verify_approval_binding
from fixture_support import fixture_harness


FIXTURE = Path(__file__).parents[1] / "fixtures" / "safe_pyyaml.json"


def test_completed_evaluation_binds_all_decision_facts_and_ledger_anchor(tmp_path: Path) -> None:
    payload, feed = load_feed(FIXTURE)
    run = fixture_harness(FixtureProvenanceVerifier()).run(payload, feed, tmp_path)

    attestation = json.loads((tmp_path / "attestations" / "F-40219.json").read_text())
    assert attestation["evidence_status"] == "bound"
    assert set(attestation["fact_hashes"]) == {
        "finding", "raw_input", "provenance", "advisory", "repository_commit",
        "proposal", "observed_diff", "verification", "policy", "policy_config",
    }
    # ``*_hash`` is the pass-through form accepted by create_approval_binding;
    # rebuilding it proves the persisted commitment is internally consistent.
    facts = {f"{name}_hash": value for name, value in attestation["fact_hashes"].items()}
    assert verify_approval_binding(attestation, facts)

    events = validate_ledger(
        tmp_path / "ledger.jsonl",
        expected_run_id=run.run_id,
        expected_final_hash=run.ledger_final_hash,
        expected_event_count=run.ledger_event_count,
    )
    binding_event = next(event for event in events if event["event_type"] == "approval_binding_recorded")
    assert binding_event["payload"]["binding_hash"] == attestation["binding_hash"]


def test_changing_a_bound_fact_invalidates_the_persisted_binding(tmp_path: Path) -> None:
    payload, feed = load_feed(FIXTURE)
    fixture_harness(FixtureProvenanceVerifier()).run(payload, feed, tmp_path)
    attestation = json.loads((tmp_path / "attestations" / "F-40219.json").read_text())
    facts = {f"{name}_hash": value for name, value in attestation["fact_hashes"].items()}
    changed = dict(facts)
    changed["policy_hash"] = "0" * 64
    assert not verify_approval_binding(attestation, changed)


def test_artifact_hash_is_optional_and_processing_errors_are_unbound(tmp_path: Path) -> None:
    payload, feed = load_feed(FIXTURE)
    fixture_harness(FixtureProvenanceVerifier(), artifact={"digest": "sha256:fixture"}).run(payload, feed, tmp_path / "artifact")
    artifact_attestation = json.loads((tmp_path / "artifact" / "attestations" / "F-40219.json").read_text())
    assert "artifact" in artifact_attestation["fact_hashes"]

    error_output = tmp_path / "error"
    fixture_harness(FixtureProvenanceVerifier()).run({**payload, "generated": "changed"}, feed, error_output)
    error_attestation = json.loads((error_output / "attestations" / "F-40219.json").read_text())
    assert error_attestation["evidence_status"] == "processing_error"
    assert error_attestation["binding_hash"] is None
    assert error_attestation["fact_hashes"] == {}
    assert error_attestation["processing_error"]["error_type"] == "ValueError"
