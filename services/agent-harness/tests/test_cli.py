from __future__ import annotations

import json
from pathlib import Path

from agent_harness.boundaries import FixtureProvenanceVerifier, load_feed
from fixture_support import fixture_harness


def test_fixture_end_to_end_writes_attestation_and_chain(tmp_path: Path):
    source = Path(__file__).parents[1] / "fixtures" / "safe_pyyaml.json"
    payload, feed = load_feed(source)
    run = fixture_harness(FixtureProvenanceVerifier()).run(payload, feed, tmp_path, run_id="run-test", timestamp="2026-01-01T00:00:00Z")
    assert run.run_status == "completed"
    assert run.findings[0].decision.value == "accept"
    attestation = json.loads((tmp_path / "attestations" / "F-40219.json").read_text())
    assert attestation["primary_reason"] == "ELIGIBLE_FOR_AUTOMATED_PULL_REQUEST"
    events = [json.loads(line) for line in (tmp_path / "ledger.jsonl").read_text().splitlines()]
    assert events[0]["previous_hash"] is None
    assert events[1]["previous_hash"] == events[0]["event_hash"]
    assert events[-1]["previous_hash"] == events[-2]["event_hash"]
    attestation_event = next(event for event in events if event["event_type"] == "attestation_recorded")
    from agent_harness.evidence import attestation_hash
    assert attestation_event["payload"]["attestation_hash"] == attestation_hash(attestation)
