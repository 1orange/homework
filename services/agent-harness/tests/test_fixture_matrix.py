from __future__ import annotations

import json
import shutil
from pathlib import Path

import pytest

from agent_harness.cli import main
from agent_harness.evidence import validate_ledger
from agent_harness.fixture_corpus import FixtureCorpus, build_fixture_harness


MATRIX = Path(__file__).parents[1] / "fixtures" / "matrix"
DEMO = Path(__file__).parents[1] / "fixtures" / "demo"


def _attestations(output: Path) -> dict[str, dict]:
    return {
        path.stem: json.loads(path.read_text(encoding="utf-8"))
        for path in sorted((output / "attestations").glob("*.json"))
    }


def test_aggregate_fixture_matrix_via_public_cli(tmp_path: Path, capsys) -> None:
    output = tmp_path / "matrix"
    # The two intentional processing errors make this a status-1 batch, while
    # every finding still receives an independent result and attestation.
    assert main(["--findings", str(MATRIX), "--output-dir", str(output)]) == 1
    lines = [json.loads(line) for line in capsys.readouterr().out.splitlines()]
    assert [line["finding_id"] for line in lines] == [f"F-{number}" for number in range(40207, 40221)]

    expected = {
        row["finding_id"]: row
        for row in json.loads((MATRIX / "expected.json").read_text(encoding="utf-8"))
    }
    actual = _attestations(output)
    assert set(actual) == set(expected)
    for finding_id, want in expected.items():
        got = actual[finding_id]
        assert got["run_status"] == want["run_status"]
        assert got["decision"] == want["decision"]
        assert got["primary_reason"] == want["primary_reason"]
        assert got["lifecycle_state"] == want["lifecycle_state"]
        assert got["error"] == want.get("error")
        assert [rule["rule"] for rule in got["rules"]] == want.get("rule_order", [])

    events = validate_ledger(output / "ledger.jsonl", expected_run_id="run-fixture-001")
    assert events[-1]["event_type"] == "run_completed"
    assert len(events) >= 2 * len(expected)


def test_reordering_fixture_sources_is_hash_deterministic(tmp_path: Path, capsys) -> None:
    first = tmp_path / "first"
    second = tmp_path / "second"
    shutil.copytree(MATRIX, first)
    shutil.copytree(MATRIX, second)
    for path in second.glob("*.json"):
        value = json.loads(path.read_text(encoding="utf-8"))
        if isinstance(value, list):
            value.reverse()
        elif isinstance(value, dict) and isinstance(value.get("findings"), list):
            value["findings"].reverse()
        path.write_text(json.dumps(value), encoding="utf-8")

    assert main(["--findings", str(first), "--output-dir", str(tmp_path / "out-a")]) == 1
    capsys.readouterr()
    assert main(["--findings", str(second), "--output-dir", str(tmp_path / "out-b")]) == 1
    capsys.readouterr()
    first_attestations = _attestations(tmp_path / "out-a")
    second_attestations = _attestations(tmp_path / "out-b")
    assert first_attestations == second_attestations
    assert (tmp_path / "out-a" / "ledger.jsonl").read_bytes() == (tmp_path / "out-b" / "ledger.jsonl").read_bytes()


def test_fixture_mutation_fails_the_canonical_provenance_boundary(tmp_path: Path) -> None:
    mutated = tmp_path / "mutated"
    shutil.copytree(MATRIX, mutated)
    advisories = json.loads((mutated / "advisories.json").read_text(encoding="utf-8"))
    advisories[-1]["cvss_score"] = 7.6
    (mutated / "advisories.json").write_text(json.dumps(advisories), encoding="utf-8")

    corpus = FixtureCorpus.load(mutated)
    with pytest.raises(ValueError, match="allow-listed"):
        corpus.verifier.verify(corpus.payload)


def test_missing_join_record_is_loaded_for_isolated_processing(tmp_path: Path) -> None:
    incomplete = tmp_path / "incomplete"
    shutil.copytree(MATRIX, incomplete)
    proposals = json.loads((incomplete / "proposals.json").read_text(encoding="utf-8"))
    proposals = [row for row in proposals if row["finding_id"] != "F-40219"]
    (incomplete / "proposals.json").write_text(json.dumps(proposals), encoding="utf-8")

    corpus = FixtureCorpus.load(incomplete)
    assert "F-40219" not in corpus.agent.records


def test_three_finding_demo_uses_one_explicit_catalog_composition(tmp_path: Path) -> None:
    corpus = FixtureCorpus.load(DEMO)
    assert set(corpus.catalog.proposals) == {"F-40218", "F-40219", "F-40220"}
    run = build_fixture_harness(corpus).run(corpus.payload, corpus.feed, tmp_path)
    assert run.run_status == "completed"
    assert [item.decision.value for item in run.findings] == ["review", "accept", "review"]
