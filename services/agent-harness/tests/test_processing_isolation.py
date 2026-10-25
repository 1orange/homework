from __future__ import annotations

import json
from pathlib import Path

from agent_harness.boundaries import load_feed, sha256_json
from agent_harness.cli import main
from agent_harness.models import (
    Finding,
    FindingFeed,
    Provenance,
    VerificationGate,
    VerificationReport,
)
from fixture_support import fixture_harness


class StaticVerifier:
    def verify(self, payload: dict) -> Provenance:
        return Provenance(
            source="fixture://test", digest="a" * 64, verified=True, claims=("test",)
        )


class RawPayloadVerifier:
    """Test verifier that binds provenance to the complete raw envelope."""

    def verify(self, payload: dict) -> Provenance:
        return Provenance(
            source="fixture://raw-bound-test",
            digest=sha256_json(payload),
            verified=True,
            claims=("test", "raw-payload-bound"),
        )


class StatusRunner:
    def __init__(self, statuses: dict[str, str]) -> None:
        self.statuses = statuses

    def verify(self, finding, proposal, changes) -> VerificationReport:
        status = self.statuses.get(finding.id, "passed")
        return VerificationReport(
            gates=tuple(
                VerificationGate(id=gate, status=status)
                for gate in proposal.verification_ids
            )
        )


def _finding(**overrides) -> Finding:
    value = {
        "id": "F-40219",
        "cve": "CVE-2020-14343",
        "severity": "high",
        "service": "report-worker",
        "package": "PyYAML",
        "ecosystem": "pypi",
        "installed_version": "5.3.1",
        "path": "direct",
        "fixed_version": "5.4",
        "sla_days_remaining": 11,
        "notes": "test",
    }
    value.update(overrides)
    return Finding.model_validate(value)


def test_processing_error_isolated_and_ids_are_sorted(tmp_path: Path):
    safe = _finding(id="F-40219")
    unknown = _finding(
        id="F-99999",
        cve="CVE-unknown",
        package="missing-package",
        service="missing-service",
    )
    feed = FindingFeed(generated="2026-01-01T00:00:00Z", scanner="test", findings=[unknown, safe])

    run = fixture_harness(StaticVerifier()).run({"test": True}, feed, tmp_path)

    assert [item.finding_id for item in run.findings] == ["F-40219", "F-99999"]
    assert run.findings[0].run_status == "completed"
    assert run.findings[0].decision is not None
    assert run.findings[1].run_status == "error"
    assert run.findings[1].decision is None
    assert run.findings[1].error
    assert (tmp_path / "attestations" / "F-40219.json").exists()
    assert (tmp_path / "attestations" / "F-99999.json").exists()


def test_completed_verification_failure_is_policy_reject(tmp_path: Path):
    finding = _finding()
    feed = FindingFeed(generated="2026-01-01T00:00:00Z", scanner="test", findings=[finding])
    run = fixture_harness(
        StaticVerifier(),
        verification_runner=StatusRunner({finding.id: "failed"}),
    ).run({"test": True}, feed, tmp_path)

    assert run.run_status == "completed"
    assert run.findings[0].run_status == "completed"
    assert run.findings[0].decision.value == "reject"


def test_unavailable_verification_is_error_but_later_finding_runs(tmp_path: Path):
    first = _finding(id="F-40219")
    second = _finding(
        id="F-40220",
        cve="CVE-2015-6420",
        service="inventory-api",
            package="commons-collections:commons-collections",
            ecosystem="maven",
        installed_version="3.2.1",
        fixed_version=None,
    )
    feed = FindingFeed(generated="2026-01-01T00:00:00Z", scanner="test", findings=[second, first])
    run = fixture_harness(
        StaticVerifier(),
        verification_runner=StatusRunner({first.id: "unavailable"}),
    ).run({"test": True}, feed, tmp_path)

    assert run.run_status == "error"
    assert run.findings[0].decision is None
    assert run.findings[0].run_status == "error"
    assert run.findings[1].run_status == "completed"
    assert run.findings[1].decision.value == "review"


def test_malformed_raw_finding_isolated_and_bound_without_echoing_input(tmp_path: Path):
    payload = {
        "generated": "2026-01-01T00:00:00Z",
        "scanner": "test",
        # Deliberately put the valid records around the malformed item so both
        # stable ordering and continuation after an item-level failure are
        # exercised.
        "findings": [
            {
                "id": "F-40220",
                "cve": "CVE-2015-6420",
                "severity": "high",
                "service": "inventory-api",
                "package": "commons-collections:commons-collections",
                "ecosystem": "maven",
                "installed_version": "3.2.1",
                "path": "direct",
                "fixed_version": None,
                "sla_days_remaining": 12,
                "notes": "valid fixture",
            },
            {
                "id": "F-secret-id",
                "cve": "CVE-should-not-be-echoed",
                "severity": "high",
                "service": "worker",
                "package": "PyYAML",
                "ecosystem": "pypi",
                "installed_version": "5.3.1",
                "path": "direct",
                "sla_days_remaining": "not-an-integer",
                "token": "secret-value-must-not-escape",
            },
            {
                "id": "F-40219",
                "cve": "CVE-2020-14343",
                "severity": "high",
                "service": "report-worker",
                "package": "PyYAML",
                "ecosystem": "pypi",
                "installed_version": "5.3.1",
                "path": "direct",
                "fixed_version": "5.4",
                "sla_days_remaining": 11,
                "notes": "valid fixture",
            },
        ],
    }
    source = tmp_path / "mixed.json"
    source.write_text(json.dumps(payload), encoding="utf-8")
    verified_payload, feed = load_feed(source)

    run = fixture_harness(RawPayloadVerifier()).run(verified_payload, feed, tmp_path / "out")

    assert [item.finding_id for item in run.findings] == [
        "F-40219", "F-40220", run.findings[2].finding_id,
    ]
    malformed = run.findings[2]
    assert malformed.finding_id.startswith("invalid-finding-000001-")
    assert malformed.run_status == "error"
    assert malformed.decision is None
    assert run.findings[0].run_status == "completed"
    assert run.findings[1].run_status == "completed"

    invalid_attestation = json.loads(
        (tmp_path / "out" / "attestations" / f"{malformed.finding_id}.json").read_text()
    )
    assert invalid_attestation["input_hash"] == sha256_json(payload["findings"][1])
    rendered = (tmp_path / "out").joinpath("ledger.jsonl").read_text() + json.dumps(invalid_attestation)
    assert "secret-value-must-not-escape" not in rendered
    assert "CVE-should-not-be-echoed" not in rendered


def test_cli_exit_statuses(tmp_path: Path, capsys):
    source = Path(__file__).parents[1] / "fixtures" / "safe_pyyaml.json"
    valid_output = tmp_path / "valid"
    assert main([
        "--findings", str(source), "--output-dir", str(valid_output)
    ]) == 0
    assert json.loads(capsys.readouterr().out)["run_status"] == "completed"

    processing_error_feed = tmp_path / "processing-error.json"
    payload = json.loads(source.read_text(encoding="utf-8"))
    payload["generated"] = "2026-01-02T00:00:00Z"
    processing_error_feed.write_text(json.dumps(payload), encoding="utf-8")
    processing_output = tmp_path / "processing-error"
    assert main([
        "--findings", str(processing_error_feed), "--output-dir", str(processing_output)
    ]) == 1
    assert json.loads(capsys.readouterr().out)["run_status"] == "error"

    malformed = tmp_path / "malformed.json"
    malformed.write_text('{"findings": []}', encoding="utf-8")
    assert main([
        "--findings", str(malformed), "--output-dir", str(tmp_path / "bad")
    ]) == 2
    assert main([]) == 2
