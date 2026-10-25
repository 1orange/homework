from __future__ import annotations

import json
from datetime import datetime, timezone
from pathlib import Path

import pytest

from agent_harness.advisories import FixtureAdvisoryAdapter
from agent_harness.boundaries import FixtureProvenanceVerifier, load_feed
from agent_harness.models import (
    ChangeObservation,
    Finding,
    FindingFeed,
    Proposal,
    VerificationGate,
    VerificationReport,
)
from fixture_support import fixture_advisory_adapter, fixture_harness
from agent_harness.policy_config import load_default_policy
from agent_harness.policy import evaluate as evaluate_policy


def evaluate(finding, advisory, proposal, changes, report):
    return evaluate_policy(
        finding, advisory, proposal, changes, report,
        evaluated_at=datetime(2026, 1, 1, tzinfo=timezone.utc), policy=load_default_policy(),
    )


FIXTURE = Path(__file__).parents[1] / "fixtures" / "safe_pyyaml.json"


class UnverifiedVerifier:
    def verify(self, payload):
        return {"source": "test", "digest": "a" * 64, "verified": False}


class RecordingRunner:
    def __init__(self):
        self.called = False

    def verify(self, finding, proposal, changes):
        self.called = True
        return VerificationReport(gates=tuple(
            VerificationGate(id=item, status="passed") for item in proposal.verification_ids
        ))


class UnknownVerificationAgent:
    def propose(self, context):
        return Proposal(
            finding_id=context.finding.id,
            service=context.finding.service,
            package=context.finding.package,
            ecosystem="pypi",
            installed_version=context.finding.installed_version,
            target_version="5.4",
            transformation_id="python-direct-dependency-update",
            verification_ids=("tests", "unknown-gate"),
            intended_paths=("services/report-worker/requirements.lock",),
            rationale="fixture",
        )


def test_unverified_provenance_is_processing_error(tmp_path: Path):
    payload, feed = load_feed(FIXTURE)
    run = fixture_harness(UnverifiedVerifier()).run(payload, feed, tmp_path)
    assert run.run_status == "error"
    assert run.findings[0].run_status == "error"
    assert run.findings[0].decision is None


def test_payload_and_processed_feed_are_bound(tmp_path: Path):
    payload, feed = load_feed(FIXTURE)
    other = json.loads(json.dumps(payload))
    other["findings"][0]["id"] = "F-swapped"
    run = fixture_harness(FixtureProvenanceVerifier()).run(other, feed, tmp_path)
    assert run.findings[0].run_status == "error"
    assert run.findings[0].error == "ValueError"


def test_unknown_verification_is_policy_reject_without_execution(tmp_path: Path):
    payload, feed = load_feed(FIXTURE)
    runner = RecordingRunner()
    run = fixture_harness(
        FixtureProvenanceVerifier(),
        agent=UnknownVerificationAgent(),
        verification_runner=runner,
    ).run(payload, feed, tmp_path)
    result = run.findings[0]
    assert result.run_status == "completed"
    assert result.decision.value == "reject"
    assert result.primary_reason == "UNKNOWN_VERIFICATION"
    assert runner.called is False


def test_finding_id_grammar_blocks_attestation_path_traversal():
    with pytest.raises(ValueError):
        Finding(
            id="../../outside",
            cve="CVE-1",
            severity="high",
            service="worker",
            package="PyYAML",
            installed_version="5.3.1",
            path="direct",
            sla_days_remaining=1,
        )


def test_duplicate_verification_ids_reject():
    finding = Finding(
        id="F-test", cve="CVE-2020-14343", severity="high", service="worker",
        package="PyYAML", installed_version="5.3.1", path="direct", fixed_version="5.4",
        sla_days_remaining=1,
    )
    advisory = fixture_advisory_adapter().enrich(finding.cve, finding.package, "pypi")
    proposal = Proposal(
        finding_id=finding.id, service=finding.service, package=finding.package, ecosystem="pypi",
        installed_version="5.3.1", target_version="5.4",
        transformation_id="python-direct-dependency-update",
        verification_ids=("tests", "tests", "security-probe", "dependency-rescan"),
        intended_paths=("requirements.lock",), rationale="fixture",
    )
    changes = ChangeObservation(
        files=("requirements.lock",), content_hashes={"requirements.lock": "a" * 64}, dependency_only=True,
    )
    report = VerificationReport(gates=tuple(
        VerificationGate(id=item, status="passed") for item in proposal.verification_ids
    ))
    result = evaluate(finding, advisory, proposal, changes, report)
    assert result.decision.value == "reject"
    assert result.primary_reason == "DUPLICATE_VERIFICATION"


def test_python_versions_use_packaging_and_unsupported_versions_review():
    finding = Finding(
        id="F-test", cve="CVE-2020-14343", severity="high", service="worker",
        package="PyYAML", installed_version="5.4rc1", path="direct", fixed_version="5.4",
        sla_days_remaining=1,
    )
    advisory = fixture_advisory_adapter().enrich(finding.cve, finding.package, "pypi")
    proposal = Proposal(
        finding_id=finding.id, service=finding.service, package=finding.package, ecosystem="pypi",
        installed_version="5.4rc1", target_version="5.4",
        transformation_id="python-direct-dependency-update",
        verification_ids=("build", "tests", "security-probe", "dependency-rescan"),
        intended_paths=("services/worker/requirements.lock",), rationale="fixture",
    )
    changes = ChangeObservation(
        files=("services/worker/requirements.lock",),
        content_hashes={"services/worker/requirements.lock": "a" * 64},
        dependency_only=True,
    )
    report = VerificationReport(gates=tuple(
        VerificationGate(id=item, status="passed") for item in proposal.verification_ids
    ))
    result = evaluate(finding, advisory, proposal, changes, report)
    assert result.decision.value == "accept"

    finding_bad = finding.model_copy(update={"installed_version": "not-a-version"})
    proposal_bad = proposal.model_copy(update={"installed_version": "not-a-version"})
    result_bad = evaluate(finding_bad, advisory, proposal_bad, changes, report)
    assert result_bad.decision.value == "review"
    assert result_bad.primary_reason == "UNSUPPORTED_VERSION"


def test_advisory_claims_and_priority_are_propagated(tmp_path: Path):
    payload, feed = load_feed(FIXTURE)
    run = fixture_harness(FixtureProvenanceVerifier()).run(payload, feed, tmp_path)
    assert run.findings[0].priority == "urgent"
    events = [json.loads(line) for line in (tmp_path / "ledger.jsonl").read_text().splitlines()]
    advisory_event = next(item for item in events if item["event_type"] == "advisory_enriched")
    assert advisory_event["payload"]["advisory_claims"][0]["issuer"] == "fixture://trusted-advisory"
    assert advisory_event["payload"]["advisory_claims"][0]["claim_text"]
