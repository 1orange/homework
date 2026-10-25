from __future__ import annotations

import json
from datetime import timedelta
from pathlib import Path

import pytest

from agent_harness.lifecycle import (
    AuthorizedGate,
    DeploymentEvidence,
    InsufficientLifecycleEvidence,
    InvalidLifecycleTransition,
    LifecycleEvidence,
    LifecycleState,
    PostDeploymentScan,
    RemediationLifecycle,
    RuntimeReplica,
    SbomEvidence,
    build_pyyaml_fixture_lifecycle,
    pyyaml_fixture_evidence,
)
from agent_harness.models import VerificationGate


STAMP = "2026-01-01T00:00:00Z"
DIGEST = "sha256:" + "a" * 64


def _gates() -> tuple[AuthorizedGate, ...]:
    return tuple(
        AuthorizedGate(id=name, status="passed", authorized=True, observed_at=STAMP)
        for name in ("build", "tests", "security-probe", "dependency-rescan")
    )


def _evidence(**changes) -> LifecycleEvidence:
    value = pyyaml_fixture_evidence().model_dump()
    value.update(changes)
    return LifecycleEvidence.model_validate(value)


def _deployed() -> RemediationLifecycle:
    lifecycle = RemediationLifecycle(
        "F-40219",
        package="PyYAML",
        cve="CVE-2020-14343",
        fixed_commit="fixture-pyyaml-fixed-commit",
        expected_replica_ids=("report-worker-a", "report-worker-b"),
        clock=lambda: STAMP,
        max_evidence_age=timedelta(days=1),
    )
    lifecycle.authorize(_gates())
    lifecycle.merge()
    lifecycle.build("fixture-pyyaml-fixed-commit", DIGEST)
    lifecycle.deploy(
        DeploymentEvidence(
            finding_id="F-40219",
            package="PyYAML",
            cve="CVE-2020-14343",
            deployment_id="deployment-1",
            status="completed",
            artifact_digest=DIGEST,
            observed_at=STAMP,
        )
    )
    return lifecycle


def test_lifecycle_requires_every_ordered_state() -> None:
    lifecycle = RemediationLifecycle(
        "F-40219",
        package="PyYAML",
        cve="CVE-2020-14343",
        fixed_commit="commit-1",
        expected_replica_ids=("report-worker-a", "report-worker-b"),
        clock=lambda: STAMP,
    )
    with pytest.raises(InvalidLifecycleTransition):
        lifecycle.merge()
    lifecycle.authorize(_gates())
    assert lifecycle.state == LifecycleState.authorized
    with pytest.raises(InvalidLifecycleTransition):
        lifecycle.verify_remediated(_evidence())
    lifecycle.merge()
    lifecycle.build("commit-1", DIGEST)
    lifecycle.deploy(DeploymentEvidence(
        finding_id="F-40219", package="PyYAML", cve="CVE-2020-14343",
        deployment_id="d", status="completed", artifact_digest=DIGEST, observed_at=STAMP,
    ))
    assert lifecycle.verify_remediated(_evidence(fixed_commit="commit-1")) == LifecycleState.verified_remediated


@pytest.mark.parametrize(
    "change",
    [
        {"fixed_commit": "other-commit"},
        {"artifact_digest": "sha256:" + "b" * 64},
        {"authorized_gates": (AuthorizedGate(id="tests", status="failed", authorized=True, observed_at=STAMP),)},
        {"sbom": SbomEvidence(artifact_digest=DIGEST, vulnerable_artifact="PyYAML==5.3.1", vulnerable_artifact_present=True, observed_at=STAMP)},
        {"deployment": DeploymentEvidence(deployment_id="d", status="pending", artifact_digest=DIGEST, observed_at=STAMP)},
        {"runtime_replicas": (RuntimeReplica(replica_id="old", artifact_digest="sha256:" + "b" * 64, observed_at=STAMP),)},
        {"post_deployment_scan": PostDeploymentScan(scan_id="scan", status="positive", artifact_digest=DIGEST, observed_at=STAMP)},
        {"vulnerable_rollback": True},
    ],
)
def test_missing_or_conflicting_fact_cannot_be_verified(change) -> None:
    lifecycle = _deployed()
    with pytest.raises(InsufficientLifecycleEvidence):
        lifecycle.verify_remediated(_evidence(**change))
    assert lifecycle.state == LifecycleState.deployed


def test_fixture_reaches_verified_remediated_without_target_changes() -> None:
    lifecycle = build_pyyaml_fixture_lifecycle()
    assert lifecycle.finding_id == "F-40219"
    assert lifecycle.state == LifecycleState.verified_remediated
    assert lifecycle.is_compliant


@pytest.mark.parametrize(
    "change, expected",
    [
        ({"vulnerable_rollback": True}, "vulnerable rollback observed"),
        ({"vulnerable_digests": (DIGEST,)}, "vulnerable digest observed"),
        ({"runtime_replicas": (RuntimeReplica(replica_id="old", artifact_digest="sha256:" + "b" * 64, observed_at=STAMP),)}, "old or divergent"),
        ({"post_deployment_scan": PostDeploymentScan(scan_id="scan-2", status="positive", artifact_digest=DIGEST, observed_at=STAMP)}, "scan is positive"),
    ],
)
def test_regression_appends_event_reopens_and_retains_history(change, expected) -> None:
    lifecycle = build_pyyaml_fixture_lifecycle()
    before = lifecycle.events
    old_final_hash = before[-1].event_hash
    lifecycle.reconcile(_evidence(**change))

    assert lifecycle.state == LifecycleState.proposed
    assert not lifecycle.is_compliant
    assert lifecycle.reopened
    assert len(lifecycle.events) == len(before) + 1
    assert lifecycle.events[:-1] == before
    regression = lifecycle.events[-1]
    assert regression.event_type == "remediation_regressed"
    assert regression.previous_hash == old_final_hash
    assert expected in (regression.reason or "")
    assert regression.event_hash != old_final_hash


def test_stale_evidence_fails_closed() -> None:
    lifecycle = _deployed()
    stale = _evidence(observed_at="2025-01-01T00:00:00Z")
    with pytest.raises(InsufficientLifecycleEvidence):
        lifecycle.verify_remediated(stale)


def test_proposal_verification_gate_cannot_be_promoted_to_authorization() -> None:
    lifecycle = RemediationLifecycle("F-40219", clock=lambda: STAMP)
    proposal_gate = VerificationGate(id="tests", status="passed")
    with pytest.raises(InsufficientLifecycleEvidence):
        lifecycle.authorize((proposal_gate,))


def test_authorization_requires_exact_independent_gate_set() -> None:
    lifecycle = RemediationLifecycle("F-40219", clock=lambda: STAMP)
    with pytest.raises(InsufficientLifecycleEvidence):
        lifecycle.authorize(_gates()[:2])
    with pytest.raises(InsufficientLifecycleEvidence):
        lifecycle.authorize(tuple(gate for gate in _gates() if gate.id != "build"))
    with pytest.raises(InsufficientLifecycleEvidence):
        lifecycle.authorize((*_gates(), AuthorizedGate(id="other", status="passed", authorized=True, observed_at=STAMP)))


def test_build_transition_does_not_substitute_for_independent_build_gate() -> None:
    lifecycle = RemediationLifecycle(
        "F-40219",
        package="PyYAML",
        cve="CVE-2020-14343",
        fixed_commit="commit-1",
        expected_replica_ids=("report-worker-a", "report-worker-b"),
        clock=lambda: STAMP,
    )
    with pytest.raises(InsufficientLifecycleEvidence):
        lifecycle.authorize(
            tuple(gate for gate in _gates() if gate.id != "build")
        )


def test_failed_independent_build_gate_cannot_be_verified() -> None:
    lifecycle = RemediationLifecycle("F-40219", clock=lambda: STAMP)
    failed_build = tuple(
        AuthorizedGate(
            id=gate.id,
            status="failed" if gate.id == "build" else gate.status,
            authorized=gate.authorized,
            observed_at=gate.observed_at,
        )
        for gate in _gates()
    )
    with pytest.raises(InsufficientLifecycleEvidence):
        lifecycle.authorize(failed_build)


def test_verified_remediated_requires_independent_build_gate() -> None:
    lifecycle = _deployed()
    without_build = tuple(gate for gate in _gates() if gate.id != "build")
    with pytest.raises(InsufficientLifecycleEvidence):
        lifecycle.verify_remediated(_evidence(authorized_gates=without_build))


def test_each_production_fact_is_bound_to_finding_package_and_cve() -> None:
    lifecycle = _deployed()
    unbound_scan = PostDeploymentScan(
        scan_id="scan-unbound", status="clean", artifact_digest=DIGEST, observed_at=STAMP
    )
    with pytest.raises(InsufficientLifecycleEvidence):
        lifecycle.verify_remediated(_evidence(post_deployment_scan=unbound_scan))


@pytest.mark.parametrize(
    "change",
    [
        {"post_deployment_scan": None},
        {"post_deployment_scan": PostDeploymentScan(
            finding_id="F-40219", package="PyYAML", cve="CVE-2020-14343",
            scan_id="corrupt", status="corrupt", artifact_digest=DIGEST, observed_at=STAMP,
        )},
        {"runtime_replicas": (RuntimeReplica(
            finding_id="F-40219", package="PyYAML", cve="CVE-2020-14343",
            replica_id="report-worker-a", artifact_digest=DIGEST, healthy=False, observed_at=STAMP,
        ),)},
        {"runtime_replicas": (RuntimeReplica(
            finding_id="F-40219", package="PyYAML", cve="CVE-2020-14343",
            replica_id="report-worker-a", artifact_digest=DIGEST, observed_at=STAMP,
        ),)},
        {"observed_at": "2025-01-01T00:00:00Z"},
    ],
)
def test_reconciliation_reopens_on_incomplete_or_untrustworthy_current_snapshot(change) -> None:
    lifecycle = build_pyyaml_fixture_lifecycle()
    before = len(lifecycle.events)
    lifecycle.reconcile(_evidence(**change))
    assert lifecycle.state == LifecycleState.proposed
    assert lifecycle.reopened
    assert len(lifecycle.events) == before + 1


def test_reconciliation_reopens_on_malformed_adapter_payload() -> None:
    lifecycle = build_pyyaml_fixture_lifecycle()
    before = len(lifecycle.events)
    lifecycle.reconcile("not-an-evidence-mapping")
    assert lifecycle.state == LifecycleState.proposed
    assert len(lifecycle.events) == before + 1


def test_fixture_is_explicitly_labeled_and_deterministic() -> None:
    path = Path(__file__).parents[1] / "fixtures" / "remediation_pyyaml_lifecycle.json"
    payload = json.loads(path.read_text(encoding="utf-8"))
    assert payload["fixture_label"] == "SIMULATED_HARNESS_EVIDENCE_ONLY"
    assert "does not attest" in payload["fixture_disclaimer"]
