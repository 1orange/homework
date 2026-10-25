from __future__ import annotations

from datetime import datetime, timedelta, timezone

import pytest

from agent_harness.advisories import FixtureAdvisoryAdapter
from agent_harness.agent import DeterministicProposalAgent
from fixture_support import fixture_advisory_adapter, FixtureCorpus, DEMO
from agent_harness.policy_config import load_default_policy
from agent_harness.models import (
    Advisory, ChangeObservation, Finding, NonReachabilityException,
    Proposal, ProposalContext,
    VerificationGate, VerificationReport,
)
from agent_harness.policy import evaluate as evaluate_policy


EVALUATED_AT = datetime(2026, 1, 1, tzinfo=timezone.utc)


def evaluate(finding, advisory, proposal, changes, report):
    return evaluate_policy(
        finding, advisory, proposal, changes, report,
        evaluated_at=EVALUATED_AT, policy=load_default_policy(),
    )


def test_safe_pyyaml_is_accepted_only_as_pull_request_eligibility():
    finding = Finding(
        id="F-40219", cve="CVE-2020-14343", severity="high", service="report-worker",
        package="PyYAML", installed_version="5.3.1", path="direct", fixed_version="5.4",
        sla_days_remaining=11, notes="fixture",
    )
    ecosystem = "pypi" if finding.package == "PyYAML" else "maven"
    advisory = fixture_advisory_adapter().enrich(finding.cve, finding.package, ecosystem)
    context = ProposalContext(
        finding=finding, advisory=advisory,
        provenance={"source": "fixture", "digest": "0" * 64, "verified": True},
        allowed_transformations=("python-direct-dependency-update",),
        allowed_verifications=("tests", "security-probe", "dependency-rescan", "build"),
    )
    proposal = DeterministicProposalAgent(FixtureCorpus.load(DEMO).catalog.proposals).propose(context)
    changes = ChangeObservation(files=proposal.intended_paths, content_hashes={proposal.intended_paths[0]: "a" * 64}, dependency_only=True)
    report = VerificationReport(gates=tuple(VerificationGate(id=gate, status="passed") for gate in proposal.verification_ids))
    result = evaluate(finding, advisory, proposal, changes, report)
    assert result.decision.value == "accept"
    assert result.primary_reason == "ELIGIBLE_FOR_AUTOMATED_PULL_REQUEST"
    assert [rule.rule for rule in result.rules] == ["exact_identity", "advisory_consistency", "trusted_unaffected_target", "allowed_transformation", "bounded_dependency_diff", "verification_gates"]


def _inputs(*, finding_overrides=None, proposal_overrides=None, change_overrides=None, gates=None):
    finding_data = dict(
        id="F-test", cve="CVE-2020-14343", severity="high", service="worker",
        package="PyYAML", installed_version="5.3.1", path="direct", fixed_version="5.4",
        sla_days_remaining=1,
    )
    finding_data.update(finding_overrides or {})
    finding = Finding(**finding_data)
    ecosystem = "pypi" if finding.package == "PyYAML" else "maven"
    advisory = fixture_advisory_adapter().enrich(finding.cve, finding.package, ecosystem)
    proposal_data = dict(
        finding_id=finding.id, service=finding.service, package=finding.package,
        ecosystem="pypi", installed_version=finding.installed_version, target_version="5.4",
        transformation_id="python-direct-dependency-update",
        verification_ids=("tests", "security-probe", "dependency-rescan", "build"),
        intended_paths=(f"services/{finding.service}/requirements.lock",), rationale="fixture",
    )
    proposal_data.update(proposal_overrides or {})
    proposal = Proposal(**proposal_data)
    changes_data = dict(
        files=proposal.intended_paths,
        content_hashes={path: "a" * 64 for path in proposal.intended_paths},
        dependency_only=True,
    )
    changes_data.update(change_overrides or {})
    changes = ChangeObservation(**changes_data)
    report = VerificationReport(gates=tuple(
        VerificationGate(id=gate, status="passed") for gate in (gates or proposal.verification_ids)
    ))
    return finding, advisory, proposal, changes, report


def test_supplied_ambiguous_cases_route_to_review_with_stable_reasons():
    finding, advisory, proposal, changes, report = _inputs(
        finding_overrides={
            "id": "F-40218", "cve": "CVE-2022-1471", "service": "inventory-api",
            "package": "org.yaml:snakeyaml", "installed_version": "1.30",
            "path": "transitive via org.springframework.boot:spring-boot-starter", "fixed_version": "2.0",
        },
        proposal_overrides={
            "finding_id": "F-40218", "service": "inventory-api", "package": "org.yaml:snakeyaml",
            "ecosystem": "maven", "installed_version": "1.30", "target_version": "2.0",
            "transformation_id": "maven-transitive-override",
            "intended_paths": ("services/inventory-api/pom.xml",),
        },
    change_overrides={"files": ("services/inventory-api/pom.xml",), "content_hashes": {"services/inventory-api/pom.xml": "a" * 64}},
    )
    advisory = fixture_advisory_adapter().enrich(finding.cve, finding.package, "maven")
    result = evaluate(finding, advisory, proposal, changes, report)
    assert result.decision.value == "review"
    assert result.primary_reason == "TRANSITIVE_OVERRIDE"


def test_unknown_operation_and_independent_unsafe_diff_are_rejected():
    finding, advisory, proposal, changes, report = _inputs(
        proposal_overrides={"transformation_id": "invented-shell-command"},
        change_overrides={
            "files": ("services/worker/requirements.lock", "services/worker/secrets.txt"),
            "content_hashes": {"services/worker/requirements.lock": "a" * 64, "services/worker/secrets.txt": "b" * 64},
        },
    )
    result = evaluate(finding, advisory, proposal, changes, report)
    assert result.decision.value == "reject"
    assert result.primary_reason == "UNKNOWN_TRANSFORMATION"


def test_registered_safe_yaml_source_transform_can_be_accepted():
    path = "services/inventory-api/src/main/java/com/example/inventory/ConfigLoader.java"
    finding = Finding(
        id="F-yaml", cve="CVE-2022-1471", severity="critical", service="inventory-api",
        package="org.yaml:snakeyaml", installed_version="1.30", path="transitive",
        fixed_version="2.0", sla_days_remaining=1,
    )
    advisory = fixture_advisory_adapter().enrich(finding.cve, finding.package, "maven")
    proposal = Proposal(
        finding_id=finding.id, service=finding.service, package=finding.package, ecosystem="maven",
        installed_version="1.30", target_version="2.0", transformation_id="safe-yaml-source-transform",
        verification_ids=("tests", "security-probe", "dependency-rescan", "build"), intended_paths=(path,), rationale="fixture",
    )
    changes = ChangeObservation(files=(path,), content_hashes={path: "a" * 64}, dependency_only=False)
    report = VerificationReport(gates=tuple(VerificationGate(id=gate, status="passed") for gate in proposal.verification_ids))
    result = evaluate(finding, advisory, proposal, changes, report)
    assert result.decision.value == "accept"
    assert result.primary_reason == "ELIGIBLE_FOR_AUTOMATED_PULL_REQUEST"


def test_advisory_conflict_compares_every_fixed_version_and_affected_status():
    finding, advisory, proposal, changes, report = _inputs()
    claim = advisory.source_claims[0].model_copy(update={
        "affected": False,
        "fixed_versions": ("5.4", "5.5"),
    })
    conflicting = advisory.model_copy(update={"source_claims": (claim,)})
    result = evaluate(finding, conflicting, proposal, changes, report)
    assert result.decision.value == "review"
    assert result.primary_reason == "ADVISORY_CONFLICT"


def test_advisory_conflict_compares_affected_ranges_across_sources():
    finding, advisory, proposal, changes, report = _inputs()
    first = advisory.source_claims[0]
    second = first.model_copy(update={"source": "fixture://second", "affected_ranges": ("< 5.3",)})
    conflicting = advisory.model_copy(update={"source_claims": (first, second)})
    result = evaluate(finding, conflicting, proposal, changes, report)
    assert result.decision.value == "review"
    assert result.primary_reason == "ADVISORY_CONFLICT"


@pytest.mark.parametrize("path", [
    "services/other-service/requirements.lock",
    "C:/workspace/services/worker/requirements.lock",
    "services/worker/../other/requirements.lock",
])
def test_dependency_manifest_cannot_escape_proposal_service(path):
    finding, advisory, proposal, changes, report = _inputs(
        change_overrides={"files": (path,), "content_hashes": {path: "a" * 64}},
    )
    result = evaluate(finding, advisory, proposal, changes, report)
    assert result.decision.value == "reject"
    assert result.primary_reason == "UNSAFE_DIFF"


def test_bounded_source_and_test_additions_route_to_review():
    finding, advisory, proposal, _, report = _inputs(
        proposal_overrides={
            "transformation_id": "source-migration",
            "intended_paths": ("services/worker/src/main.py",),
        },
    )
    source_changes = ChangeObservation(
        files=proposal.intended_paths,
        content_hashes={proposal.intended_paths[0]: "a" * 64},
        dependency_only=False,
    )
    source_result = evaluate(finding, advisory, proposal, source_changes, report)
    assert source_result.decision.value == "review"
    assert source_result.primary_reason == "UNAPPROVED_SOURCE_MIGRATION"

    test_path = "services/worker/tests/test_dependency.py"
    test_proposal = proposal.model_copy(update={
        "transformation_id": "python-direct-dependency-update",
        "intended_paths": ("services/worker/requirements.lock", test_path),
    })
    test_changes = ChangeObservation(
        files=test_proposal.intended_paths,
        content_hashes={path: "a" * 64 for path in test_proposal.intended_paths},
        dependency_only=False,
    )
    test_result = evaluate(finding, advisory, test_proposal, test_changes, report)
    assert test_result.decision.value == "review"
    assert test_result.primary_reason == "TEST_CHANGE_REQUIRES_REVIEW"


def test_non_reachability_exception_requires_typed_future_expiry_and_metadata():
    finding, advisory, proposal, changes, report = _inputs(
        proposal_overrides={
            "non_reachability_exception": {
                "approved_by": "security-reviewer",
                "expires_at": (EVALUATED_AT + timedelta(days=1)).isoformat(),
                "tool_identity": "reachability-checker",
                "repository_commit": "abc123",
                "coverage_context": "runtime graph",
            },
        },
    )
    assert isinstance(proposal.non_reachability_exception.expires_at, datetime)
    result = evaluate(finding, advisory, proposal, changes, report)
    assert result.decision.value == "review"
    assert result.primary_reason == "NON_REACHABILITY_EXCEPTION"

    expired = proposal.model_copy(update={
        "non_reachability_exception": proposal.non_reachability_exception.model_copy(
            update={"expires_at": EVALUATED_AT - timedelta(seconds=1)}
        ),
    })
    expired_result = evaluate(finding, advisory, expired, changes, report)
    assert expired_result.decision.value == "reject"
    assert expired_result.primary_reason == "INVALID_NON_REACHABILITY_EXCEPTION"

    with pytest.raises(ValueError):
        NonReachabilityException(
            approved_by="security-reviewer",
            expires_at="not-a-timestamp",
            tool_identity="reachability-checker",
            repository_commit="abc123",
            coverage_context="runtime graph",
        )
