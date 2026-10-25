from __future__ import annotations

import pytest
from pydantic import ValidationError

from agent_harness.models import Finding, Proposal


def finding(**overrides):
    value = {
        "id": "F-test", "cve": "CVE-1", "severity": "high", "service": "worker",
        "package": "PyYAML", "installed_version": "5.3.1", "path": "direct",
        "fixed_version": "5.4", "sla_days_remaining": 1, "notes": "fixture",
    }
    value.update(overrides)
    return value


def test_boundary_models_reject_unknown_fields():
    with pytest.raises(ValidationError):
        Finding.model_validate({**finding(), "unexpected": "input"})


def test_proposal_is_immutable_and_declarative():
    proposal = Proposal(
        finding_id="F-test", service="worker", package="PyYAML", ecosystem="pypi",
        installed_version="5.3.1", target_version="5.4",
        transformation_id="python-direct-dependency-update",
        verification_ids=("tests",), rationale="fixture",
    )
    with pytest.raises(ValidationError):
        proposal.target_version = "9.9"
    assert "command" not in proposal.model_dump()
