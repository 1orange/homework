from __future__ import annotations

import socket

from agent_harness.agent import DeterministicProposalAgent
from agent_harness.models import Advisory, Finding, ProposalContext, Provenance
from fixture_support import FixtureCorpus, DEMO


def test_function_model_path_is_local_and_does_not_use_provider(monkeypatch) -> None:
    def no_network(*args, **kwargs):
        raise AssertionError("FunctionModel attempted a provider/network call")

    monkeypatch.setattr(socket.socket, "connect", no_network)
    finding = Finding(
        id="F-40219", cve="CVE-2020-14343", severity="high",
        service="report-worker", package="PyYAML", installed_version="5.3.1",
        path="direct", fixed_version="5.4", sla_days_remaining=1,
    )
    provenance = Provenance(source="fixture://test", digest="a" * 64, verified=True)
    advisory = Advisory(
        cve=finding.cve, ecosystem="pypi", package=finding.package, affected=True,
        fixed_versions=("5.4",), provenance=provenance,
    )
    context = ProposalContext(
        finding=finding, advisory=advisory, provenance=provenance,
        allowed_transformations=("python-direct-dependency-update",),
        allowed_verifications=("build", "tests", "security-probe", "dependency-rescan"),
    )

    catalog = FixtureCorpus.load(DEMO)
    agent = DeterministicProposalAgent(catalog.catalog.proposals)
    proposal = agent.propose(context)

    assert agent._function_model is not None
    assert agent._agent is not None
    assert proposal.finding_id == finding.id
    assert proposal.verification_ids == ("build", "tests", "security-probe", "dependency-rescan")
