from __future__ import annotations

from pathlib import Path

from agent_harness.fixture_corpus import FixtureCorpus, build_fixture_harness
from agent_harness.advisories import FixtureAdvisoryAdapter
from agent_harness.policy_config import load_default_policy


DEMO = Path(__file__).parents[1] / "fixtures" / "demo"


def fixture_harness(verifier, **overrides):
    """Compose test harness dependencies from the checked-in demo catalog."""
    return build_fixture_harness(
        FixtureCorpus.load(DEMO),
        verifier=verifier,
        policy=load_default_policy(),
        **overrides,
    )


def fixture_advisory_adapter():
    corpus = FixtureCorpus.load(DEMO)
    return FixtureAdvisoryAdapter(corpus.catalog.advisories)
