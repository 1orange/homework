from __future__ import annotations

import json
from pathlib import Path

import pytest

from agent_harness.boundaries import sha256_json
from agent_harness.evidence import create_approval_binding, verify_approval_binding
from agent_harness.policy_config import PolicyConfig, load_default_policy, load_policy


def test_default_policy_is_strict_immutable_and_digest_is_canonical() -> None:
    policy = load_default_policy()
    assert isinstance(policy, PolicyConfig)
    assert len(policy.digest) == 64
    with pytest.raises((TypeError, ValueError)):
        policy.registered_transformations = ()  # type: ignore[misc]
    assert policy.digest == load_default_policy().digest


def test_policy_change_changes_digest_and_invalidates_old_binding(tmp_path: Path) -> None:
    source = Path(__file__).parents[1] / "policies" / "default.json"
    value = json.loads(source.read_text(encoding="utf-8"))
    first = load_policy(source)
    value["required_verification_gates"] = ["build", "tests", "security-probe"]
    changed_path = tmp_path / "policy.json"
    changed_path.write_text(json.dumps(value), encoding="utf-8")
    changed = load_policy(changed_path)
    assert changed.digest != first.digest

    # The policy result itself is unchanged; changing only configuration still
    # invalidates the complete approval commitment.
    result_hash = sha256_json({"decision": "accept", "primary_reason": "fixture"})
    facts = {"policy_hash": result_hash, "policy_config_hash": first.digest}
    binding = create_approval_binding(facts)
    assert verify_approval_binding(binding, facts)
    assert not verify_approval_binding(
        binding, {**facts, "policy_config_hash": changed.digest}
    )


def test_policy_digest_ignores_allowlist_source_order(tmp_path: Path) -> None:
    source = Path(__file__).parents[1] / "policies" / "default.json"
    value = json.loads(source.read_text(encoding="utf-8"))
    for key in (
        "registered_transformations",
        "required_verification_gates",
        "review_only_transformations",
    ):
        value[key].reverse()
    value["bounded_source_paths"].reverse()
    changed_path = tmp_path / "reordered-policy.json"
    changed_path.write_text(json.dumps(value), encoding="utf-8")
    assert load_policy(changed_path).digest == load_policy(source).digest


@pytest.mark.parametrize(
    "invalid",
    [
        {"required_verification_gates": []},
        {"registered_transformations": ["x"], "required_verification_gates": ["tests"], "review_only_transformations": [], "bounded_source_paths": [], "unexpected": True},
    ],
)
def test_invalid_policy_fails_closed(tmp_path: Path, invalid: dict[str, object]) -> None:
    path = tmp_path / "invalid-policy.json"
    path.write_text(json.dumps(invalid), encoding="utf-8")
    with pytest.raises(ValueError):
        load_policy(path)
