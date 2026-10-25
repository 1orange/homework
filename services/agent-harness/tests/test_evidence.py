from __future__ import annotations

import json
from pathlib import Path

import pytest
from pydantic import SecretBytes, SecretStr

from agent_harness.evidence import (
    EvidenceError,
    EvidenceLedger,
    RedactionFilter,
    create_approval_binding,
    redact_value,
    safe_error,
    validate_ledger,
    verify_approval_binding,
    verify_ledger,
    write_attestation,
)


def test_canonical_hash_normalizes_mapping_order_and_redacts_secrets() -> None:
    from agent_harness.evidence import sha256_json

    assert sha256_json({"b": 2, "a": 1}) == sha256_json({"a": 1, "b": 2})
    clean = redact_value({"token": "do-not-write", "raw_source": "source text", "ok": 1})
    assert clean == {"token": "[REDACTED]", "ok": 1}
    assert "do-not-write" not in str(clean)


def test_ledger_uses_injected_clock_and_ids_and_detects_tampering(tmp_path: Path) -> None:
    timestamps = iter(("2026-01-01T00:00:00Z", "2026-01-01T00:00:01Z"))
    event_ids = iter(("event-0", "event-1"))
    path = tmp_path / "ledger.jsonl"
    ledger = EvidenceLedger(path, run_id="run-test", clock=lambda: next(timestamps), id_factory=lambda: next(event_ids))
    ledger.append("finding_started", "F-1", {"token": "secret-value", "raw_logs": "untrusted"})
    ledger.append("run_completed", None, {"last_event_hash": ledger.previous_hash})

    assert verify_ledger(path)
    events = [json.loads(line) for line in path.read_text().splitlines()]
    assert events[0]["event_id"] == "event-0"
    assert events[0]["timestamp"] == "2026-01-01T00:00:00Z"
    assert "secret-value" not in path.read_text()

    events[0]["payload"]["new_fact"] = "tampered"
    path.write_text("\n".join(json.dumps(event) for event in events) + "\n")
    assert not verify_ledger(path)


def test_completed_ledger_truncation_is_detected(tmp_path: Path) -> None:
    path = tmp_path / "ledger.jsonl"
    ledger = EvidenceLedger(path, run_id="run-test", timestamp="2026-01-01T00:00:00Z")
    ledger.append("finding_started", "F-1", {})
    ledger.append("run_completed", None, {"last_event_hash": ledger.previous_hash})
    final_hash = ledger.previous_hash
    path.write_text(path.read_text().splitlines()[0] + "\n")
    assert not verify_ledger(path)
    assert not verify_ledger(path, expected_final_hash=final_hash)
    assert validate_ledger(path, allow_in_progress=True)[0]["event_type"] == "finding_started"


def test_completed_ledger_cannot_be_appended(tmp_path: Path) -> None:
    path = tmp_path / "ledger.jsonl"
    ledger = EvidenceLedger(path, run_id="run-test", timestamp="2026-01-01T00:00:00Z")
    ledger.append("run_completed", None, {"last_event_hash": ledger.previous_hash})
    with pytest.raises(EvidenceError):
        ledger.append("late_event", None, {})
    with pytest.raises(EvidenceError):
        EvidenceLedger(path, run_id="run-test")


def test_approval_binding_invalidates_changed_inputs() -> None:
    binding = create_approval_binding({"finding": {"id": "F-1"}, "proposal": {"target": "5.4"}})
    assert verify_approval_binding(binding, {"finding": {"id": "F-1"}, "proposal": {"target": "5.4"}})
    assert not verify_approval_binding(binding, {"finding": {"id": "F-1"}, "proposal": {"target": "5.5"}})


def test_approval_binding_commits_secret_values_without_serializing_them() -> None:
    first = create_approval_binding({"clientSecret": SecretStr("first-value")})
    second = create_approval_binding({"clientSecret": SecretStr("second-value")})
    binary = create_approval_binding({"clientSecret": SecretBytes(b"first-value")})

    assert first.binding_hash != second.binding_hash
    assert first.binding_hash != binary.binding_hash
    assert "first-value" not in first.model_dump_json()
    assert "second-value" not in second.model_dump_json()


def test_redaction_masks_camel_case_sensitive_keys() -> None:
    clean = redact_value({"clientSecret": "secret-value", "apiToken": "token-value", "safe": 1})
    assert clean == {"clientSecret": "[REDACTED]", "apiToken": "[REDACTED]", "safe": 1}


def test_attestation_is_immutable_and_validation_errors_are_safe(tmp_path: Path) -> None:
    write_attestation(tmp_path, "F-1", {"decision": "accept", "password": "secret-value"})
    assert "secret-value" not in (tmp_path / "F-1.json").read_text()
    with pytest.raises(EvidenceError):
        write_attestation(tmp_path, "F-1", {"decision": "reject"})
    assert safe_error(ValueError("token=secret-value")) == "ValueError"


def test_attestation_rejects_traversal_and_symlink_targets(tmp_path: Path) -> None:
    with pytest.raises(EvidenceError):
        write_attestation(tmp_path, "../outside", {"decision": "accept"})

    outside = tmp_path / "outside.json"
    outside.write_text("keep\n", encoding="utf-8")
    target = tmp_path / "F-2.json"
    target.symlink_to(outside)
    with pytest.raises(EvidenceError):
        write_attestation(tmp_path, "F-2", {"decision": "reject"})
    assert outside.read_text(encoding="utf-8") == "keep\n"


def test_redaction_filter_masks_structured_log_args() -> None:
    import logging

    record = logging.LogRecord("test", logging.INFO, __file__, 1, "credentials=%s", ("secret-value",), None)
    RedactionFilter().filter(record)
    assert "secret-value" not in str(record.args)
