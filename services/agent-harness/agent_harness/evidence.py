"""Canonical, tamper-evident and secret-safe evidence primitives.

Evidence is deliberately a fact record, rather than a copy of material that
was inspected. Callers should put hashes and bounded structured facts in a
ledger payload. This module applies a last-resort redaction pass before
anything is hashed or written.
"""

from __future__ import annotations

import hashlib
import hmac
import json
import logging
import os
import re
import stat
from dataclasses import dataclass
from datetime import date, datetime, timezone
from pathlib import Path
from typing import Any, Callable, Mapping


_SENSITIVE_KEY = re.compile(
    r"(?:^|[_-])(secret|token|password|passwd|credential|credentials|api[-_]?key|"
    r"private[-_]?key|authorization|cookie|session)(?:$|[_-])", re.IGNORECASE
)
_RAW_KEY = re.compile(
    r"(?:^|[_-])(?:raw[-_]?(?:source|log|logs)|issue[-_]?(?:text|body)|"
    r"source[-_]?(?:text|content)|prompt|source|log|logs|issue)(?:$|[_-])", re.IGNORECASE
)
_SECRET_TEXT = re.compile(
    r"(?i)(?:bearer\s+|basic\s+|password\s*[=:]\s*|token\s*[=:]\s*|"
    r"api[_-]?key\s*[=:]\s*)([^\s,;]+)"
)
_SECRET_LITERAL = re.compile(r"(?i)(?:secret|password|credential)[-_]?[A-Za-z0-9._-]+")
_ATTESTATION_ID = re.compile(r"^[A-Za-z0-9][A-Za-z0-9_-]{0,127}$")


class EvidenceError(ValueError):
    """Base error for invalid or unverifiable evidence."""


class LedgerVerificationError(EvidenceError):
    """Raised by :func:`validate_ledger` when the chain is not trustworthy."""


def _to_jsonable(value: Any) -> Any:
    """Convert common model values without exposing a SecretStr value."""

    if value is None or isinstance(value, (str, int, float, bool)):
        return value
    try:
        from pydantic import SecretBytes, SecretStr

        if isinstance(value, (SecretStr, SecretBytes)):
            return "[REDACTED]"
    except ImportError:  # pragma: no cover
        pass
    if isinstance(value, (datetime, date)):
        return value.isoformat()
    if isinstance(value, Mapping):
        return {str(key): _to_jsonable(item) for key, item in value.items()}
    if isinstance(value, (list, tuple, set, frozenset)):
        items = [_to_jsonable(item) for item in value]
        if isinstance(value, (set, frozenset)):
            items.sort(key=lambda item: json.dumps(item, sort_keys=True, ensure_ascii=False))
        return items
    if hasattr(value, "model_dump"):
        return _to_jsonable(value.model_dump(mode="json"))
    if hasattr(value, "__dict__"):
        return _to_jsonable(vars(value))
    return str(value)


def _normalized_key(key: Any) -> str:
    """Normalize separators so sensitive camelCase keys use the same rules."""

    return re.sub(r"([a-z0-9])([A-Z])", r"\1_\2", str(key))


def _is_raw_key(key: Any) -> bool:
    return bool(_RAW_KEY.search(_normalized_key(key)))


def _is_sensitive_key(key: Any) -> bool:
    return bool(_SENSITIVE_KEY.search(_normalized_key(key)))


def redact_text(value: str) -> str:
    """Mask credential-shaped values in diagnostic text."""

    value = _SECRET_TEXT.sub(
        lambda match: match.group(0)[:-len(match.group(1))] + "[REDACTED]", value
    )
    return _SECRET_LITERAL.sub("[REDACTED]", value)


def redact_value(value: Any, *, key: str | None = None) -> Any:
    """Return a JSON-safe value with sensitive fields removed or masked."""

    if key and _is_raw_key(key):
        return None
    if key and _is_sensitive_key(key):
        return "[REDACTED]"
    value = _to_jsonable(value)
    if isinstance(value, str):
        return redact_text(value)
    if isinstance(value, dict):
        output: dict[str, Any] = {}
        for child_key, child_value in value.items():
            if _is_raw_key(child_key):
                continue
            output[str(child_key)] = redact_value(child_value, key=str(child_key))
        return output
    if isinstance(value, list):
        return [redact_value(item) for item in value]
    return value


def safe_error(exc: BaseException) -> str:
    """Produce a stable error description without echoing rejected input."""

    return type(exc).__name__


def canonical_json(value: Any) -> str:
    """Serialize normalized values deterministically for hashing and storage."""

    return json.dumps(redact_value(value), sort_keys=True, separators=(",", ":"), ensure_ascii=False)


def sha256_json(value: Any) -> str:
    """SHA-256 of :func:`canonical_json`."""

    return hashlib.sha256(canonical_json(value).encode("utf-8")).hexdigest()


canonical_hash = sha256_json
canonical_serialize = canonical_json


def _timestamp(value: str | datetime) -> str:
    if isinstance(value, datetime):
        if value.tzinfo is None:
            value = value.replace(tzinfo=timezone.utc)
        return value.astimezone(timezone.utc).isoformat().replace("+00:00", "Z")
    return value


class EvidenceLedger:
    """Append-only JSONL ledger with a hash-linked event chain."""

    def __init__(
        self,
        path: Path,
        *,
        run_id: str,
        timestamp: str | datetime | None = None,
        clock: Callable[[], str | datetime] | None = None,
        id_factory: Callable[[], str] | None = None,
        event_id_factory: Callable[[], str] | None = None,
    ) -> None:
        self.path = Path(path)
        self.run_id = run_id
        self._fixed_timestamp = timestamp or "1970-01-01T00:00:00Z"
        self.clock = clock
        self.id_factory = event_id_factory or id_factory
        self.previous_hash: str | None = None
        self.sequence = 0
        self.path.parent.mkdir(parents=True, exist_ok=True)
        if self.path.exists() and self.path.stat().st_size:
            # Re-opening an in-progress ledger is an internal resume path. A
            # completed ledger is deliberately rejected below so callers
            # cannot append an invalid post-terminal chain.
            events = validate_ledger(self.path, expected_run_id=run_id, allow_in_progress=True)
            if events[-1].get("event_type") == "run_completed":
                raise EvidenceError("cannot append to a completed ledger")
            self.sequence = len(events)
            self.previous_hash = events[-1]["event_hash"]
        self._completed = False

    def _now(self) -> str:
        value = self.clock() if self.clock else self._fixed_timestamp
        return _timestamp(value)

    def append(self, event_type: str, finding_id: str | None, payload: Mapping[str, Any]) -> str:
        if self._completed:
            raise EvidenceError("cannot append to a completed ledger")
        clean_payload = redact_value(dict(payload))
        event: dict[str, Any] = {
            "sequence": self.sequence,
            "run_id": self.run_id,
            "finding_id": finding_id,
            "event_type": event_type,
            "timestamp": self._now(),
            "payload": clean_payload,
            "previous_hash": self.previous_hash,
        }
        if self.id_factory:
            event["event_id"] = self.id_factory()
        event_hash = _hash_event(event)
        event["event_hash"] = event_hash
        with self.path.open("a", encoding="utf-8") as stream:
            stream.write(canonical_json(event) + "\n")
        self.previous_hash = event_hash
        self.sequence += 1
        self._completed = event_type == "run_completed"
        return event_hash

    def verify(self, **kwargs: Any) -> bool:
        """Verify this ledger instance's on-disk chain."""

        return verify_ledger(self.path, expected_run_id=self.run_id, **kwargs)


def _hash_event(event: Mapping[str, Any]) -> str:
    unsigned = {key: value for key, value in event.items() if key != "event_hash"}
    # Events are redacted before append. Hash the exact canonical bytes that
    # were written so replacing a masked value with a secret is still detected
    # as tampering (the public canonical helper intentionally masks secrets).
    encoded = json.dumps(_to_jsonable(unsigned), sort_keys=True, separators=(",", ":"), ensure_ascii=False)
    return hashlib.sha256(encoded.encode("utf-8")).hexdigest()


def _read_events(path: Path) -> list[dict[str, Any]]:
    try:
        lines = path.read_text(encoding="utf-8").splitlines()
    except OSError as exc:
        raise LedgerVerificationError("ledger cannot be read") from exc
    events: list[dict[str, Any]] = []
    for line_number, line in enumerate(lines, 1):
        if not line.strip():
            continue
        try:
            event = json.loads(line)
        except json.JSONDecodeError as exc:
            raise LedgerVerificationError(f"invalid ledger JSON at line {line_number}") from exc
        if not isinstance(event, dict):
            raise LedgerVerificationError(f"ledger event at line {line_number} is not an object")
        events.append(event)
    if not events:
        raise LedgerVerificationError("ledger is empty")
    return events


def validate_ledger(
    path: Path,
    *,
    expected_run_id: str | None = None,
    expected_final_hash: str | None = None,
    expected_event_count: int | None = None,
    require_terminal: bool = True,
    allow_in_progress: bool | None = None,
) -> tuple[dict[str, Any], ...]:
    """Validate sequence, links and hashes, raising on any tampering.

    Verification is for completed runs by default.  ``allow_in_progress`` is
    an explicit escape hatch for an internal writer resuming an unfinished
    ledger; it must never be used for a trust decision about run output.
    ``require_terminal=False`` is retained as an equivalent low-level option.
    """

    if allow_in_progress is not None:
        require_terminal = not allow_in_progress

    events = _read_events(Path(path))
    if expected_event_count is not None and len(events) != expected_event_count:
        raise LedgerVerificationError("ledger event count does not match its anchor")
    run_id = expected_run_id or events[0].get("run_id")
    previous: str | None = None
    seen_sequences: set[int] = set()
    for index, event in enumerate(events):
        required = {"sequence", "run_id", "finding_id", "event_type", "timestamp", "payload", "previous_hash", "event_hash"}
        if not required <= event.keys():
            raise LedgerVerificationError(f"ledger event {index} is missing required fields")
        if event.get("sequence") != index or event["sequence"] in seen_sequences:
            raise LedgerVerificationError("ledger sequence is not contiguous")
        seen_sequences.add(event["sequence"])
        if run_id is not None and event.get("run_id") != run_id:
            raise LedgerVerificationError("ledger contains multiple run identifiers")
        if event.get("previous_hash") != previous:
            raise LedgerVerificationError("ledger previous-hash link is broken")
        if not isinstance(event.get("payload"), dict) or _hash_event(event) != event.get("event_hash"):
            raise LedgerVerificationError("ledger event hash does not match canonical content")
        previous = event["event_hash"]
    if expected_final_hash is not None and previous != expected_final_hash:
        raise LedgerVerificationError("ledger final hash does not match its anchor")
    completed_events = [event for event in events if event.get("event_type") == "run_completed"]
    if completed_events:
        if len(completed_events) != 1:
            raise LedgerVerificationError("ledger contains multiple terminal events")
        if events[-1].get("event_type") != "run_completed":
            raise LedgerVerificationError("completed ledger is missing its terminal event")
        terminal_previous = events[-2]["event_hash"] if len(events) > 1 else None
        if events[-1].get("payload", {}).get("last_event_hash") != terminal_previous:
            raise LedgerVerificationError("terminal event does not anchor the preceding event")
    elif require_terminal:
        raise LedgerVerificationError("ledger is missing its terminal event")
    return tuple(events)


def verify_ledger(path: Path, **kwargs: Any) -> bool:
    """Return ``True`` only when a ledger is fully verifiable."""

    try:
        validate_ledger(path, **kwargs)
    except (EvidenceError, OSError, TypeError, ValueError):
        return False
    return True


def verify_chain(path: Path, **kwargs: Any) -> bool:
    return verify_ledger(path, **kwargs)


class LedgerVerifier:
    """Small injectable verifier facade for adapters and integration tests."""

    def __init__(self, *, expected_run_id: str | None = None, expected_final_hash: str | None = None) -> None:
        self.expected_run_id = expected_run_id
        self.expected_final_hash = expected_final_hash

    def verify(self, path: Path) -> bool:
        return verify_ledger(
            path,
            expected_run_id=self.expected_run_id,
            expected_final_hash=self.expected_final_hash,
        )


def write_attestation(directory: Path, finding_id: str, payload: Mapping[str, Any]) -> Path:
    """Write one immutable, redacted per-finding attestation."""

    if not isinstance(finding_id, str) or not _ATTESTATION_ID.fullmatch(finding_id):
        raise EvidenceError("invalid finding ID for attestation")
    directory = Path(directory)
    try:
        directory.mkdir(parents=True, exist_ok=True)
    except OSError as exc:
        raise EvidenceError("attestation directory cannot be created") from exc
    # A symlinked directory would make an otherwise safe filename resolve
    # outside the caller's intended output tree.
    if directory.is_symlink() or not directory.is_dir():
        raise EvidenceError("attestation directory is not a regular directory")
    path = directory / f"{finding_id}.json"
    clean = redact_value(dict(payload))
    rendered = json.dumps(clean, sort_keys=True, indent=2, ensure_ascii=False) + "\n"
    # O_NOFOLLOW protects direct API callers even when an attacker races the
    # existence check with a symlink swap. O_EXCL preserves immutability for a
    # first write; an existing regular file is read through the same no-follow
    # constraint and may only be re-written with identical bytes.
    try:
        fd = os.open(
            path,
            os.O_WRONLY | os.O_CREAT | os.O_EXCL | getattr(os, "O_NOFOLLOW", 0),
            0o600,
        )
    except FileExistsError:
        try:
            fd = os.open(
                path,
                os.O_RDONLY
                | getattr(os, "O_NOFOLLOW", 0)
                | getattr(os, "O_NONBLOCK", 0),
            )
            if not stat.S_ISREG(os.fstat(fd).st_mode):
                os.close(fd)
                raise EvidenceError("attestation target is not a regular file")
            with os.fdopen(fd, "r", encoding="utf-8") as stream:
                existing = stream.read()
        except EvidenceError:
            raise
        except OSError as exc:
            raise EvidenceError("attestation target is not a regular file") from exc
        if existing != rendered:
            raise EvidenceError("attestation already exists for finding")
        return path
    except OSError as exc:
        raise EvidenceError("attestation target cannot be created") from exc
    try:
        with os.fdopen(fd, "w", encoding="utf-8") as stream:
            stream.write(rendered)
    except OSError as exc:
        raise EvidenceError("attestation target cannot be written") from exc
    return path


def attestation_hash(payload: Mapping[str, Any]) -> str:
    return sha256_json(payload)


hash_payload = sha256_json


@dataclass(frozen=True)
class ApprovalBinding:
    """Hash commitment to every fact an authorization decision depends on."""

    fact_hashes: tuple[tuple[str, str], ...]
    binding_hash: str

    def model_dump(self, *args: Any, **kwargs: Any) -> dict[str, Any]:
        return {"fact_hashes": dict(self.fact_hashes), "binding_hash": self.binding_hash}

    def model_dump_json(self, *args: Any, **kwargs: Any) -> str:
        return canonical_json(self.model_dump())

    @classmethod
    def from_inputs(cls, facts: Mapping[str, Any] | None = None, **kwargs: Any) -> "ApprovalBinding":
        return create_approval_binding(facts, **kwargs)

    def is_valid(self, facts: Mapping[str, Any] | None = None, **kwargs: Any) -> bool:
        return verify_approval_binding(self, facts, **kwargs)


def _fact_mapping(facts: Mapping[str, Any] | None = None, **kwargs: Any) -> dict[str, Any]:
    values = dict(facts or {})
    values.update(kwargs)
    return {str(name): values[name] for name in sorted(values)}


def _approval_jsonable(value: Any) -> Any:
    """Normalize an approval fact without ever JSON-serializing a secret.

    Pydantic's ``SecretStr``/``SecretBytes`` intentionally stringify to a
    redaction marker.  That is right for evidence, but would make an approval
    binding identical for every secret.  Replace each secret with a digest
    computed directly from its in-memory value instead; only the digest enters
    the canonical JSON used for the fact commitment.
    """

    try:
        from pydantic import SecretBytes, SecretStr

        if isinstance(value, SecretStr):
            raw = value.get_secret_value().encode("utf-8")
            return {"__secret_commitment__": hashlib.sha256(b"SecretStr\0" + raw).hexdigest()}
        if isinstance(value, SecretBytes):
            raw = value.get_secret_value()
            return {"__secret_commitment__": hashlib.sha256(b"SecretBytes\0" + raw).hexdigest()}
    except ImportError:  # pragma: no cover
        pass
    if value is None or isinstance(value, (str, int, float, bool)):
        return value
    if isinstance(value, (datetime, date)):
        return value.isoformat()
    if isinstance(value, Mapping):
        return {str(key): _approval_jsonable(item) for key, item in value.items()}
    if isinstance(value, (list, tuple, set, frozenset)):
        items = [_approval_jsonable(item) for item in value]
        if isinstance(value, (set, frozenset)):
            items.sort(key=lambda item: json.dumps(item, sort_keys=True, ensure_ascii=False))
        return items
    if hasattr(value, "model_dump"):
        try:
            return _approval_jsonable(value.model_dump(mode="python"))
        except TypeError:
            return _approval_jsonable(value.model_dump())
    if hasattr(value, "__dict__"):
        return _approval_jsonable(vars(value))
    return str(value)


def approval_fact_hashes(facts: Mapping[str, Any] | None = None, **kwargs: Any) -> dict[str, str]:
    values = _fact_mapping(facts, **kwargs)
    output: dict[str, str] = {}
    for name, value in values.items():
        # Adapters frequently already have the required hash. Accepting that
        # representation avoids hashing a digest for a second time while the
        # object form remains convenient for unit/integration callers.
        normalized_name = name[:-5] if name.endswith("_hash") else name
        if name.endswith("_hash") and isinstance(value, str) and re.fullmatch(r"[0-9a-f]{64}", value):
            output[normalized_name] = value
        else:
            # Bind the exact normalized fact. Secret-bearing fields are not
            # serialized into evidence, but changing one must still invalidate
            # an old approval rather than silently reusing it.
            encoded = json.dumps(_approval_jsonable(value), sort_keys=True, separators=(",", ":"), ensure_ascii=False)
            output[normalized_name] = hashlib.sha256(encoded.encode("utf-8")).hexdigest()
    return output


def _binding_hash(fact_hashes: Mapping[str, str]) -> str:
    """Hash already-safe fact digests without redacting their field names."""

    encoded = json.dumps(dict(fact_hashes), sort_keys=True, separators=(",", ":"), ensure_ascii=False)
    return hashlib.sha256(encoded.encode("utf-8")).hexdigest()


def create_approval_binding(facts: Mapping[str, Any] | None = None, **kwargs: Any) -> ApprovalBinding:
    fact_hashes = approval_fact_hashes(facts, **kwargs)
    return ApprovalBinding(tuple(fact_hashes.items()), _binding_hash(fact_hashes))


def approval_binding_hash(facts: Mapping[str, Any] | None = None, **kwargs: Any) -> str:
    return create_approval_binding(facts, **kwargs).binding_hash


def verify_approval_binding(
    binding: ApprovalBinding | Mapping[str, Any], facts: Mapping[str, Any] | None = None, **kwargs: Any
) -> bool:
    expected = create_approval_binding(facts, **kwargs)
    if isinstance(binding, ApprovalBinding):
        actual_facts = dict(binding.fact_hashes)
        actual_hash = binding.binding_hash
    else:
        actual_facts = binding.get("fact_hashes", {})
        actual_hash = str(binding.get("binding_hash", ""))
    if not isinstance(actual_facts, Mapping) or not actual_hash:
        return False
    # Validate the commitment itself as well as comparing it with current
    # inputs; otherwise an edited fact-hash map could be paired with an old
    # binding hash and appear valid to a shallow consumer.
    committed_hash = _binding_hash({str(key): str(value) for key, value in actual_facts.items()})
    return hmac.compare_digest(str(actual_hash), committed_hash) and hmac.compare_digest(
        str(actual_hash), expected.binding_hash
    )


def approval_is_valid(*args: Any, **kwargs: Any) -> bool:
    return verify_approval_binding(*args, **kwargs)


# Short aliases used by adapters that call this an authorization commitment.
approval_hashes = approval_fact_hashes
bind_approval = create_approval_binding


class RedactionFilter(logging.Filter):
    """Final structured-log redaction filter for handlers and test capture."""

    def filter(self, record: logging.LogRecord) -> bool:
        record.msg = redact_value(record.msg)
        if record.args:
            if isinstance(record.args, Mapping):
                record.args = {key: redact_value(value, key=str(key)) for key, value in record.args.items()}
            elif isinstance(record.args, tuple):
                record.args = tuple(redact_value(value) for value in record.args)
            else:
                record.args = redact_value(record.args)
        return True


__all__ = [
    "ApprovalBinding", "EvidenceError", "EvidenceLedger", "LedgerVerificationError", "LedgerVerifier",
    "RedactionFilter", "approval_binding_hash", "approval_fact_hashes", "approval_hashes",
    "approval_is_valid", "bind_approval",
    "attestation_hash", "canonical_hash", "canonical_json", "canonical_serialize", "hash_payload",
    "create_approval_binding", "redact_text", "redact_value", "safe_error", "sha256_json",
    "validate_ledger", "verify_approval_binding", "verify_chain", "verify_ledger",
    "write_attestation",
]
