"""Offline, declarative fixture corpus for the aggregate harness demo.

The corpus deliberately keeps scanner findings, advisory claims, proposals,
observed changes, verification responses, and expected outcomes in separate
files.  The adapters in this module join those records by ``finding_id`` (or
the advisory CVE/package identity) and expose the same small interfaces used
by the normal orchestrator.  No fixture record is executable.
"""

from __future__ import annotations

import hashlib
import json
from dataclasses import dataclass
from pathlib import Path
from collections.abc import Mapping
from types import MappingProxyType
from typing import Any

from pydantic import BaseModel, ConfigDict, Field, ValidationError

from agent_harness.boundaries import canonical_json
from agent_harness.models import (
    Advisory,
    ChangeObservation,
    Finding,
    FindingFeed,
    Proposal,
    ProposalContext,
    Provenance,
    VerificationGate,
    VerificationReport,
)


class FixtureCorpusError(ValueError):
    """The corpus itself is malformed or incomplete."""


class InvalidFixtureProvenanceError(LookupError):
    """A case intentionally represents an untrusted provenance boundary."""


class CorpusRecord(BaseModel):
    model_config = ConfigDict(extra="forbid", strict=True)
    finding_id: str = Field(min_length=1)


class ExpectedResult(CorpusRecord):
    decision: str | None = None
    primary_reason: str | None = None
    run_status: str = "completed"
    lifecycle_state: str = "proposed"
    category: str = Field(min_length=1)
    rule_order: tuple[str, ...] = ()
    error: str | None = None


_CORPUS_DIGEST_ALLOWLIST = frozenset({
    # Canonical digest of the checked-in aggregate matrix.  This is deliberately
    # an allow-list, rather than a digest calculated and trusted by the loader
    # at verification time.
    "3d32e112bebbfc5b8e675f2e017b1372db3643ca1450fba28d9329a667672bcc",
    # Canonical digest of the checked-in three-finding CLI corpus.
    "db55e6666ac83ec269ca450b4c3abe1b12c3fd2b7631695e65e06a56150ce8a2",
})


def _canonical_record_order(name: str, value: Any) -> Any:
    """Normalize only semantically unordered fixture collections."""
    if not isinstance(value, list):
        if isinstance(value, dict):
            return {key: _canonical_record_order(name, item) for key, item in value.items()}
        return value
    rows = [_canonical_record_order(name, item) for item in value]
    if name == "findings.json":
        rows.sort(key=lambda row: str(row.get("id", "")) if isinstance(row, dict) else "")
        return rows
    if name == "advisories.json":
        rows.sort(key=lambda row: tuple(str(row.get(key, "")) for key in ("cve", "package", "ecosystem")) if isinstance(row, dict) else ("", "", ""))
        return rows
    if name in {"proposals.json", "changes.json", "verification.json", "expected.json"}:
        rows.sort(key=lambda row: str(row.get("finding_id", "")) if isinstance(row, dict) else "")
        if name == "proposals.json":
            for row in rows:
                if isinstance(row, dict):
                    for key in ("verification_ids", "intended_paths"):
                        if isinstance(row.get(key), list):
                            row[key] = sorted(row[key])
        elif name == "verification.json":
            for row in rows:
                if isinstance(row, dict) and isinstance(row.get("gates"), list):
                    row["gates"].sort(key=lambda gate: str(gate.get("id", "")))
        return rows
    return rows


class CorpusProvenanceVerifier:
    """Authenticate the complete normalized fixture corpus.

    The corpus digest is calculated once from all six source files and checked
    against the checked-in allow-list.  ``verify`` still returns the scanner
    envelope digest because the orchestrator binds that exact payload to the
    processed feed; the allow-listed corpus digest is the trust decision.
    """

    def __init__(self, canonical_payload: dict[str, Any] | None = None) -> None:
        self.corpus_digest = (
            hashlib.sha256(canonical_json(canonical_payload).encode("utf-8")).hexdigest()
            if canonical_payload is not None else None
        )

    def verify(self, payload: dict[str, Any]) -> Provenance:
        if self.corpus_digest is None or self.corpus_digest not in _CORPUS_DIGEST_ALLOWLIST:
            raise ValueError("fixture corpus digest is not allow-listed")
        scanner = payload.get("scanner")
        generated = payload.get("generated")
        if not isinstance(scanner, str) or not scanner.startswith("fixture-"):
            raise ValueError("fixture corpus scanner is not recognized")
        if not isinstance(generated, str) or not generated:
            raise ValueError("fixture corpus timestamp is not recognized")
        digest = hashlib.sha256(canonical_json(payload).encode("utf-8")).hexdigest()
        return Provenance(
            source="fixture://aggregate-corpus",
            digest=digest,
            verified=True,
            claims=("offline-fixture", "aggregate-corpus", "canonical-allowlist", "offline-digest"),
        )


class CorpusAdvisoryAdapter:
    def __init__(self, records: dict[tuple[str, str, str], Advisory | Exception]) -> None:
        self.records = MappingProxyType(dict(records))

    def enrich(self, cve: str, package: str, ecosystem: str | None) -> Advisory:
        if ecosystem is None:
            candidates = [
                record for (record_cve, record_package, _), record in self.records.items()
                if record_cve == cve and record_package == package
            ]
            if len(candidates) != 1:
                raise LookupError(f"fixture advisory identity is not uniquely resolvable for {cve}")
            record = candidates[0]
        else:
            try:
                record = self.records[(cve, package, ecosystem)]
            except KeyError as exc:
                raise LookupError(f"missing fixture advisory for {cve}") from exc
        if isinstance(record, Exception):
            raise record
        return record


class CorpusProposalAgent:
    """Select exactly one immutable proposal from the finding-ID map."""

    model_name = "fixture.CorpusProposalAgent"

    def __init__(self, records: dict[str, Proposal]) -> None:
        self.records = MappingProxyType(dict(records))

    def proposal_for(self, finding_id: str) -> Proposal:
        try:
            return self.records[finding_id]
        except KeyError as exc:
            raise LookupError(f"missing fixture proposal for {finding_id}") from exc

    def propose(self, context: ProposalContext) -> Proposal:
        try:
            proposal = self.proposal_for(context.finding.id)
        except LookupError as exc:
            raise LookupError(f"missing fixture proposal for {context.finding.id}") from exc
        if proposal.finding_id != context.finding.id:
            raise ValueError("fixture proposal selected a different finding")
        return proposal


class CorpusChangeObserver:
    def __init__(self, records: dict[str, ChangeObservation]) -> None:
        self.records = MappingProxyType(dict(records))

    def observe(self, finding: Finding, proposal: object) -> ChangeObservation:
        try:
            return self.records[finding.id]
        except KeyError as exc:
            raise LookupError(f"missing fixture change observation for {finding.id}") from exc


class CorpusVerificationRunner:
    def __init__(self, records: dict[str, VerificationReport]) -> None:
        self.records = MappingProxyType(dict(records))

    def verify(self, finding: Finding, proposal: object, changes: ChangeObservation) -> VerificationReport:
        try:
            return self.records[finding.id]
        except KeyError as exc:
            raise LookupError(f"missing fixture verification for {finding.id}") from exc


@dataclass(frozen=True)
class FixtureCatalog:
    """Immutable, typed records shared by fixture adapters."""

    advisories: Mapping[tuple[str, str, str], Advisory | Exception]
    proposals: Mapping[str, Proposal]
    changes: Mapping[str, ChangeObservation]
    verification: Mapping[str, VerificationReport]

    def __post_init__(self) -> None:
        object.__setattr__(self, "advisories", MappingProxyType(dict(self.advisories)))
        object.__setattr__(self, "proposals", MappingProxyType(dict(self.proposals)))
        object.__setattr__(self, "changes", MappingProxyType(dict(self.changes)))
        object.__setattr__(self, "verification", MappingProxyType(dict(self.verification)))


class FixtureCorpus:
    """Loaded and canonicalized aggregate fixture dataset.

    The directory must contain ``findings.json``, ``advisories.json``,
    ``proposals.json``, ``changes.json``, ``verification.json``, and
    ``expected.json``.  Files contain ordinary JSON arrays except findings,
    which use the normal scanner-feed envelope.  Arrays are allowed in any
    order; all joins and the feed handed to the orchestrator are normalized.
    """

    required_files = (
        "findings.json",
        "advisories.json",
        "proposals.json",
        "changes.json",
        "verification.json",
        "expected.json",
    )

    def __init__(
        self,
        *,
        payload: dict[str, Any],
        feed: FindingFeed,
        advisories: CorpusAdvisoryAdapter,
        proposals: CorpusProposalAgent,
        changes: CorpusChangeObserver,
        verification: CorpusVerificationRunner,
        expected: tuple[ExpectedResult, ...],
        canonical_payload: dict[str, Any],
    ) -> None:
        self.payload = payload
        self.feed = feed
        self.advisory_adapter = advisories
        self.agent = proposals
        self.change_observer = changes
        self.verification_runner = verification
        self.catalog = FixtureCatalog(
            advisories=advisories.records,
            proposals=proposals.records,
            changes=changes.records,
            verification=verification.records,
        )
        self.expected = expected
        self.verifier = CorpusProvenanceVerifier(canonical_payload)

    @classmethod
    def load(cls, directory: Path) -> "FixtureCorpus":
        directory = Path(directory)
        if not directory.is_dir():
            raise FixtureCorpusError("fixture corpus must be a directory")

        values: dict[str, Any] = {}
        for name in cls.required_files:
            path = directory / name
            try:
                values[name] = json.loads(path.read_text(encoding="utf-8"))
            except (OSError, json.JSONDecodeError) as exc:
                raise FixtureCorpusError(f"invalid fixture file: {name}") from exc

        try:
            raw_payload = values["findings.json"]
            raw_feed = FindingFeed.model_validate(raw_payload)
            findings = tuple(sorted(raw_feed.findings, key=lambda item: item.id))
            if len({item.id for item in findings}) != len(findings):
                raise FixtureCorpusError("fixture finding IDs must be unique")
            # Rebuild the envelope in stable order.  This keeps the run-level
            # input hash independent of source-array ordering.
            payload = dict(raw_payload)
            payload["findings"] = [item.model_dump(mode="json") for item in findings]
            feed = FindingFeed.model_validate(payload)
            advisory_adapter = cls._advisories(values["advisories.json"])
            proposal_agent = cls._proposals(values["proposals.json"])
            change_observer = cls._changes(values["changes.json"])
            verification_runner = cls._verification(values["verification.json"])
            expected = cls._expected(values["expected.json"])
        except (ValidationError, TypeError, KeyError) as exc:
            raise FixtureCorpusError("fixture corpus schema is invalid") from exc

        ids = {finding.id for finding in findings}
        if {item.finding_id for item in expected} != ids:
            raise FixtureCorpusError("expected results do not match findings")
        canonical_payload = {
            name: _canonical_record_order(name, values[name])
            for name in cls.required_files
        }
        return cls(
            payload=payload,
            feed=feed,
            advisories=advisory_adapter,
            proposals=proposal_agent,
            changes=change_observer,
            verification=verification_runner,
            expected=expected,
            canonical_payload=canonical_payload,
        )

    @staticmethod
    def _rows(value: Any, name: str) -> list[dict[str, Any]]:
        if not isinstance(value, list) or not all(isinstance(item, dict) for item in value):
            raise FixtureCorpusError(f"{name} must be an array of objects")
        return value

    @classmethod
    def _advisories(cls, value: Any) -> CorpusAdvisoryAdapter:
        records: dict[tuple[str, str, str], Advisory | Exception] = {}
        for row in cls._rows(value, "advisories.json"):
            cve = row.get("cve")
            package = row.get("package")
            ecosystem = row.get("ecosystem")
            error = row.get("error")
            if not all(isinstance(item, str) and item for item in (cve, package, ecosystem)):
                raise FixtureCorpusError("advisory identity is required")
            if error == "missing_advisory":
                records[(cve, package, ecosystem)] = LookupError("missing trusted advisory fixture")
            elif error == "invalid_provenance":
                records[(cve, package, ecosystem)] = InvalidFixtureProvenanceError("fixture provenance is invalid")
            elif error is not None:
                raise FixtureCorpusError("unknown advisory fixture error")
            else:
                data = dict(row)
                data.pop("cve", None)
                data.pop("package", None)
                data.pop("ecosystem", None)
                if isinstance(data.get("fixed_versions"), list):
                    data["fixed_versions"] = tuple(data["fixed_versions"])
                if isinstance(data.get("affected_ranges"), list):
                    data["affected_ranges"] = tuple(data["affected_ranges"])
                if isinstance(data.get("provenance"), dict) and isinstance(data["provenance"].get("claims"), list):
                    data["provenance"] = dict(data["provenance"])
                    data["provenance"]["claims"] = tuple(data["provenance"]["claims"])
                if isinstance(data.get("source_claims"), list):
                    claims = []
                    for claim in data["source_claims"]:
                        claim_data = dict(claim)
                        for field in ("fixed_versions", "affected_ranges"):
                            if isinstance(claim_data.get(field), list):
                                claim_data[field] = tuple(claim_data[field])
                        claims.append(claim_data)
                    data["source_claims"] = tuple(claims)
                records[(cve, package, ecosystem)] = Advisory(cve=cve, package=package, ecosystem=ecosystem, **data)
        return CorpusAdvisoryAdapter(records)

    @classmethod
    def _proposals(cls, value: Any) -> CorpusProposalAgent:
        records: dict[str, Proposal] = {}
        for row in cls._rows(value, "proposals.json"):
            data = dict(row)
            for field in ("verification_ids", "intended_paths"):
                if isinstance(data.get(field), list):
                    data[field] = tuple(data[field])
            proposal = Proposal.model_validate(data)
            if proposal.finding_id in records:
                raise FixtureCorpusError("duplicate proposal fixture")
            records[proposal.finding_id] = proposal
        return CorpusProposalAgent(records)

    @classmethod
    def _changes(cls, value: Any) -> CorpusChangeObserver:
        records: dict[str, ChangeObservation] = {}
        for row in cls._rows(value, "changes.json"):
            data = dict(row)
            finding_id = data.pop("finding_id", None)
            if not isinstance(finding_id, str) or finding_id in records:
                raise FixtureCorpusError("invalid change fixture identity")
            for field in ("files", "unrelated_files", "protected_files", "weakened_controls"):
                if isinstance(data.get(field), list):
                    data[field] = tuple(data[field])
            records[finding_id] = ChangeObservation.model_validate(data)
        return CorpusChangeObserver(records)

    @classmethod
    def _verification(cls, value: Any) -> CorpusVerificationRunner:
        records: dict[str, VerificationReport] = {}
        for row in cls._rows(value, "verification.json"):
            data = dict(row)
            finding_id = data.pop("finding_id", None)
            if not isinstance(finding_id, str) or finding_id in records:
                raise FixtureCorpusError("invalid verification fixture identity")
            if isinstance(data.get("gates"), list):
                data["gates"] = tuple(data["gates"])
            records[finding_id] = VerificationReport.model_validate(data)
        return CorpusVerificationRunner(records)

    @classmethod
    def _expected(cls, value: Any) -> tuple[ExpectedResult, ...]:
        results = []
        for row in cls._rows(value, "expected.json"):
            data = dict(row)
            if isinstance(data.get("rule_order"), list):
                data["rule_order"] = tuple(data["rule_order"])
            results.append(ExpectedResult.model_validate(data))
        results = tuple(sorted(results, key=lambda item: item.finding_id))
        if len({item.finding_id for item in results}) != len(results):
            raise FixtureCorpusError("duplicate expected fixture identity")
        return results


def build_fixture_harness(
    corpus: FixtureCorpus,
    *,
    verifier=None,
    policy=None,
    advisory_adapter=None,
    agent=None,
    change_observer=None,
    verification_runner=None,
    repository_commit=None,
    artifact=None,
    artifact_hash=None,
):
    """Compose the harness explicitly from one validated fixture catalog."""
    from agent_harness.advisories import FixtureAdvisoryAdapter
    from agent_harness.agent import DeterministicProposalAgent
    from agent_harness.orchestrator import Harness
    from agent_harness.policy_config import load_default_policy

    return Harness(
        verifier or corpus.verifier,
        policy=policy or load_default_policy(),
        advisory_adapter=advisory_adapter or FixtureAdvisoryAdapter(corpus.catalog.advisories),
        agent=agent or DeterministicProposalAgent(corpus.catalog.proposals),
        change_observer=change_observer or CorpusChangeObserver(corpus.catalog.changes),
        verification_runner=verification_runner or CorpusVerificationRunner(corpus.catalog.verification),
        repository_commit=repository_commit,
        artifact=artifact,
        artifact_hash=artifact_hash,
    )


__all__ = [
    "CorpusAdvisoryAdapter",
    "CorpusChangeObserver",
    "CorpusProposalAgent",
    "CorpusProvenanceVerifier",
    "CorpusVerificationRunner",
    "ExpectedResult",
    "FixtureCatalog",
    "FixtureCorpus",
    "FixtureCorpusError",
    "InvalidFixtureProvenanceError",
    "build_fixture_harness",
]
