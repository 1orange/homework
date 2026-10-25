"""Strict, immutable contracts at the harness trust boundaries."""

from __future__ import annotations

from datetime import datetime
from enum import StrEnum
from typing import Any, Literal

from pydantic import BaseModel, ConfigDict, Field, PrivateAttr, SecretStr, field_validator


class StrictModel(BaseModel):
    # Rejected values can contain secrets or untrusted source text.  Pydantic's
    # default validation errors echo the offending input, so keep those details
    # out of all boundary exceptions.
    model_config = ConfigDict(extra="forbid", strict=True, hide_input_in_errors=True)


class Finding(StrictModel):
    id: str = Field(pattern=r"^[A-Za-z0-9][A-Za-z0-9_-]{0,127}$")
    cve: str = Field(min_length=1, max_length=128)
    severity: Literal["low", "medium", "high", "critical"]
    service: str = Field(min_length=1, max_length=256)
    package: str = Field(min_length=1, max_length=256)
    installed_version: str = Field(min_length=1, max_length=128)
    path: str = Field(min_length=1, max_length=512)
    fixed_version: str | None = Field(default=None, max_length=128)
    sla_days_remaining: int
    notes: str = Field(default="", max_length=2048)
    # New scanner feeds should provide this identity.  ``None`` is retained for
    # backwards-compatible validation of the supplied historical fixtures; the
    # orchestrator only uses a package mapping for those recorded fixtures.
    ecosystem: Literal["pypi", "maven"] | None = None
    # Reachability is advisory routing metadata, never an authorization fact.
    reachability: Literal["reachable", "unreachable", "unknown"] | bool | None = None


class InvalidFinding(StrictModel):
    """A finding that failed item validation after its envelope was accepted.

    The scanner's raw value is deliberately not retained.  ``input_hash``
    binds this safe sentinel to the exact raw item that the authenticated
    envelope contained, while ``finding_id`` is generated from its position
    and digest so an attacker-controlled ID can never become an output path.
    """

    finding_id: str = Field(pattern=r"^invalid-finding-[0-9]+-[0-9a-f]{16}$")
    input_hash: str = Field(pattern=r"^[0-9a-f]{64}$")
    source_index: int = Field(ge=0)
    error: Literal["ValidationError"] = "ValidationError"


class ScannerEnvelope(StrictModel):
    """Strict scanner envelope whose individual items are validated later."""

    generated: str = Field(min_length=1, max_length=128)
    scanner: str = Field(min_length=1, max_length=256)
    findings: list[Any] = Field(min_length=1)


class FindingFeed(StrictModel):
    generated: str = Field(min_length=1, max_length=128)
    scanner: str = Field(min_length=1, max_length=256)
    findings: list[Finding | InvalidFinding] = Field(min_length=1)
    # ``load_feed`` keeps the exact JSON item sequence here solely for
    # payload/feed binding and per-record input hashes.  It is private so raw
    # scanner values cannot accidentally serialize into evidence or agent
    # context.  Programmatically-created feeds fall back to model dumps.
    _raw_findings: tuple[object, ...] = PrivateAttr(default=())


class Provenance(StrictModel):
    source: str = Field(min_length=1, max_length=256)
    digest: str = Field(pattern=r"^[0-9a-f]{64}$")
    verified: bool
    claims: tuple[str, ...] = Field(default=(), max_length=16)


class AdvisoryClaim(StrictModel):
    source: str = Field(min_length=1, max_length=256)
    fixed_versions: tuple[str, ...] = Field(default=(), max_length=16)
    affected_ranges: tuple[str, ...] = Field(default=(), max_length=16)
    affected: bool
    cvss_score: float | None = Field(default=None, ge=0, le=10)
    cvss_vector: str | None = Field(default=None, max_length=256)
    claim: str = Field(min_length=1, max_length=2048)


class Advisory(StrictModel):
    cve: str = Field(min_length=1, max_length=128)
    ecosystem: Literal["pypi", "maven"]
    package: str = Field(min_length=1, max_length=256)
    affected: bool
    fixed_versions: tuple[str, ...] = Field(default=(), max_length=16)
    cvss_score: float | None = Field(default=None, ge=0, le=10)
    cvss_vector: str | None = Field(default=None, max_length=256)
    provenance: Provenance
    source_claims: tuple[AdvisoryClaim, ...] = ()


class NonReachabilityException(StrictModel):
    """Human-accountable exception metadata; it can only route to review."""

    approved_by: str = Field(min_length=1)
    expires_at: datetime
    tool_identity: str = Field(min_length=1)
    repository_commit: str = Field(min_length=1)
    coverage_context: str = Field(min_length=1)

    @field_validator("expires_at", mode="before")
    @classmethod
    def parse_expiry(cls, value: object) -> object:
        """Accept only ISO timestamps, retaining a typed datetime contract."""
        if isinstance(value, str):
            try:
                return datetime.fromisoformat(value.replace("Z", "+00:00"))
            except ValueError as exc:
                raise ValueError("expires_at must be an ISO timestamp") from exc
        return value

    @field_validator("approved_by", "tool_identity", "repository_commit", "coverage_context")
    @classmethod
    def require_metadata(cls, value: str) -> str:
        if not value.strip():
            raise ValueError("approval metadata must not be blank")
        return value


class Proposal(StrictModel):
    """A declarative proposal; intentionally has no command or script field."""

    model_config = ConfigDict(extra="forbid", strict=True, frozen=True, hide_input_in_errors=True)

    finding_id: str = Field(pattern=r"^[A-Za-z0-9][A-Za-z0-9_-]{0,127}$")
    service: str = Field(min_length=1, max_length=256)
    package: str = Field(min_length=1, max_length=256)
    ecosystem: Literal["pypi", "maven"]
    installed_version: str = Field(min_length=1, max_length=128)
    target_version: str = Field(min_length=1, max_length=128)
    transformation_id: str = Field(min_length=1, max_length=128)
    verification_ids: tuple[str, ...] = Field(min_length=1, max_length=16)
    intended_paths: tuple[str, ...] = Field(default=(), max_length=32)
    rationale: str = Field(min_length=1, max_length=2048)
    non_reachability_exception: NonReachabilityException | None = None


class ProposalContext(StrictModel):
    """The complete, bounded input exposed to the simulated agent."""

    finding: Finding
    advisory: Advisory
    provenance: Provenance
    allowed_transformations: tuple[str, ...]
    allowed_verifications: tuple[str, ...]

    def model_dump(self, *args: Any, **kwargs: Any) -> dict[str, Any]:
        """Return a bounded, redacted view when serialized for the agent.

        The typed object remains available to deterministic policy code, but the
        model-facing JSON must not carry scanner notes or advisory prose.  The
        deterministic fixture agent only needs the identity and normalized facts.
        """
        data = super().model_dump(*args, **kwargs)
        finding = data.get("finding")
        if isinstance(finding, dict):
            finding["notes"] = "[REDACTED]"
        advisory = data.get("advisory")
        if isinstance(advisory, dict):
            claims = advisory.get("source_claims")
            if isinstance(claims, list):
                for claim in claims:
                    if isinstance(claim, dict):
                        claim["claim"] = "[REDACTED]"
        return data


class ChangeObservation(StrictModel):
    files: tuple[str, ...]
    content_hashes: dict[str, str]
    dependency_only: bool
    unrelated_files: tuple[str, ...] = ()
    protected_files: tuple[str, ...] = ()
    weakened_controls: tuple[str, ...] = ()


class VerificationGate(StrictModel):
    id: str = Field(min_length=1)
    status: Literal["passed", "failed", "unavailable", "timeout", "corrupt"]
    detail: str = ""


class VerificationReport(StrictModel):
    gates: tuple[VerificationGate, ...]


class RuleEvaluation(StrictModel):
    rule: str = Field(min_length=1)
    outcome: Literal["pass", "review", "fail"]
    reason: str = Field(min_length=1)


class Decision(StrEnum):
    accept = "accept"
    review = "review"
    reject = "reject"


class PolicyResult(StrictModel):
    decision: Decision
    primary_reason: str = Field(min_length=1)
    rules: tuple[RuleEvaluation, ...]
    # Routing metadata only.  Priority never waives an authorization rule.
    priority: Literal["urgent", "high", "normal", "low"] = "normal"


class FindingResult(StrictModel):
    finding_id: str = Field(pattern=r"^[A-Za-z0-9][A-Za-z0-9_-]{0,127}$")
    run_status: Literal["completed", "error"]
    decision: Decision | None = None
    primary_reason: str | None = None
    lifecycle_state: Literal["proposed", "authorized", "merged", "built", "deployed", "verified_remediated"] = "proposed"
    rules: tuple[RuleEvaluation, ...] = ()
    proposal_hash: str | None = None
    # A completed policy result is committed to the exact facts that produced
    # it.  Processing errors deliberately leave this unset: an operational
    # failure must never be mistaken for an authorization commitment.
    binding_hash: str | None = Field(default=None, pattern=r"^[0-9a-f]{64}$")
    priority: Literal["urgent", "high", "normal", "low"] = "normal"
    error: str | None = None
    error_stage: str | None = None


class RunResult(StrictModel):
    run_id: str = Field(min_length=1)
    run_status: Literal["completed", "error"]
    findings: tuple[FindingResult, ...]
    ledger_path: str
    # These are copied from the terminal ledger event so consumers can detect
    # truncation without having to guess which ledger bytes were evaluated.
    ledger_final_hash: str = Field(pattern=r"^[0-9a-f]{64}$")
    ledger_event_count: int = Field(ge=1)


class RedactedCredentials(StrictModel):
    """Only used by future adapters; secret values never serialize by default."""

    token: SecretStr

    def model_dump(self, *args: Any, **kwargs: Any) -> dict[str, Any]:
        return {"token": "[REDACTED]"}
