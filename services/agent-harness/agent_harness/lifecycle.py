"""Production-remediation lifecycle and reconciliation primitives.

The policy engine answers whether a *proposal* is safe to automate.  This
module answers the deliberately different question of whether the resulting
change can be described as remediated in production.  The two decisions are
kept separate: an accepted proposal can only enter ``authorized`` here and
must still pass the merge, build, deployment, runtime, SBOM, and scan facts.

The adapters represented by these models are fixtures in this exercise.  They
are facts, not assertions supplied by the proposal agent.  A lifecycle keeps
an immutable tuple of hash-linked events; a later runtime divergence appends a
``remediation_regressed`` event and reopens the finding without rewriting the
successful history.
"""

from __future__ import annotations

import hashlib
import re
from collections.abc import Callable, Iterable, Mapping
from datetime import datetime, timedelta, timezone
from enum import StrEnum
from typing import Any, Literal

from pydantic import ConfigDict, Field, ValidationError

from agent_harness.evidence import EvidenceLedger, canonical_json, sha256_json
from agent_harness.models import StrictModel


class LifecycleError(ValueError):
    """Base error for an invalid lifecycle operation or evidence set."""


class InvalidLifecycleTransition(LifecycleError):
    """Raised when a state transition attempts to skip a lifecycle stage."""


class InsufficientLifecycleEvidence(LifecycleError):
    """Raised when production-remediation evidence is absent or contradictory."""


class LifecycleState(StrEnum):
    proposed = "proposed"
    authorized = "authorized"
    merged = "merged"
    built = "built"
    deployed = "deployed"
    verified_remediated = "verified_remediated"


_STATE_ORDER = (
    LifecycleState.proposed,
    LifecycleState.authorized,
    LifecycleState.merged,
    LifecycleState.built,
    LifecycleState.deployed,
    LifecycleState.verified_remediated,
)
_GATE_STATUSES = Literal["passed", "failed", "unavailable", "timeout", "corrupt"]
_REQUIRED_GATE_IDS = frozenset({"build", "tests", "security-probe", "dependency-rescan"})
_SHA256_DIGEST = re.compile(r"^sha256:[0-9a-f]{64}$")


def _now_iso() -> str:
    return datetime.now(timezone.utc).isoformat().replace("+00:00", "Z")


def _as_datetime(value: str) -> datetime:
    try:
        parsed = datetime.fromisoformat(value.replace("Z", "+00:00"))
    except (TypeError, ValueError) as exc:
        raise InsufficientLifecycleEvidence("evidence timestamp is invalid") from exc
    if parsed.tzinfo is None:
        parsed = parsed.replace(tzinfo=timezone.utc)
    return parsed.astimezone(timezone.utc)


def _digest(value: str, *, name: str) -> str:
    if not isinstance(value, str) or not value.strip():
        raise InsufficientLifecycleEvidence(f"{name} is missing")
    return value


def _artifact(value: str, *, name: str = "artifact_digest") -> str:
    value = _digest(value, name=name)
    if not _SHA256_DIGEST.fullmatch(value):
        raise InsufficientLifecycleEvidence(f"{name} is not a valid SHA-256 digest")
    return value


def _normalize_fact_names(values: Mapping[str, Any]) -> dict[str, Any]:
    """Accept adapter vocabulary without adding alternate model fields."""

    aliases = {
        "gates": "authorized_gates",
        "gate_evidence": "authorized_gates",
        "sbom_evidence": "sbom",
        "deployment_evidence": "deployment",
        "replicas": "runtime_replicas",
        "runtime_evidence": "runtime_replicas",
        "scan": "post_deployment_scan",
        "scan_evidence": "post_deployment_scan",
        "expected_replicas": "expected_replica_ids",
        "replica_inventory": "expected_replica_ids",
        "rollback_detected": "vulnerable_rollback",
        "vulnerable_rollback_detected": "vulnerable_rollback",
    }
    return {aliases.get(str(name), str(name)): value for name, value in values.items()}


class LifecycleFact(StrictModel):
    """Base for externally observed lifecycle facts.

    Facts are frozen once admitted to the lifecycle.  ``observed_at`` is kept
    as a normalized string to match the rest of the harness boundary models.
    """

    model_config = ConfigDict(extra="forbid", strict=True, frozen=True)
    observed_at: str = Field(default_factory=_now_iso, min_length=1)


class AuthorizedGate(LifecycleFact):
    """One independently authorized CI/security gate result."""

    id: str = Field(min_length=1)
    status: _GATE_STATUSES
    # There is no implicit authorization default: this field must come from
    # the independent gate adapter, not from a proposal/verification result.
    authorized: bool


class SbomEvidence(LifecycleFact):
    """SBOM result for the exact artifact being considered."""

    finding_id: str | None = Field(default=None, min_length=1)
    package: str | None = Field(default=None, min_length=1)
    cve: str | None = Field(default=None, min_length=1)
    artifact_digest: str = Field(min_length=1)
    vulnerable_artifact: str = Field(min_length=1)
    vulnerable_artifact_present: bool


class DeploymentEvidence(LifecycleFact):
    """Deployment controller result for a fixed artifact."""

    finding_id: str | None = Field(default=None, min_length=1)
    package: str | None = Field(default=None, min_length=1)
    cve: str | None = Field(default=None, min_length=1)
    deployment_id: str = Field(min_length=1)
    status: Literal["completed", "pending", "failed"]
    artifact_digest: str = Field(min_length=1)


class RuntimeReplica(LifecycleFact):
    """Observed digest for one production replica."""

    finding_id: str | None = Field(default=None, min_length=1)
    package: str | None = Field(default=None, min_length=1)
    cve: str | None = Field(default=None, min_length=1)
    replica_id: str = Field(min_length=1)
    artifact_digest: str = Field(min_length=1)
    healthy: bool = True


class PostDeploymentScan(LifecycleFact):
    """Finding-specific scan performed after deployment completed."""

    finding_id: str | None = Field(default=None, min_length=1)
    package: str | None = Field(default=None, min_length=1)
    cve: str | None = Field(default=None, min_length=1)
    scan_id: str = Field(min_length=1)
    status: Literal["clean", "positive", "unavailable", "corrupt"]
    artifact_digest: str = Field(min_length=1)


class LifecycleEvidence(LifecycleFact):
    """All facts required to make (or reject) a production claim.

    The fields intentionally describe structured observations only.  There is
    no mode switch that can turn fixture data into a production attestation.
    """

    model_config = ConfigDict(extra="forbid", strict=True, frozen=True, populate_by_name=True)
    finding_id: str | None = Field(default=None, min_length=1)
    package: str | None = Field(default=None, min_length=1)
    cve: str | None = Field(default=None, min_length=1)
    fixed_commit: str | None = Field(default=None, min_length=1)
    artifact_digest: str | None = Field(default=None, min_length=1)
    authorized_gates: tuple[AuthorizedGate, ...] = ()
    sbom: SbomEvidence | None = None
    deployment: DeploymentEvidence | None = None
    runtime_replicas: tuple[RuntimeReplica, ...] = ()
    expected_replica_ids: tuple[str, ...] = Field(default=(), alias="expected_replicas")
    post_deployment_scan: PostDeploymentScan | None = None
    vulnerable_rollback: bool = False
    vulnerable_digests: tuple[str, ...] = ()

    @property
    def replicas(self) -> tuple[RuntimeReplica, ...]:
        """Short alias useful to adapters and callers."""

        return self.runtime_replicas

    @property
    def expected_replicas(self) -> tuple[str, ...]:
        """Compatibility alias for adapters that call the inventory by replicas."""

        return self.expected_replica_ids


# Common spelling variants are kept as aliases so adapters can use the
# terminology in their source systems without creating competing contracts.
SBOMEvidence = SbomEvidence
GateEvidence = AuthorizedGate
RuntimeEvidence = RuntimeReplica
ScanEvidence = PostDeploymentScan
RemediationEvidence = LifecycleEvidence


class LifecycleEvent(StrictModel):
    """An immutable, hash-linked lifecycle event."""

    model_config = ConfigDict(extra="forbid", strict=True, frozen=True)
    sequence: int = Field(ge=0)
    finding_id: str = Field(min_length=1)
    event_type: Literal["lifecycle_transition", "remediation_regressed"]
    from_state: str | None = None
    to_state: str = Field(min_length=1)
    timestamp: str = Field(min_length=1)
    evidence_hash: str | None = None
    reason: str | None = None
    previous_hash: str | None = None
    event_hash: str = Field(pattern=r"^[0-9a-f]{64}$")


def _event_hash(event: Mapping[str, Any]) -> str:
    unsigned = {key: value for key, value in event.items() if key != "event_hash"}
    return hashlib.sha256(canonical_json(unsigned).encode("utf-8")).hexdigest()


class RemediationLifecycle:
    """Strict sequential lifecycle with immutable event history.

    ``fixed_commit`` may be supplied when the finding's accepted proposal is
    created.  If omitted, it is bound exactly once by :meth:`build`; changing
    it later is rejected.  ``max_evidence_age`` makes stale production facts
    fail closed.  Tests and deterministic fixtures should inject ``clock``.
    """

    def __init__(
        self,
        finding_id: str,
        *,
        package: str | None = None,
        cve: str | None = None,
        fixed_commit: str | None = None,
        expected_replica_ids: Iterable[str] | None = None,
        expected_replicas: Iterable[str] | None = None,
        clock: Callable[[], str | datetime] | None = None,
        max_evidence_age: timedelta = timedelta(days=1),
        ledger: EvidenceLedger | None = None,
    ) -> None:
        if not finding_id:
            raise ValueError("finding_id is required")
        self.finding_id = finding_id
        self._package = _digest(package, name="package") if package else None
        self._cve = _digest(cve, name="cve") if cve else None
        self._fixed_commit = _digest(fixed_commit, name="fixed_commit") if fixed_commit else None
        if expected_replica_ids is not None and expected_replicas is not None:
            if tuple(expected_replica_ids) != tuple(expected_replicas):
                raise ValueError("expected replica inventories conflict")
        expected_ids = expected_replica_ids if expected_replica_ids is not None else expected_replicas
        if expected_ids is None:
            self._expected_replica_ids: tuple[str, ...] | None = None
        else:
            ids = tuple(_digest(replica_id, name="replica_id") for replica_id in expected_ids)
            if not ids or len(ids) != len(set(ids)):
                raise ValueError("expected_replica_ids must be a non-empty unique inventory")
            self._expected_replica_ids = ids
        self._artifact_digest: str | None = None
        self._clock = clock or _now_iso
        self._max_evidence_age = max_evidence_age
        self._ledger = ledger
        self._state = LifecycleState.proposed
        self._events: tuple[LifecycleEvent, ...] = ()
        self._gates: tuple[AuthorizedGate, ...] = ()
        self._sbom: SbomEvidence | None = None
        self._deployment: DeploymentEvidence | None = None
        self._runtime_replicas: tuple[RuntimeReplica, ...] = ()
        self._post_scan: PostDeploymentScan | None = None
        self._append("lifecycle_transition", None, LifecycleState.proposed, reason="finding proposed")

    @property
    def state(self) -> LifecycleState:
        return self._state

    @property
    def lifecycle_state(self) -> LifecycleState:
        """Compatibility name used by per-finding attestations."""

        return self._state

    @property
    def current_state(self) -> LifecycleState:
        return self._state

    @property
    def is_compliant(self) -> bool:
        return self._state == LifecycleState.verified_remediated

    @property
    def reopened(self) -> bool:
        return not self.is_compliant and any(event.event_type == "remediation_regressed" for event in self._events)

    @property
    def events(self) -> tuple[LifecycleEvent, ...]:
        return self._events

    @property
    def history(self) -> tuple[LifecycleEvent, ...]:
        return self._events

    @property
    def fixed_commit(self) -> str | None:
        return self._fixed_commit

    @property
    def package(self) -> str | None:
        return self._package

    @property
    def cve(self) -> str | None:
        return self._cve

    @property
    def expected_replica_ids(self) -> tuple[str, ...] | None:
        return self._expected_replica_ids

    @property
    def artifact_digest(self) -> str | None:
        return self._artifact_digest

    def authorize(self, gates: Iterable[AuthorizedGate] | LifecycleEvidence) -> LifecycleState:
        """Advance proposed → authorized after successful authorized gates."""

        self._require_state(LifecycleState.proposed)
        values = gates.authorized_gates if isinstance(gates, LifecycleEvidence) else tuple(gates)
        normalized: list[AuthorizedGate] = []
        for value in values:
            if isinstance(value, AuthorizedGate):
                normalized.append(value)
                continue
            # A proposal-level VerificationGate is deliberately not promoted
            # to an independently authorized gate.  Only the dedicated,
            # immutable AuthorizedGate contract may authorize a lifecycle.
            try:
                normalized.append(AuthorizedGate.model_validate(value))
            except ValidationError as exc:
                raise InsufficientLifecycleEvidence("authorization requires independently authorized gates") from exc
        values = tuple(normalized)
        self._require_fresh(values)
        gate_ids = tuple(value.id for value in values)
        if set(gate_ids) != _REQUIRED_GATE_IDS or len(gate_ids) != len(_REQUIRED_GATE_IDS):
            raise InsufficientLifecycleEvidence(
                "exact build, tests, security-probe, and dependency-rescan gates are required"
            )
        if any(value.status != "passed" or not value.authorized for value in values):
            raise InsufficientLifecycleEvidence("all authorization gates must be passed and authorized")
        # Canonical ordering makes the authorization record deterministic and
        # prevents a later caller from swapping or dropping a gate.
        self._gates = tuple(sorted(values, key=lambda value: value.id))
        self._append("lifecycle_transition", LifecycleState.proposed, LifecycleState.authorized, evidence=self._gates)
        return self._state

    def merge(self) -> LifecycleState:
        """Advance authorized → merged; authorization alone cannot merge."""

        self._require_state(LifecycleState.authorized)
        self._append("lifecycle_transition", LifecycleState.authorized, LifecycleState.merged)
        return self._state

    def build(self, fixed_commit: str, artifact_digest: str) -> LifecycleState:
        """Advance merged → built and bind the exact commit and artifact."""

        self._require_state(LifecycleState.merged)
        commit = _digest(fixed_commit, name="fixed_commit")
        artifact = _artifact(artifact_digest)
        if self._fixed_commit is not None and self._fixed_commit != commit:
            raise InsufficientLifecycleEvidence("fixed commit conflicts with the authorized proposal")
        self._fixed_commit = commit
        self._artifact_digest = artifact
        self._append("lifecycle_transition", LifecycleState.merged, LifecycleState.built, evidence={"fixed_commit": commit, "artifact_digest": artifact})
        return self._state

    def deploy(self, deployment: DeploymentEvidence | Mapping[str, Any]) -> LifecycleState:
        """Advance built → deployed only for a completed fixed-artifact rollout."""

        self._require_state(LifecycleState.built)
        value = deployment if isinstance(deployment, DeploymentEvidence) else DeploymentEvidence.model_validate(deployment)
        self._require_fresh((value,))
        self._require_fact_binding(value, "deployment")
        if value.status != "completed":
            raise InsufficientLifecycleEvidence("deployment is not completed")
        if value.artifact_digest != self._artifact_digest:
            raise InsufficientLifecycleEvidence("deployment artifact conflicts with the built artifact")
        self._deployment = value
        self._append("lifecycle_transition", LifecycleState.built, LifecycleState.deployed, evidence=value)
        return self._state

    def verify_remediated(self, evidence: LifecycleEvidence | Mapping[str, Any] | None = None, **facts: Any) -> LifecycleState:
        """Advance deployed → verified_remediated only if every fact agrees."""

        self._require_state(LifecycleState.deployed)
        value = self._coerce_evidence(evidence, facts)
        self._check_complete_evidence(value)
        self._sbom = value.sbom
        self._runtime_replicas = value.runtime_replicas
        self._post_scan = value.post_deployment_scan
        self._append("lifecycle_transition", LifecycleState.deployed, LifecycleState.verified_remediated, evidence=value)
        return self._state

    def advance(self, target: LifecycleState | str, evidence: Any = None, **kwargs: Any) -> LifecycleState:
        """Small adapter-friendly dispatcher for sequential state changes."""

        target = LifecycleState(target)
        if target == LifecycleState.authorized:
            if isinstance(evidence, Mapping):
                evidence = evidence.get("gates", evidence.get("authorized_gates", ()))
            return self.authorize(evidence if evidence is not None else kwargs.get("gates", ()))
        if target == LifecycleState.merged:
            return self.merge()
        if target == LifecycleState.built:
            if evidence is None and not kwargs:
                raise InsufficientLifecycleEvidence("build requires fixed commit and artifact digest")
            payload = evidence if isinstance(evidence, Mapping) else kwargs
            return self.build(payload["fixed_commit"], payload["artifact_digest"])
        if target == LifecycleState.deployed:
            return self.deploy(evidence if evidence is not None else kwargs)
        if target == LifecycleState.verified_remediated:
            return self.verify_remediated(evidence, **kwargs)
        if target == LifecycleState.proposed and self._state == LifecycleState.proposed:
            return self._state
        raise InvalidLifecycleTransition(f"cannot advance {self._state.value} to {target.value}")

    def record_regression(self, reason: str, evidence: LifecycleEvidence | Mapping[str, Any] | None = None) -> LifecycleState:
        """Append a regression and reopen the finding.

        The current compliant state is invalidated, but no prior event is
        modified.  A reopened finding returns to ``proposed`` so it cannot be
        mistaken for a current production claim.
        """

        if not reason:
            raise ValueError("regression reason is required")
        payload: Any = evidence
        if evidence is not None and not isinstance(evidence, LifecycleEvidence):
            try:
                payload = LifecycleEvidence.model_validate(_normalize_fact_names(evidence))
            except ValidationError:
                # The regression event remains useful even when the current
                # adapter payload is malformed; never let corrupt evidence
                # suppress reopening or mutate prior history.
                payload = None
        self._state = LifecycleState.proposed
        self._append("remediation_regressed", self._events[-1].to_state if self._events else None, LifecycleState.proposed, evidence=payload, reason=reason)
        return self._state

    def reconcile(self, evidence: LifecycleEvidence | Mapping[str, Any]) -> LifecycleState:
        """Reconcile a complete current snapshot, reopening on any uncertainty.

        Reconciliation is fail-closed: malformed, missing, stale, partial,
        or otherwise contradictory current evidence is itself a regression.
        This prevents a probe that simply omits an old replica or scan from
        preserving a prior compliant claim.
        """

        try:
            value = self._coerce_evidence(evidence, {})
        except (InsufficientLifecycleEvidence, TypeError, ValueError) as exc:
            return self.record_regression(f"current evidence is corrupt or incomplete: {exc}")
        try:
            self._check_complete_evidence(value)
        except InsufficientLifecycleEvidence as exc:
            reasons = self._regression_reasons(value)
            return self.record_regression("; ".join(reasons) if reasons else str(exc), value)
        return self._state

    # Friendly aliases for reconciliation adapters.
    observe = reconcile
    reopen = record_regression
    regress = record_regression
    observe_regression = record_regression
    transition = advance

    def _require_state(self, expected: LifecycleState) -> None:
        if self._state != expected:
            raise InvalidLifecycleTransition(f"expected {expected.value}, current state is {self._state.value}")

    def _require_fresh(self, facts: Iterable[LifecycleFact]) -> None:
        now_value = self._clock()
        now = _as_datetime(now_value if isinstance(now_value, str) else now_value.isoformat())
        for fact in facts:
            observed = _as_datetime(fact.observed_at)
            if observed > now or now - observed > self._max_evidence_age:
                raise InsufficientLifecycleEvidence("lifecycle evidence is stale")

    def _coerce_evidence(
        self,
        evidence: LifecycleEvidence | Mapping[str, Any] | None,
        facts: Mapping[str, Any],
    ) -> LifecycleEvidence:
        try:
            if evidence is None:
                payload: Mapping[str, Any] = _normalize_fact_names(facts)
            elif isinstance(evidence, LifecycleEvidence):
                if facts:
                    raise TypeError("facts cannot be combined with evidence")
                return evidence
            else:
                payload = dict(evidence)
                payload.update(_normalize_fact_names(facts))
                payload = _normalize_fact_names(payload)
            return LifecycleEvidence.model_validate(payload)
        except (ValidationError, TypeError, ValueError) as exc:
            raise InsufficientLifecycleEvidence("lifecycle evidence is corrupt or incomplete") from exc

    def _require_fact_binding(self, fact: Any, label: str) -> None:
        expected = {
            "finding_id": self.finding_id,
            "package": self._package,
            "cve": self._cve,
        }
        if any(expected[name] is None for name in ("package", "cve")):
            raise InsufficientLifecycleEvidence(f"{label} is not bound to a package and CVE")
        for name, expected_value in expected.items():
            if getattr(fact, name, None) != expected_value:
                raise InsufficientLifecycleEvidence(f"{label} is not bound to this finding/package/CVE")

    def _check_complete_evidence(self, value: LifecycleEvidence) -> None:
        self._require_fact_binding(value, "lifecycle evidence")
        if value.fixed_commit != self._fixed_commit:
            raise InsufficientLifecycleEvidence("fixed commit is missing or conflicts with the built commit")
        if value.artifact_digest != self._artifact_digest:
            raise InsufficientLifecycleEvidence("artifact digest is missing or conflicts with the built artifact")
        _artifact(value.artifact_digest)
        facts: tuple[LifecycleFact, ...] = (
            value,
            *value.authorized_gates,
            *(fact for fact in (value.sbom, value.deployment) if fact is not None),
            *value.runtime_replicas,
            *(fact for fact in (value.post_deployment_scan,) if fact is not None),
        )
        self._require_fresh(facts)
        if not value.authorized_gates or any(g.status != "passed" or not g.authorized for g in value.authorized_gates):
            raise InsufficientLifecycleEvidence("authorized gates are not all successful")
        canonical_gates = tuple(sorted(value.authorized_gates, key=lambda gate: gate.id))
        if set(gate.id for gate in canonical_gates) != _REQUIRED_GATE_IDS or len(canonical_gates) != len(_REQUIRED_GATE_IDS):
            raise InsufficientLifecycleEvidence("exact authorized gate set is required")
        if canonical_gates != self._gates:
            raise InsufficientLifecycleEvidence("verification gates conflict with the authorization record")
        if value.sbom is None:
            raise InsufficientLifecycleEvidence("SBOM evidence is missing")
        self._require_fact_binding(value.sbom, "SBOM evidence")
        _artifact(value.sbom.artifact_digest)
        if value.sbom.artifact_digest != self._artifact_digest or value.sbom.vulnerable_artifact_present:
            raise InsufficientLifecycleEvidence("SBOM does not prove absence of the vulnerable artifact")
        if value.deployment is None:
            raise InsufficientLifecycleEvidence("deployment evidence is missing")
        self._require_fact_binding(value.deployment, "deployment evidence")
        _artifact(value.deployment.artifact_digest)
        if value.deployment.status != "completed" or value.deployment.artifact_digest != self._artifact_digest:
            raise InsufficientLifecycleEvidence("deployment evidence is missing or conflicts with the artifact")
        if self._expected_replica_ids is None:
            raise InsufficientLifecycleEvidence("expected runtime replica inventory is missing")
        observed_ids = tuple(replica.replica_id for replica in value.runtime_replicas)
        if set(observed_ids) != set(self._expected_replica_ids) or len(observed_ids) != len(self._expected_replica_ids):
            raise InsufficientLifecycleEvidence("runtime replica inventory is incomplete or contains duplicates")
        if tuple(value.expected_replica_ids) != self._expected_replica_ids:
            raise InsufficientLifecycleEvidence("expected runtime replica inventory is missing or conflicts")
        for replica in value.runtime_replicas:
            self._require_fact_binding(replica, "runtime evidence")
            _artifact(replica.artifact_digest)
        if any(not replica.healthy or replica.artifact_digest != self._artifact_digest for replica in value.runtime_replicas):
            raise InsufficientLifecycleEvidence("every runtime replica must be healthy on the fixed artifact")
        scan = value.post_deployment_scan
        if scan is None:
            raise InsufficientLifecycleEvidence("post-deployment scan evidence is missing")
        self._require_fact_binding(scan, "post-deployment scan")
        _artifact(scan.artifact_digest)
        if scan.status != "clean" or scan.artifact_digest != self._artifact_digest:
            raise InsufficientLifecycleEvidence("post-deployment scan is missing or not clean")
        if value.vulnerable_rollback or self._regression_reasons(value):
            raise InsufficientLifecycleEvidence("vulnerable rollback or runtime divergence is present")

    def _regression_reasons(self, value: LifecycleEvidence) -> list[str]:
        reasons: list[str] = []
        if value.vulnerable_rollback:
            reasons.append("vulnerable rollback observed")
        if value.vulnerable_digests:
            reasons.append("vulnerable digest observed")
        if value.sbom and value.sbom.vulnerable_artifact_present:
            reasons.append("vulnerable artifact present in SBOM")
        if value.deployment and (value.deployment.status != "completed" or (self._artifact_digest and value.deployment.artifact_digest != self._artifact_digest)):
            reasons.append("deployment diverged from the fixed artifact")
        if self._artifact_digest and value.runtime_replicas and any(replica.artifact_digest != self._artifact_digest for replica in value.runtime_replicas):
            reasons.append("runtime replica is on an old or divergent digest")
        if value.post_deployment_scan and value.post_deployment_scan.status == "positive":
            reasons.append("post-deployment scan is positive")
        return reasons

    def _append(
        self,
        event_type: Literal["lifecycle_transition", "remediation_regressed"],
        from_state: LifecycleState | str | None,
        to_state: LifecycleState,
        *,
        evidence: Any = None,
        reason: str | None = None,
    ) -> None:
        previous_hash = self._events[-1].event_hash if self._events else None
        timestamp = self._clock()
        timestamp = timestamp if isinstance(timestamp, str) else timestamp.isoformat()
        event_data: dict[str, Any] = {
            "sequence": len(self._events),
            "finding_id": self.finding_id,
            "event_type": event_type,
            "from_state": from_state.value if isinstance(from_state, LifecycleState) else from_state,
            "to_state": to_state.value,
            "timestamp": timestamp,
            "evidence_hash": sha256_json(evidence) if evidence is not None else None,
            "reason": reason,
            "previous_hash": previous_hash,
        }
        event_data["event_hash"] = _event_hash(event_data)
        event = LifecycleEvent.model_validate(event_data)
        self._events = (*self._events, event)
        self._state = to_state
        if self._ledger is not None:
            # The lifecycle event remains the canonical state-machine record;
            # the shared evidence ledger receives the same structured facts so
            # a run can be reconstructed alongside policy events.
            self._ledger.append(event_type, self.finding_id, event_data)


def pyyaml_fixture_evidence() -> LifecycleEvidence:
    """Return the complete, explicitly simulated PyYAML success fixture."""

    timestamp = "2026-01-01T00:00:00Z"
    digest = "sha256:" + "a" * 64
    finding_id = "F-40219"
    package = "PyYAML"
    cve = "CVE-2020-14343"
    replica_ids = ("report-worker-a", "report-worker-b")
    gates = tuple(
        AuthorizedGate(id=gate, status="passed", authorized=True, observed_at=timestamp)
        for gate in ("build", "tests", "security-probe", "dependency-rescan")
    )
    return LifecycleEvidence(
        finding_id=finding_id,
        package=package,
        cve=cve,
        fixed_commit="fixture-pyyaml-fixed-commit",
        artifact_digest=digest,
        authorized_gates=gates,
        sbom=SbomEvidence(
            finding_id=finding_id,
            package=package,
            cve=cve,
            artifact_digest=digest,
            vulnerable_artifact="PyYAML==5.3.1",
            vulnerable_artifact_present=False,
            observed_at=timestamp,
        ),
        deployment=DeploymentEvidence(
            finding_id=finding_id,
            package=package,
            cve=cve,
            deployment_id="fixture-pyyaml-deployment",
            status="completed",
            artifact_digest=digest,
            observed_at=timestamp,
        ),
        runtime_replicas=tuple(
            RuntimeReplica(
                finding_id=finding_id,
                package=package,
                cve=cve,
                replica_id=replica_id,
                artifact_digest=digest,
                observed_at=timestamp,
            )
            for replica_id in replica_ids
        ),
        expected_replica_ids=replica_ids,
        post_deployment_scan=PostDeploymentScan(
            finding_id=finding_id,
            package=package,
            cve=cve,
            scan_id="fixture-pyyaml-post-deploy-scan",
            status="clean",
            artifact_digest=digest,
            observed_at=timestamp,
        ),
        observed_at=timestamp,
    )


def build_pyyaml_fixture_lifecycle() -> RemediationLifecycle:
    """Run the complete fixture path without touching either target service."""

    timestamp = "2026-01-01T00:00:00Z"
    lifecycle = RemediationLifecycle(
        "F-40219",
        package="PyYAML",
        cve="CVE-2020-14343",
        fixed_commit="fixture-pyyaml-fixed-commit",
        expected_replica_ids=("report-worker-a", "report-worker-b"),
        clock=lambda: timestamp,
    )
    evidence = pyyaml_fixture_evidence()
    lifecycle.authorize(evidence.authorized_gates)
    lifecycle.merge()
    lifecycle.build(evidence.fixed_commit or "", evidence.artifact_digest or "")
    lifecycle.deploy(evidence.deployment or {})
    lifecycle.verify_remediated(evidence)
    return lifecycle


__all__ = [
    "AuthorizedGate", "DeploymentEvidence", "GateEvidence", "InvalidLifecycleTransition",
    "LifecycleError", "LifecycleEvent", "LifecycleEvidence", "LifecycleFact", "LifecycleState",
    "PostDeploymentScan", "RemediationEvidence", "RemediationLifecycle", "RuntimeEvidence",
    "RuntimeReplica", "SBOMEvidence", "ScanEvidence", "SbomEvidence", "InsufficientLifecycleEvidence",
    "build_pyyaml_fixture_lifecycle", "pyyaml_fixture_evidence",
]
