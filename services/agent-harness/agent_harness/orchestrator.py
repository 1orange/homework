"""Sequential finding evaluation with per-finding failure isolation.

The orchestrator owns the failure boundary between adapters and policy.  Adapter
failures mean that no trustworthy decision could be obtained and therefore must
never be represented as a policy rejection.  Once a verification report has
been obtained with a completed (``passed`` or ``failed``) status, it is handed
to policy unchanged; a failed gate is a genuine security decision.
"""

from __future__ import annotations

from datetime import datetime
from pathlib import Path
from typing import Any, Protocol

from agent_harness.boundaries import AdvisoryAdapter, ProvenanceVerifier, sha256_json
from agent_harness.evidence import (
    ApprovalBinding,
    EvidenceLedger,
    attestation_hash,
    create_approval_binding,
    write_attestation,
)
from agent_harness.models import (
    ChangeObservation, Finding, FindingFeed, FindingResult, InvalidFinding, ProposalContext,
    Provenance, RunResult, VerificationGate, VerificationReport,
)
from agent_harness.policy import evaluate
from agent_harness.policy_config import PolicyConfig


# The harness evaluates recorded fixture observations rather than a live
# checkout.  Keep that identity explicit and stable so two runs over the same
# fixtures produce the same approval commitment.
_FIXTURE_REPOSITORY_COMMIT = "fixture-repository-commit"


class ChangeObserver(Protocol):
    """Independently observe the proposed repository change."""

    def observe(self, finding: Finding, proposal: object) -> ChangeObservation: ...


class VerificationRunner(Protocol):
    """Run the independent verification gates for one proposal."""

    def verify(self, finding: Finding, proposal: object, changes: ChangeObservation) -> VerificationReport: ...


class ProposalAgent(Protocol):
    """Agent seam for bounded proposal generation."""

    def propose(self, context: ProposalContext): ...


class Harness:
    def __init__(
        self,
        verifier: ProvenanceVerifier,
        advisory_adapter: AdvisoryAdapter,
        *,
        policy: PolicyConfig,
        agent: ProposalAgent,
        change_observer: ChangeObserver,
        verification_runner: VerificationRunner,
        repository_commit: object | None = None,
        artifact: object | None = None,
        artifact_hash: str | None = None,
    ) -> None:
        self.verifier = verifier
        if not isinstance(policy, PolicyConfig):
            raise ValueError("invalid policy configuration")
        self.policy = policy
        self.advisories = advisory_adapter
        self.agent = agent
        self.change_observer = change_observer
        self.verification_runner = verification_runner
        self.repository_commit = repository_commit
        self.artifact = artifact
        self.artifact_hash = artifact_hash

    def run(
        self,
        payload: dict,
        feed: FindingFeed,
        output_dir: Path,
        *,
        run_id: str = "run-fixture-001",
        timestamp: str = "2026-01-01T00:00:00Z",
        repository_commit: object | None = None,
        artifact: object | None = None,
        artifact_hash: str | None = None,
    ) -> RunResult:
        try:
            evaluated_at = datetime.fromisoformat(timestamp.replace("Z", "+00:00"))
        except ValueError as exc:
            raise ValueError("timestamp must be an ISO timestamp") from exc
        if evaluated_at.tzinfo is None:
            raise ValueError("timestamp must include a timezone")
        # Duplicate IDs would overwrite one another's attestations and make a
        # deterministic batch impossible.  This is a top-level input error,
        # rather than an isolated finding processing error.
        findings = self._ordered_findings(feed)
        output_dir.mkdir(parents=True, exist_ok=True)
        ledger = EvidenceLedger(output_dir / "ledger.jsonl", run_id=run_id, timestamp=timestamp)
        input_hash = sha256_json(payload)
        commit_value = self.repository_commit if repository_commit is None else repository_commit
        if commit_value is None:
            # A custom observer may expose the identity as an adapter fact;
            # otherwise use the explicit offline fixture identity.
            commit_value = getattr(self.change_observer, "repository_commit", None) or _FIXTURE_REPOSITORY_COMMIT
        artifact_value = self.artifact if artifact is None else artifact
        # Real adapters commonly provide a commit digest already; fixture
        # identities are ordinary strings and are hashed here.
        repository_commit_hash = self._fact_hash(commit_value, already_hash=True)
        resolved_artifact_hash = self._fact_hash(artifact_value) if artifact_value is not None else None
        selected_artifact_hash = artifact_hash if artifact_hash is not None else self.artifact_hash
        if selected_artifact_hash is not None:
            resolved_artifact_hash = self._fact_hash(selected_artifact_hash, already_hash=True)

        # Provenance is shared by the feed, but an invalid/unavailable verifier
        # result still gets an attestation for every finding.  This preserves
        # per-finding isolation and gives operators a clear exit-1 run rather
        # than losing the whole batch before evidence is written.
        provenance: Provenance | None = None
        provenance_error: Exception | None = None
        try:
            self._assert_payload_feed_binding(payload, feed)
            candidate = self.verifier.verify(payload)
            candidate_provenance = candidate if isinstance(candidate, Provenance) else Provenance.model_validate(candidate)
            if not candidate_provenance.verified:
                raise ValueError("provenance is not verified")
            # For scanner-feed envelopes the verifier's digest must be the
            # exact bytes that are subsequently processed.  Metadata-only
            # adapter callers retain the legacy test seam, but the CLI path is
            # cryptographically bound end-to-end.
            if {"generated", "scanner", "findings"} <= set(payload):
                expected_digest = sha256_json(payload)
                if candidate_provenance.digest != expected_digest:
                    raise ValueError("provenance digest does not match payload")
            provenance = candidate_provenance
        except Exception as exc:  # adapter boundary; never expose raw details
            provenance_error = exc

        ledger.append(
            "run_started",
            None,
            {
                "finding_count": len(findings),
                "input_hash": input_hash,
                "provenance_hash": sha256_json(provenance.model_dump(mode="json")) if provenance else None,
                "provenance_status": "verified" if provenance else "error",
                "policy_digest": self.policy.digest,
            },
        )
        results: list[FindingResult] = []
        for finding in findings:
            source_index = self._finding_source_index(feed, finding)
            binding: ApprovalBinding | None = None
            if isinstance(finding, InvalidFinding):
                result = self._processing_error(
                    finding.finding_id,
                    ledger,
                    stage="finding_validation",
                    exc=None,
                    error_type=finding.error,
                )
            elif provenance_error is not None or provenance is None:
                result = self._processing_error(finding, ledger, stage="provenance", exc=provenance_error)
            else:
                result, binding = self._evaluate_one(
                    finding,
                    provenance,
                    ledger,
                    input_hash=self._finding_input_hash(payload, feed, finding, source_index),
                    repository_commit_hash=repository_commit_hash,
                    artifact_hash=resolved_artifact_hash,
                    evaluated_at=evaluated_at,
                )
            results.append(result)
            if isinstance(finding, InvalidFinding):
                input_hash = finding.input_hash
                finding_id = finding.finding_id
            else:
                input_hash = self._finding_input_hash(payload, feed, finding, source_index)
                finding_id = finding.id
            attestation = {
                "run_id": run_id,
                "finding_id": finding_id,
                "run_status": result.run_status,
                "decision": result.decision.value if result.decision else None,
                "primary_reason": result.primary_reason,
                "rules": [rule.model_dump(mode="json") for rule in result.rules],
                "lifecycle_state": result.lifecycle_state,
                "proposal_hash": result.proposal_hash,
                # This is the hash of the raw, authenticated scanner item,
                # not a normalized model dump.  A malformed item therefore
                # remains bound without ever being echoed into evidence.
                "input_hash": input_hash,
                "input_index": source_index,
                "provenance_hash": provenance.digest if provenance else None,
                "policy_digest": self.policy.digest,
                "priority": result.priority,
                "error": result.error,
                # Keep failures explicit and bounded.  In particular, no
                # partial/operational result is represented as an approval.
                "evidence_status": "bound" if binding is not None else "processing_error",
                "processing_error": (
                    {"stage": result.error_stage, "error_type": result.error}
                    if binding is None and result.error else None
                ),
            }
            if binding is not None:
                fact_hashes = dict(binding.fact_hashes)
                attestation.update({
                    "finding_hash": fact_hashes["finding"],
                    "raw_input_hash": fact_hashes["raw_input"],
                    "provenance_hash": fact_hashes["provenance"],
                    "advisory_hash": fact_hashes["advisory"],
                    "repository_commit_hash": fact_hashes["repository_commit"],
                    "proposal_hash": fact_hashes["proposal"],
                    "observed_diff_hash": fact_hashes["observed_diff"],
                    "verification_hash": fact_hashes["verification"],
                    "policy_hash": fact_hashes["policy"],
                    "policy_result_hash": fact_hashes["policy"],
                    "policy_config_hash": fact_hashes["policy_config"],
                    "policy_digest": self.policy.digest,
                    "fact_hashes": fact_hashes,
                    "binding_hash": binding.binding_hash,
                    "approval_binding": binding.model_dump(),
                })
                if "artifact" in fact_hashes:
                    attestation["artifact_hash"] = fact_hashes["artifact"]
            else:
                # The raw item hash remains useful for malformed scanner
                # records, but no incomplete fact set may look authoritative.
                attestation["fact_hashes"] = {}
                attestation["binding_hash"] = None
                attestation["approval_binding"] = None
            attestation_path = write_attestation(
                output_dir / "attestations", finding_id, attestation
            )
            ledger.append(
                "attestation_recorded",
                finding_id,
                {
                    "attestation_hash": attestation_hash(attestation),
                    "attestation_name": attestation_path.name,
                },
            )
        status = "error" if any(item.run_status == "error" for item in results) else "completed"
        final_hash = ledger.append("run_completed", None, {"run_status": status, "finding_count": len(results), "last_event_hash": ledger.previous_hash})
        run = RunResult(
            run_id=run_id,
            run_status=status,
            findings=tuple(results),
            ledger_path=str(ledger.path),
            ledger_final_hash=final_hash,
            ledger_event_count=ledger.sequence,
        )
        (output_dir / "run.json").write_text(run.model_dump_json(indent=2) + "\n", encoding="utf-8")
        return run

    @staticmethod
    def _assert_payload_feed_binding(payload: dict, feed: FindingFeed) -> None:
        """Ensure a feed cannot be swapped after its verified envelope is read.

        ``Harness.run`` historically accepted arbitrary adapter metadata in a
        few unit callers.  The cryptographic binding is mandatory whenever the
        input has the scanner-feed envelope shape used by the CLI; metadata-only
        test adapters remain compatible.
        """
        if not {"generated", "scanner", "findings"} <= set(payload):
            return

        def without_none(value: object) -> object:
            if isinstance(value, dict):
                return {key: without_none(item) for key, item in value.items() if item is not None}
            if isinstance(value, list):
                return [without_none(item) for item in value]
            return value

        payload_shape = without_none(payload)
        raw_findings = getattr(feed, "_raw_findings", ())
        if len(raw_findings) == len(feed.findings):
            feed_findings = list(raw_findings)
        else:
            # Programmatically-created feeds do not have scanner bytes.  A
            # malformed sentinel cannot safely be reconstructed in that case,
            # so reject the attempted scanner-envelope binding.
            if any(isinstance(item, InvalidFinding) for item in feed.findings):
                raise ValueError("verified payload is not the processed feed")
            feed_findings = [item.model_dump(mode="json", exclude_none=True) for item in feed.findings]
        feed_shape = without_none({
            "generated": feed.generated,
            "scanner": feed.scanner,
            "findings": feed_findings,
        })
        if sha256_json(payload_shape) != sha256_json(feed_shape):
            raise ValueError("verified payload is not the processed feed")

    @staticmethod
    def _ordered_findings(feed: FindingFeed) -> list[Finding | InvalidFinding]:
        findings = list(feed.findings)
        ids = [finding.finding_id if isinstance(finding, InvalidFinding) else finding.id for finding in findings]
        if len(ids) != len(set(ids)):
            raise ValueError("finding IDs must be unique")
        return sorted(
            findings,
            key=lambda item: item.finding_id if isinstance(item, InvalidFinding) else item.id,
        )

    @staticmethod
    def _finding_source_index(feed: FindingFeed, finding: Finding | InvalidFinding) -> int:
        if isinstance(finding, InvalidFinding):
            return finding.source_index
        for index, candidate in enumerate(feed.findings):
            if candidate is finding:
                return index
        # A feed assembled by a caller may copy models while retaining the
        # same stable ID.  Duplicate IDs are rejected before this point, so a
        # value match is unambiguous.
        for index, candidate in enumerate(feed.findings):
            if isinstance(candidate, Finding) and candidate.id == finding.id:
                return index
        raise ValueError("finding is not present in feed")

    @staticmethod
    def _finding_input_hash(payload: dict, feed: FindingFeed, finding: Finding, source_index: int) -> str:
        if {"generated", "scanner", "findings"} <= set(payload):
            raw_findings = payload.get("findings")
            if isinstance(raw_findings, list) and source_index < len(raw_findings):
                return sha256_json(raw_findings[source_index])
        raw_findings = getattr(feed, "_raw_findings", ())
        if len(raw_findings) == len(feed.findings):
            return sha256_json(raw_findings[source_index])
        return sha256_json(finding.model_dump(mode="json"))

    @staticmethod
    def _fact_hash(value: object, *, already_hash: bool = False) -> str:
        if already_hash and isinstance(value, str) and len(value) == 64 and all(char in "0123456789abcdef" for char in value):
            return value
        return sha256_json(value)

    def _evaluate_one(
        self,
        finding: Finding,
        provenance: Provenance,
        ledger: EvidenceLedger,
        *,
        input_hash: str,
        repository_commit_hash: str,
        artifact_hash: str | None,
        evaluated_at: datetime,
    ) -> tuple[FindingResult, ApprovalBinding | None]:
        stage = "advisory_enrichment"
        try:
            advisory = self.advisories.enrich(
                finding.cve, finding.package, finding.ecosystem
            )
            ecosystem = advisory.ecosystem
            advisory_hash = sha256_json(advisory.model_dump(mode="json"))
            ledger.append("advisory_enriched", finding.id, {
                "advisory_hash": advisory_hash,
                "affected": advisory.affected,
                "fixed_versions": advisory.fixed_versions,
                "scanner_claim": {
                    "issuer": "authenticated_scanner_finding",
                    "cve": finding.cve,
                    "package": finding.package,
                    "installed_version": finding.installed_version,
                    "fixed_version": finding.fixed_version,
                },
                # ``source_claims`` is intentionally represented under a
                # neutral evidence key: the last-resort evidence redactor
                # treats keys containing ``source`` as raw source material.
                "advisory_claims": [
                    {
                        # Evidence redaction intentionally removes raw/source
                        # keys.  These aliases carry the structured claim and
                        # issuer identity without being mistaken for raw input.
                        "issuer": claim.source,
                        "fixed_versions": claim.fixed_versions,
                        "affected_ranges": claim.affected_ranges,
                        "affected": claim.affected,
                        "cvss_score": claim.cvss_score,
                        "cvss_vector": claim.cvss_vector,
                        "claim_text": claim.claim,
                    }
                    for claim in advisory.source_claims
                ],
            })
            stage = "proposal_generation"
            context = ProposalContext(
                finding=finding, advisory=advisory, provenance=provenance,
                allowed_transformations=self.policy.registered_transformations,
                allowed_verifications=self.policy.required_verification_gates,
            )
            proposal = self.agent.propose(context)
            proposal_hash = sha256_json(proposal.model_dump(mode="json"))
            ledger.append("proposal_recorded", finding.id, {"proposal_hash": proposal_hash, "transformation_id": proposal.transformation_id})
            stage = "change_observation"
            changes = self._observe_changes(finding, proposal)
            observed_diff_hash = sha256_json(changes.model_dump(mode="json"))
            stage = "verification"
            unknown_verifications = set(proposal.verification_ids) - set(self.policy.required_verification_gates)
            duplicate_verifications = len(proposal.verification_ids) != len(set(proposal.verification_ids))
            if unknown_verifications or duplicate_verifications:
                # This is a completed policy rejection, and no adapter is
                # called for an ID the registry does not authorize.
                verification = VerificationReport(gates=tuple(
                    VerificationGate(
                        id=verification_id,
                        status="failed" if verification_id in unknown_verifications else "passed",
                    )
                    for verification_id in proposal.verification_ids
                ))
            else:
                verification = self._run_verification(finding, proposal, changes)
            verification_hash = sha256_json(verification.model_dump(mode="json"))
            # A response that says the gate infrastructure was unavailable is
            # not evidence of a failed gate.  It cannot reach policy.
            operational_statuses = {"unavailable", "timeout", "corrupt"}
            if not verification.gates:
                raise ValueError("verification response has no gates")
            if any(gate.status in operational_statuses for gate in verification.gates):
                raise _OperationalVerificationError("verification infrastructure unavailable")
            policy = evaluate(
                finding, advisory, proposal, changes, verification,
                evaluated_at=evaluated_at, policy=self.policy,
            )
            policy_result_hash = sha256_json(policy.model_dump(mode="json"))
            policy_config_hash = self.policy.digest
            ledger.append("policy_evaluated", finding.id, {
                "decision": policy.decision.value,
                "primary_reason": policy.primary_reason,
                "priority": policy.priority,
                "rules": [rule.model_dump(mode="json") for rule in policy.rules],
                "policy_result_hash": policy_result_hash,
                "policy_hash": policy_result_hash,
                "policy_config_hash": policy_config_hash,
                "policy_digest": policy_config_hash,
            })
            # ``*_hash`` names intentionally use the existing evidence API's
            # pass-through form.  ``create_approval_binding`` strips the
            # suffix while preserving each already-computed digest.
            facts: dict[str, Any] = {
                "finding_hash": self._fact_hash(finding.model_dump(mode="json")),
                "raw_input_hash": input_hash,
                "provenance_hash": self._fact_hash(provenance.model_dump(mode="json")),
                "advisory_hash": advisory_hash,
                "repository_commit_hash": repository_commit_hash,
                "proposal_hash": proposal_hash,
                "observed_diff_hash": observed_diff_hash,
                "verification_hash": verification_hash,
                "policy_hash": policy_result_hash,
                "policy_config_hash": policy_config_hash,
            }
            if artifact_hash is not None:
                facts["artifact_hash"] = artifact_hash
            binding = create_approval_binding(facts)
            ledger.append("approval_binding_recorded", finding.id, {
                "fact_hashes": dict(binding.fact_hashes),
                "binding_hash": binding.binding_hash,
                "policy_digest": self.policy.digest,
            })
            result = FindingResult(
                finding_id=finding.id, run_status="completed", decision=policy.decision,
                # `accept` means authorization-eligible. Actual authorization
                # is a separate lifecycle transition backed by independent
                # approval evidence.
                primary_reason=policy.primary_reason, lifecycle_state="proposed",
                rules=policy.rules, proposal_hash=proposal_hash,
                binding_hash=binding.binding_hash,
                priority=policy.priority,
            )
            return result, binding
        except Exception as exc:  # isolate a single finding; do not expose input or secrets
            return self._processing_error(finding, ledger, stage=stage, exc=exc), None

    def _observe_changes(self, finding: Finding, proposal: object) -> ChangeObservation:
        observer = self.change_observer
        value = observer.observe(finding, proposal) if hasattr(observer, "observe") else observer(finding, proposal)  # type: ignore[operator]
        if isinstance(value, ChangeObservation):
            return value
        return ChangeObservation.model_validate(value)

    def _run_verification(self, finding: Finding, proposal: object, changes: ChangeObservation) -> VerificationReport:
        runner = self.verification_runner
        value = runner.verify(finding, proposal, changes) if hasattr(runner, "verify") else runner(finding, proposal, changes)  # type: ignore[operator]
        if isinstance(value, VerificationReport):
            return value
        try:
            return VerificationReport.model_validate(value)
        except Exception as exc:
            raise _OperationalVerificationError("verification response is corrupt") from exc

    def _processing_error(
        self,
        finding: Finding | str,
        ledger: EvidenceLedger,
        *,
        stage: str,
        exc: Exception | None,
        error_type: str | None = None,
    ) -> FindingResult:
        error_type = error_type or (type(exc).__name__ if exc is not None else "ProcessingError")
        finding_id = finding if isinstance(finding, str) else finding.id
        ledger.append(
            "finding_processing_error",
            finding_id,
            {"stage": stage, "error_type": error_type},
        )
        return FindingResult(
            finding_id=finding_id,
            run_status="error",
            decision=None,
            primary_reason=None,
            error=error_type,
            error_stage=stage,
        )


class _OperationalVerificationError(RuntimeError):
    """Verification could not complete, as opposed to a failed completed gate."""
