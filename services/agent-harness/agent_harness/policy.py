"""Pure, ordered authorization rules."""

from __future__ import annotations

import re
from datetime import datetime, timezone

from packaging.version import InvalidVersion, Version

from agent_harness.models import (
    Advisory, ChangeObservation, Decision, Finding, PolicyResult, Proposal,
    RuleEvaluation, VerificationReport,
)
from agent_harness.policy_config import PolicyConfig


_SERVICE_NAME = re.compile(r"[A-Za-z0-9][A-Za-z0-9._-]{0,127}")


def _service_relative_path(service: str, path: str) -> str | None:
    """Return a safe path relative to ``services/<service>``.

    A proposal path is untrusted data.  In particular, checking only the
    basename would let ``other-service/requirements.lock`` or ``C:\\...``
    masquerade as the proposal's dependency manifest.
    """
    if not service or not _SERVICE_NAME.fullmatch(service):
        return None
    normalized = path.replace("\\", "/")
    if (
        not normalized
        or re.match(r"^[A-Za-z]:[\\/]", normalized)
        or normalized.startswith(("/", "//"))
        or ".." in normalized.split("/")
        or "" in normalized.split("/")
        or "." in normalized.split("/")
    ):
        return None
    root = f"services/{service}/"
    if not normalized.startswith(root):
        return None
    relative = normalized[len(root):]
    return relative or None


def _is_test_path(relative: str) -> bool:
    """Identify test files so test-only changes can be routed to review."""
    parts = relative.split("/")
    name = parts[-1]
    return any(part.lower() in {"test", "tests", "testing"} for part in parts[:-1]) or bool(
        re.search(r"(?:^test[_-]|[_-]test\.|\.test\.)", name, re.IGNORECASE)
    )


def _is_source_path(relative: str) -> bool:
    """Identify source files for the explicitly reviewable source transforms."""
    return any(part.lower() in {"src", "source"} for part in relative.split("/")[:-1])


def _path_allowed(transformation: str, path: str, service: str, policy: PolicyConfig) -> bool:
    """Answer whether a declared path stays inside the trusted service boundary.

    The service name, transformation, and path come from the proposal, so this
    helper fails closed for traversal, cross-service, unknown, or unbounded
    paths.  ``True`` only means the path is structurally eligible; the diff
    rule still decides whether the observed change is safe, reviewable, or a
    rejection.
    """
    relative = _service_relative_path(service, path)
    if relative is None:
        return False
    normalized = path.replace("\\", "/")
    bounded_paths = policy.paths_for(transformation)
    if bounded_paths:
        return normalized in bounded_paths
    # Test additions are bounded to the proposal service.  They route to
    # review below, but must still be declared and cannot escape the service.
    if _is_test_path(relative):
        return True
    # Source additions are only a reviewable shape for explicitly unapproved
    # source transformations.  Registered dependency updates cannot smuggle
    # source edits through a manifest allowlist.
    if transformation in policy.review_only_transformations and _is_source_path(relative):
        return True
    if transformation in {
        "python-direct-dependency-update",
        *policy.review_only_transformations,
    }:
        name = normalized.rsplit("/", 1)[-1]
        return bool(re.fullmatch(r"(?:requirements(?:[-_.][A-Za-z0-9]+)*|pyproject|poetry)\.(?:txt|lock|toml)", name))
    if transformation in {"maven-direct-dependency-update", "maven-transitive-override"}:
        name = normalized.rsplit("/", 1)[-1]
        return bool(re.fullmatch(r"(?:pom\.xml|build\.gradle(?:\.kts)?|gradle\.properties)", name))
    # Unknown transformations are rejected by their own rule; keep the diff
    # rule fail-closed as well if it is called independently.
    return False


def _version(value: str, ecosystem: str = "maven") -> Version | tuple[int, ...] | None:
    """Parse an ecosystem version without inventing ordering for bad input."""
    if ecosystem == "pypi":
        try:
            return Version(value.strip())
        except (InvalidVersion, AttributeError):
            return None
    if not re.fullmatch(r"\d+(?:\.\d+)*", value.strip()):
        return None
    return tuple(int(part) for part in value.split("."))


def _same_version(left: str, right: str, ecosystem: str = "maven") -> bool:
    """Compare two versions using ecosystem semantics, conservatively on errors."""
    a, b = _version(left, ecosystem), _version(right, ecosystem)
    return left == right if a is None or b is None else a == b


def _versions_match(left: tuple[str, ...], right: tuple[str, ...], ecosystem: str) -> bool:
    """Check that two trusted fixed-version sets contain the same releases."""
    if len(left) != len(right):
        return False
    unmatched = list(right)
    for candidate in left:
        match = next((index for index, value in enumerate(unmatched)
                      if _same_version(candidate, value, ecosystem)), None)
        if match is None:
            return False
        unmatched.pop(match)
    return not unmatched


def _claim_consistent(finding: Finding, advisory: Advisory) -> bool:
    """Answer whether scanner and advisory claims agree on remediation facts.

    The finding and every advisory claim are trusted inputs for this comparison;
    affected status, the complete fixed-version set, affected ranges, and the
    finding's fixed version must agree.  ``True`` permits the target rule to
    continue, while ``False`` produces a review-only ``ADVISORY_CONFLICT``;
    it never silently discards a disagreeing source.
    """
    claims = advisory.source_claims
    if any(claim.affected != advisory.affected for claim in claims):
        return False
    if any(not _versions_match(advisory.fixed_versions, claim.fixed_versions, advisory.ecosystem)
           for claim in claims):
        return False
    if claims:
        ranges = {tuple(claim.affected_ranges) for claim in claims}
        if len(ranges) != 1:
            return False
    if advisory.fixed_versions:
        if finding.fixed_version is None or not any(
            _same_version(finding.fixed_version, fixed, advisory.ecosystem)
            for fixed in advisory.fixed_versions
        ):
            return False
    elif finding.fixed_version is not None:
        return False
    return True


def _identity_matches(finding: Finding, advisory: Advisory, proposal: Proposal) -> bool:
    """Check that proposal, finding, and advisory refer to one exact target.

    The finding and advisory identify the trusted subject; the proposal must
    match their ID, service, package, installed version, ecosystem, and CVE.
    A mismatch is a fail-closed ``IDENTITY_MISMATCH`` rejection, while a match
    permits the remaining policy rules to evaluate.
    """
    return (
        proposal.finding_id == finding.id and proposal.service == finding.service
        and proposal.package == finding.package and proposal.installed_version == finding.installed_version
        and proposal.ecosystem == advisory.ecosystem
        and (finding.ecosystem is None or proposal.ecosystem == finding.ecosystem)
        and advisory.cve == finding.cve
        and advisory.package == finding.package
    )


def _target_rule(finding: Finding, advisory: Advisory, proposal: Proposal) -> tuple[str, str]:
    """Check that the proposed target is a trusted, non-downgrade fix.

    The rule trusts the finding's installed version, advisory fixed versions
    and provenance, and the proposal's target/ecosystem.  Unparseable versions
    or a downgrade require review; an unproven or non-fixed target fails; a
    verified fixed target passes this rule.
    """
    target = _version(proposal.target_version, proposal.ecosystem)
    installed = _version(finding.installed_version, proposal.ecosystem)
    if target is None or installed is None:
        return ("review", "AMBIGUOUS_MAVEN_VERSION") if proposal.ecosystem == "maven" else ("review", "UNSUPPORTED_VERSION")
    if installed is not None and target is not None and target < installed:
        return "review", "DOWNGRADE"
    fixed = any(_version(v, proposal.ecosystem) == target for v in advisory.fixed_versions)
    if not fixed or (advisory.affected and not advisory.fixed_versions) or not advisory.provenance.verified:
        return "fail", "TARGET_NOT_PROVEN_SAFE"
    return "pass", "TARGET_UNAFFECTED"


def _transformation_rule(
    finding: Finding, proposal: Proposal, evaluated_at: datetime, policy: PolicyConfig
) -> tuple[str, str]:
    """Authorize only registered, bounded transformations.

    The proposal's transformation, verification IDs, paths, versions, and
    optional exception are the decision inputs, with ``evaluated_at`` defining
    exception freshness.  Unknown or expired claims fail; registered but
    transitive, major, downgraded, ambiguous, or explicitly unapproved work is
    reviewable; approved direct non-major and safe-YAML transforms pass.
    """
    transform = proposal.transformation_id
    exception = proposal.non_reachability_exception
    if exception is not None:
        expiry = exception.expires_at
        if expiry.tzinfo is None or expiry <= evaluated_at.astimezone(timezone.utc):
            return "fail", "INVALID_NON_REACHABILITY_EXCEPTION"
        return "review", "NON_REACHABILITY_EXCEPTION"
    if transform not in policy.registered_transformations:
        if transform in policy.review_only_transformations:
            return "review", "UNAPPROVED_SOURCE_MIGRATION"
        return "fail", "UNKNOWN_TRANSFORMATION"
    if set(proposal.verification_ids) - set(policy.required_verification_gates):
        return "fail", "UNKNOWN_VERIFICATION"
    if transform in {item.transformation_id for item in policy.bounded_source_paths}:
        valid = (
            proposal.ecosystem == "maven" and proposal.package == "org.yaml:snakeyaml"
            and set(proposal.intended_paths) <= policy.paths_for(transform)
            and bool(set(proposal.intended_paths))
        )
        return ("pass", "APPROVED_DETERMINISTIC_TRANSFORMATION") if valid else ("fail", "UNAPPROVED_SOURCE_MIGRATION")
    installed = _version(finding.installed_version, proposal.ecosystem)
    target = _version(proposal.target_version, proposal.ecosystem)
    if installed is None or target is None:
        return ("review", "AMBIGUOUS_MAVEN_VERSION") if proposal.ecosystem == "maven" else ("review", "UNSUPPORTED_VERSION")
    if transform == "maven-transitive-override" or finding.path != "direct":
        return "review", "TRANSITIVE_OVERRIDE"
    if target == installed:
        return "review", "NO_VERSION_CHANGE"
    if target < installed:
        return "review", "DOWNGRADE"
    target_major = target.release[0] if isinstance(target, Version) else target[0]
    installed_major = installed.release[0] if isinstance(installed, Version) else installed[0]
    if target_major != installed_major:
        return "review", "MAJOR_UPGRADE"
    if transform in {"python-direct-dependency-update", "maven-direct-dependency-update"}:
        return "pass", "DIRECT_NON_MAJOR_UPDATE"
    return "review", "TRANSFORMATION_REQUIRES_REVIEW"


def _diff_rule(
    changes: ChangeObservation, proposal: Proposal, policy: PolicyConfig
) -> tuple[str, str]:
    """Check that observed files and hashes match a bounded proposal.

    The observed change record and proposal paths are trusted only as typed
    evidence, not as permission to widen scope.  Missing or invalid hashes,
    protected/unrelated/undeclared files, control weakening, and out-of-bound
    paths fail; test changes receive review; a dependency-only bounded diff
    passes this rule.
    """
    observed, intended = set(changes.files), set(proposal.intended_paths)
    hashes_ok = set(changes.content_hashes) == observed and all(
        re.fullmatch(r"[0-9a-f]{64}", value) for value in changes.content_hashes.values()
    )
    if not observed or not hashes_ok:
        return "fail", "UNSAFE_DIFF"
    if any(not _path_allowed(proposal.transformation_id, path, proposal.service, policy)
           for path in observed | set(proposal.intended_paths)):
        return "fail", "UNSAFE_DIFF"
    if changes.protected_files:
        return "fail", "PROTECTED_CHANGE"
    if changes.weakened_controls:
        return "fail", "CONTROL_WEAKENING"
    if changes.unrelated_files:
        return "fail", "UNRELATED_CHANGE"
    if not observed <= intended:
        return "fail", "UNDECLARED_CHANGE"
    observed_text = " ".join(observed).lower()
    control_path = any(token in observed_text for token in (
        "credential", "secret", "branch-protection", ".github/workflows", "policy", "ci/",
    ))
    if control_path:
        return "fail", "PROTECTED_CHANGE"
    test_path = any(
        _is_test_path(relative)
        for path in observed
        if (relative := _service_relative_path(proposal.service, path)) is not None
    )
    if test_path and not changes.weakened_controls:
        return "review", "TEST_CHANGE_REQUIRES_REVIEW"
    unapproved_source = proposal.transformation_id in policy.review_only_transformations
    bounded_source = bool(policy.paths_for(proposal.transformation_id))
    if not changes.dependency_only and not bounded_source and not unapproved_source:
        return "fail", "UNSAFE_DIFF"
    if bounded_source and not observed <= policy.paths_for(proposal.transformation_id):
        return "fail", "UNSAFE_DIFF"
    return "pass", "BOUNDED_DIFF"


def _verification_rule(
    verification: VerificationReport, proposal: Proposal, policy: PolicyConfig
) -> tuple[str, str]:
    """Require the complete registered verification gate set to pass.

    Declared proposal IDs and observed gate IDs are compared as typed inputs.
    Unknown or duplicate gates and any missing or failed required gate fail;
    only the exact set of passed build, test, security-probe, and rescan gates
    passes this rule.
    """
    gates = tuple(verification.gates)
    declared, ids = set(proposal.verification_ids), [gate.id for gate in gates]
    required = set(policy.required_verification_gates)
    if declared - required or set(ids) - required:
        return "fail", "UNKNOWN_VERIFICATION"
    if len(proposal.verification_ids) != len(declared):
        return "fail", "DUPLICATE_VERIFICATION"
    if declared != required or set(ids) != required or len(ids) != len(set(ids)):
        return "fail", "VERIFICATION_FAILED"
    if any(gate.status != "passed" for gate in gates):
        return "fail", "VERIFICATION_FAILED"
    return "pass", "ALL_GATES_PASSED"


def _priority(finding: Finding, advisory: Advisory) -> str:
    """Assign routing urgency without changing the authorization decision.

    CVSS score, severity, reachability, and SLA timing are trusted routing
    facts.  The result is ``urgent``, ``high``, ``normal``, or ``low`` only;
    priority never turns a review or rejection into an approval.
    """
    score = advisory.cvss_score or 0
    if finding.reachability in {"unreachable", False} and score < 9 and finding.sla_days_remaining > 0:
        return "normal"
    if score >= 9 or finding.sla_days_remaining <= 0:
        return "urgent"
    if score >= 7 or finding.severity in {"high", "critical"}:
        return "high"
    return "normal" if finding.severity == "medium" else "low"


def evaluate(finding: Finding, advisory: Advisory, proposal: Proposal,
             changes: ChangeObservation, verification: VerificationReport, *,
             evaluated_at: datetime, policy: PolicyConfig) -> PolicyResult:
    """Evaluate normalized inputs in a stable six-rule order.

    Identity, advisory consistency, target safety, transformation
    authorization, bounded diff, and verification gates are evaluated in that
    order.  A fail yields ``reject``; otherwise any review yields ``review``;
    only six passing rules yield ``accept``.  The primary reason is selected
    from the explicit reject/review precedence lists, so reporting remains
    deterministic even when several rules disagree.
    """
    if evaluated_at.tzinfo is None:
        raise ValueError("evaluated_at must include a timezone")
    if not isinstance(policy, PolicyConfig):
        raise ValueError("invalid policy configuration")
    rules: list[RuleEvaluation] = []
    identity = _identity_matches(finding, advisory, proposal)
    rules.append(RuleEvaluation(rule="exact_identity", outcome="pass" if identity else "fail", reason="IDENTITY_MATCH" if identity else "IDENTITY_MISMATCH"))
    consistent = _claim_consistent(finding, advisory)
    rules.append(RuleEvaluation(rule="advisory_consistency", outcome="pass" if consistent else "review", reason="ADVISORY_MATCH" if consistent else "ADVISORY_CONFLICT"))
    outcome, reason = _target_rule(finding, advisory, proposal)
    rules.append(RuleEvaluation(rule="trusted_unaffected_target", outcome=outcome, reason=reason))
    outcome, reason = _transformation_rule(finding, proposal, evaluated_at, policy)
    rules.append(RuleEvaluation(rule="allowed_transformation", outcome=outcome, reason=reason))
    outcome, reason = _diff_rule(changes, proposal, policy)
    rules.append(RuleEvaluation(rule="bounded_dependency_diff", outcome=outcome, reason=reason))
    outcome, reason = _verification_rule(verification, proposal, policy)
    rules.append(RuleEvaluation(rule="verification_gates", outcome=outcome, reason=reason))

    decision = Decision.reject if any(r.outcome == "fail" for r in rules) else Decision.review if any(r.outcome == "review" for r in rules) else Decision.accept
    precedence = {
        Decision.reject: ("UNKNOWN_TRANSFORMATION", "UNKNOWN_VERIFICATION", "DUPLICATE_VERIFICATION", "IDENTITY_MISMATCH", "TARGET_NOT_PROVEN_SAFE", "INVALID_NON_REACHABILITY_EXCEPTION", "PROTECTED_CHANGE", "CONTROL_WEAKENING", "UNDECLARED_CHANGE", "UNRELATED_CHANGE", "UNSAFE_DIFF", "VERIFICATION_FAILED"),
        Decision.review: ("ADVISORY_CONFLICT", "NON_REACHABILITY_EXCEPTION", "TRANSITIVE_OVERRIDE", "UNAPPROVED_SOURCE_MIGRATION", "TEST_CHANGE_REQUIRES_REVIEW", "NO_VERSION_CHANGE", "MAJOR_UPGRADE", "DOWNGRADE", "AMBIGUOUS_MAVEN_VERSION", "UNSUPPORTED_VERSION", "TRANSFORMATION_REQUIRES_REVIEW"),
        Decision.accept: ("ELIGIBLE_FOR_AUTOMATED_PULL_REQUEST",),
    }
    reasons = precedence[decision]
    primary = next((item for item in reasons if any(rule.reason == item for rule in rules)), reasons[-1])
    try:
        return PolicyResult(decision=decision, primary_reason=primary, rules=tuple(rules), priority=_priority(finding, advisory))
    except TypeError:
        return PolicyResult(decision=decision, primary_reason=primary, rules=tuple(rules))


__all__ = ["PolicyConfig", "evaluate"]
