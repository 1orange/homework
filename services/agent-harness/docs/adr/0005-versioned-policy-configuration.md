# ADR-0005: Inject and bind policy configuration

Status: Accepted

## Context

Transformation, verification, and bounded-path allow-lists are authorization inputs. Keeping them
inside the evaluator hides configuration changes in implementation code, while loading mutable or
unauthenticated policy implicitly would make decisions difficult to reproduce or trust.

## Decision

Load a strict, immutable policy document at the composition boundary and inject it into the harness
and evaluator. Keep decision algorithms and validation patterns in code. Canonicalize semantically
unordered allow-lists and bind both the policy-configuration digest and evaluated policy-result hash
into every completed approval commitment.

## Alternatives and trade-offs

Module constants are simpler but couple policy rollout to code releases. A generic constants module
only moves that coupling. Making validation regexes configurable would widen the trusted surface and
could introduce unsafe matching behavior. External policy adds loading and provenance concerns, but
makes authorization inputs explicit and independently reviewable.

## Consequences

Changing policy invalidates an old approval even when all other facts are unchanged. The checked-in
document is sufficient only for this fixture demonstration; production must verify a separately
controlled signed policy source, signer, version, and deployment provenance.
