# ADR-0002: Use declarative, allow-listed transformations

Status: Accepted

## Context

Dependency remediation sometimes needs a small source migration, but executing arbitrary model output
would turn a proposal into code execution and could hide unrelated changes or weakened tests.

## Decision

Proposals contain typed data only: target identity, target version, registered transformation ID,
bounded paths, and registered verification IDs. The policy registry allow-lists deterministic recipes
and path patterns. Independently observed changed paths and hashes, rather than the agent's declared
intent, are the authorization input. Unknown operations, protected paths, undeclared changes, test
weakening, CI changes, credential changes, and policy bypasses are rejected.

## Alternatives and trade-offs

Allowing shell commands or unrestricted patches would support more ecosystems quickly, but would
grant execution authority and make review difficult. Requiring humans for every source edit would be
safer but would lose the narrow automation benefit. A small registry is less expressive, yet makes
the safe subset inspectable and testable.

## Consequences

The harness can accept a narrowly approved deterministic recipe while routing behavior-sensitive or
novel migrations to review. New recipes require explicit registration, bounded paths, and independent
verification; the agent cannot invent a privileged operation.
