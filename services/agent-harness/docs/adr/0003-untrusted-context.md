# ADR-0003: Treat repository context as untrusted

Status: Accepted

## Context

Repository instructions, stale runbooks, issue descriptions, logs, and model prose can contain
prompt-injection-like guidance. Useful diagnostics must not become authority to bypass tests,
credentials, branch protection, provenance, or policy.

## Decision

The context broker exposes only bounded, typed, redacted facts. Repository text and optional logs or
issue context are labelled untrusted and cannot alter policy. Security-relevant inputs come through
separate authenticated boundaries: provenance verification, advisory enrichment, independent diff
observation, and verification adapters. The known auto-merge, branch-bypass, test-exclusion, and
credential-refresh instructions are therefore test data, never authorization.

## Alternatives and trade-offs

Passing the whole repository to the agent would improve convenience and apparent context, but would
expand the prompt-injection and secret-exposure surface. Ignoring all context would be simpler, but
would lose useful bounded diagnostics. The broker costs adapter code and context limits while keeping
the authority boundary clear.

## Consequences

Future production adapters can add authenticated facts without changing proposal semantics. Logs
remain useful for diagnosis, but their content cannot turn a review into an accept or make missing
security evidence appear present.
