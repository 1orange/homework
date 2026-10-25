# ADR-0001: Separate deterministic authorization from proposals

Status: Accepted

## Context

An agent can suggest a useful dependency change, but model output is not an authorization boundary.
The same normalized inputs must produce the same disposition, primary reason, and ordered rule
evaluations, including when an agent or repository context is misleading.

## Decision

Keep proposal generation and authorization in separate trust domains. The deterministic function
model emits exactly one typed proposal. A pure, ordered policy engine independently combines the
finding, authenticated advisory facts, observed diff, and verification report. Only completed
evaluations receive `accept`, `review`, or `reject`; operational failures remain processing errors.

## Alternatives and trade-offs

Letting the agent choose its own disposition would be simpler, but would make prompt/model behavior
an authorization primitive. A weighted risk score would be flexible, but would obscure why a result
changed and allow severity to dilute a hard safety rule. Explicit rules are more verbose and narrow,
but reproducible and auditable.

## Consequences

The agent cannot approve its own work, CVSS cannot waive a gate, and tests can assert public policy
contracts. Policy changes require deliberate, reviewable rule changes rather than prompt changes.
