# ADR 0002: Intent-bound actions as a deterministic, fail-closed check in front of the bridge

## Status

Accepted (2026-10-31).

## Context

The bridge checks whether an agent *may* call a tool, not whether the user *asked* for it. An injected
agent with a valid grant can still call tools outside the request.

## Decision

Derive an intent scope (tools, highest action level, named resource ids) from the user's request with a
keyword parser. Deny calls outside it (INTENT-01..03) and deny everything when the scope is empty
(INTENT-04). Allow a named human to widen the scope for one tool. Offer `flag` mode for rollout.

## Consequences

- Deterministic and testable; accuracy measured on a labelled set (step 11).
- Synonyms and paraphrase are missed; kept as known-miss tests. A classifier can be layered on top later,
  with this parser as the floor.
