# ADR 0003: Pin MCP tool listings and quarantine on any drift

## Status

Accepted (2026-10-31).

## Context

MCP tool descriptions are read by the model, not by people, and can change after approval.

## Decision

Hash each tool's description and input schema at approval. On every listing refresh, compare; any change,
addition or removal quarantines the server until a named human re-approves. Scan descriptions (and
parameter descriptions) for hidden instructions on every refresh; a poisoned listing also quarantines.

## Consequences

- Legitimate updates need a human re-approval; this is intended friction.
- Pattern scanning misses paraphrased and non-English instructions; documented and tested as known misses.
