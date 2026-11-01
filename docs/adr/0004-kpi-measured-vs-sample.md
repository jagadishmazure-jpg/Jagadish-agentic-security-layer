# ADR 0004: Leadership KPIs say whether they were measured

## Status

Accepted (2026-10-31).

## Context

Three repos share one KPI catalog, but each repo can only measure what its own code produces.

## Decision

Each repo measures the KPIs it owns from deterministic runs on synthetic data. Other KPIs come from a
fixture whose label must contain "synthetic" (enforced at load) and each row is marked "synthetic sample
(owned by ...)". Reports are written to `reports/` and never sent.

## Consequences

- No invented measurements. Leadership sees which numbers are real outputs of code.
- The fixture must be updated when an owning repo's measurements change.
