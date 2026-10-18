# ADR 0001: SQLite authorizer backstop for the read gateway

## Status

Accepted.

## Context

The SELECT-only gateway first used a text allowlist (single SELECT,
FROM/JOIN targets must be allowlisted views). Text scanning cannot see
every way SQLite names a table: comma joins (`FROM a, v`), `/**/`
comments as whitespace, parenthesised tables (`FROM (t)`), and
double-quoted identifiers (`FROM "t"`) all reach base tables without a
`FROM <name>` token. A real bypass of this class was found during
standardization of sibling repos.

## Decision

Add a second, independent layer: a SQLite `set_authorizer` callback that
runs while each gateway query executes. A base-table READ is allowed only
when SQLite's `source` argument names an allowlisted view (i.e. SQLite is
reading the table *on behalf of* the view). Direct reads, schema tables,
writes, PRAGMA, ATTACH, and `load_extension` are denied. The narrow
exception is SQLite's empty-column read for tables behind a view (view
self-joins, `count(*)`), which returns no column data.

## Consequences

- The text check and the authorizer are independent; either alone blocks
  the known bypasses.
- Regression tests run the authorizer with the text check **bypassed**
  (`run_query_authorizer_only`) to prove the backstop holds on its own —
  this is now a standing rule for every repo with a gateway.
