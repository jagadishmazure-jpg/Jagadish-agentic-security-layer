# ADR 0005: Browser AI policy uses metadata and a DLP flag, not page content

## Status

Accepted (2026-10-31).

## Context

Browser-level AI controls can drift into employee surveillance.

## Decision

The browser policy engine decides on host, sanction state, login domain, group and a boolean `sensitive`
flag set by the DLP step. It stores decisions, not content. Group overrides tighten policy for finance and
HR; everyone else is warned and coached first.

## Consequences

- Content inspection lives in one place (the DLP gateway in `Jagadish-pii-guard`).
- The engine cannot explain *what* was sensitive; that detail stays in the DLP findings, which hold types,
  never values.
