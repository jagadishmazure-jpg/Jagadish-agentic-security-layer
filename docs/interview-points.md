# Interview points

- **Problem:** AI agents accumulate privileges with no governance; shadow
  agents operate outside any registry.
- **Approach:** a governed bridge so agents never call tools directly —
  registration, grant, and autonomy policy checked per action, like an API
  gateway for agent tool calls.
- **Shadow detection:** unregistered callers found from activity logs,
  scored by privilege exercised, onboard-or-block recommendation.
- **Blast radius:** deterministic privilege graph; "if this agent is
  compromised, what is exposed?" answered with paths, not meetings.
- **Zero standing privilege:** posture score 0-100 with a prioritized
  improvement list — the roadmap writes itself.
- **Defense in depth on reads:** the SELECT gateway has two independent
  layers (text check + SQLite authorizer); regression tests prove the
  authorizer alone denies raw-table reads with the text check bypassed.
- **Proof:** 52 tests, all from real runs; demo scenario is deterministic.
