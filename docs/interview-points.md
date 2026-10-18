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
- **Approvals the agent cannot forge:** review found an agent could set
  `human_approved=True` itself. Approvals now come only from a named human
  via `Bridge.approve`, are single-use, scoped and expiring — tested.
- **Proof:** the README's test count and demo output are rendered from a
  real run and checked in CI; the demo uses a fixed clock.
