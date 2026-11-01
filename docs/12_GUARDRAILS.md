# Guardrails

*Step 12 of the reading path.*

## What you'll learn

Each safety rule and the test that proves it.

| Rule | Claim | Test |
|---|---|---|
| BRIDGE-01..06 | registration, grant, autonomy, human approval, single-use approvals, human approvers | `tests/test_agelayer.py` |
| INTENT-01..04 | calls outside the request are denied; empty scope fails closed | `tests/test_intent.py` |
| Widening | only a named human can widen an intent scope | `test_widen_needs_human` |
| BUDGET-01..03 | step, token and cost caps stop the session | `tests/test_budget.py` |
| LOOP-01/02 | repeat and oscillation loops stop | `test_loop_same_call`, `test_loop_oscillation` |
| KILL-01/02 | kill switch stops; unreadable state denies | `test_kill_switch_global_and_agent`, `test_kill_switch_unreadable_fails_closed` |
| Reset | stopped sessions and kill switches reset only by a named human | `test_stopped_stays_stopped_until_human_reset`, `test_kill_reset_needs_human` |
| Order | intent is checked before the bridge; bridge rules still apply | `tests/test_guarded.py` |
| Audit | guard decisions go to the hash chain | `test_decisions_in_hash_chain` |
| RISK-01..06 | missing owner or approval path is flagged | `tests/test_risk_card.py` |
| MCP-01..05 | unknown, denied, ungranted, plain-HTTP servers and unknown tools are denied | `tests/test_mcp.py` |
| DRIFT-01..04 | drift quarantines until human re-approval | `test_drift_rules_quarantine`, `test_reapproval_lifts_quarantine` |
| POISON-01..07 | labelled descriptions classified; hidden characters caught | `test_poison_labels`, `test_hidden_characters` |
| TOK-01..06 | tampered, expired, wrong-audience, wrong-scope, over-long and revoked tokens fail | `test_token_rejections`, `test_tampered_token`, `test_ttl_cap`, `test_revoked` |
| SAI-01..04 | shadow AI, unclassified AI, personal accounts, large uploads | `tests/test_shadow_ai.py` |
| BPOL-01..05 | graduated decisions; policy changes need another named human | `tests/test_browser_policy.py` |
| EXT-01..04 | high-risk permissions reviewed; blocks need a human sign-off | `tests/test_extensions.py` |
| CSG-01..05 | secrets, secret files, restricted code blocked; values never logged | `tests/test_coding_sessions.py` |
| Reports | KPI sources labelled; committed reports match a fresh run | `tests/test_leadership.py` |

## Next

[13_LIMITATIONS.md](13_LIMITATIONS.md)
