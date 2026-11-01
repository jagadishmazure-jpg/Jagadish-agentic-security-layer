# Runtime guardrails v2

*Step 06 of the reading path.*

## What you'll learn

- How a tool call is checked against what the user asked for
- How step, token and cost caps, loop detection and the kill switch work
- What an agent risk card shows

## 1. Intent-bound actions (`intent.py`)

The user's request becomes an **intent scope**: the tools it implies, the highest action level it implies
(read < write < destructive) and the resource ids it names (`TCK-`, `INV-`, `ORD-`, `svc-`). A call is
denied when the tool is not implied (INTENT-01), targets a resource the user did not name (INTENT-02), is a
higher action level than the request (INTENT-03), or the request implies no tool at all (INTENT-04,
fail-closed). A named human can widen the scope for one tool; the widening is recorded.

This is a deterministic keyword parser standing in for an intent classifier. Its measured accuracy and
known misses are in [11_EVALUATION.md](11_EVALUATION.md).

## 2. Budgets, loops and kill switch (`budget.py`)

| Rule | Stops when |
|---|---|
| BUDGET-01 | step cap reached |
| BUDGET-02 | token cap reached |
| BUDGET-03 | cost cap reached (synthetic per-1k-token prices, not vendor prices) |
| LOOP-01 | same call 3 or more times in the last 5 |
| LOOP-02 | A-B-A-B oscillation |
| KILL-01 | kill switch on (global or for this agent) |
| KILL-02 | kill switch state unreadable: deny |

A stopped session stays stopped until a named human resets it.

## 3. Guarded session (`guarded.py`)

`GuardedSession` runs: kill switch → loop and step budget → intent → bridge → token and cost accounting.
`intent_mode="flag"` exists for a shadow-mode rollout (log, do not block); the default is `block`.

## 4. Agent risk card (`risk_card.py`)

One card per agent: owner, autonomy, approval path, direct and indirect tools, MCP servers, last red-team
ASR (synthetic, from the red-team repo's shape). Flags: RISK-01 L2+ with no owner, RISK-02 L2+ with no
approval path, RISK-03 a sensitivity-5 tool, RISK-04 indirect-only privilege, RISK-05 ASR above 10%,
RISK-06 an unapproved MCP server.

KPI K06 counts L2+ agents with both an owner and an approval path. The source note says "above L2"; this
repo uses **L2 or higher**, because L2 is the first level where an agent writes without a per-call human.

## Real output (rendered in CI)

<!-- run: python scripts/show_guardrails_v2.py -->
```text
guard agt-router    read_tickets    allowed  -
guard agt-router    read_tickets    denied   INTENT-02
guard agt-router    read_orders     denied   INTENT-01
guard agt-biller    read_orders     denied   INTENT-01
guard agt-biller    write_invoice   allowed  -
guard agt-biller    read_customers  denied   INTENT-01
guard agt-deployer  read_builds     allowed  -
guard agt-deployer  deploy_service  denied   INTENT-03
guard agt-deployer  rotate_secret   denied   INTENT-03
guard agt-router    read_tickets    stopped  KILL-01
guard agt-biller    write_invoice   stopped  KILL-02
out-of-intent attempts 6, blocked 6; audit chain valid: True
budget token_runaway  ran  10/500 stop BUDGET-02 tokens avoided  1,960,000 cost avoided $1.96
budget cost_runaway   ran   5/500 stop BUDGET-03 tokens avoided  9,900,000 cost avoided $49.50
budget step_runaway   ran  25/500 stop BUDGET-01 tokens avoided     47,500 cost avoided $0.01
budget tight_loop     ran   2/500 stop LOOP-01   tokens avoided    149,400 cost avoided $0.15
(costs use synthetic per-1k-token prices, not vendor prices)
card agt-biller    L2 owner=fin-team       path=fin-approvers    score  26 medium   RISK-04
card agt-deployer  L2 owner=platform-team  path=MISSING          score  76 critical RISK-02,RISK-03,RISK-04,RISK-05,RISK-06
card agt-router    L1 owner=ops-team       path=MISSING          score  33 medium   RISK-03,RISK-04
card agt-wiper     L3 owner=platform-team  path=platform-oncall  score  34 medium   RISK-05
L2+ agents with owner and approval path: 2/3
```
<!-- /run -->

The `tokens avoided` numbers compare a scripted 500-step runaway with where the cap stopped it. They are
measured on the script, with synthetic prices.

## Next

[07_MCP_SECURITY.md](07_MCP_SECURITY.md)
