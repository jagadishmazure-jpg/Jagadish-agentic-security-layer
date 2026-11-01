# Use cases

*Step 10 of the reading path.*

## What you'll learn

Seven scenarios you can demo, each with the command and what to point at. All companies, people and hosts
are fictional; all data is synthetic.

### 1. "Which AI tools are we using?" (Northwind Mutual, IT)
`python scripts/show_shadow_ai.py`. Point at the inventory table: 12 AI apps seen, 11 known, one
unclassified host found only by its API-style path (SAI-02). The decision queue is sorted by risk and
nothing is auto-blocked.

### 2. Finance pastes into an unsanctioned chat app
Same script, "browser policy" line. Finance and HR get `block` on unsanctioned, personal and unclassified
apps; other groups get `warn`. Sensitive content on an approved app is `redact`, not block.

### 3. A coding assistant reads `.env`
Same script, `coding cs-002` and `cs-003`. The secret in the prompt and the `.env` read are blocked; the
third session also shows an unregistered agent and an unapproved assistant sent payments code.

### 4. An injected agent tries extra tools
`python scripts/show_guardrails_v2.py`. The user asked to summarise TCK-101; the agent also reads TCK-102
(INTENT-02) and orders (INTENT-01). The deploy agent asked to *check* a build tries to deploy (INTENT-03).

### 5. A runaway loop at 2 a.m.
Same script, budget lines. Four scripted runaways stop on token, cost, step and loop rules; tokens and cost
avoided are measured against the 500-step script, at synthetic prices.

### 6. An MCP server changes its tool description after approval
`python scripts/show_mcp.py`. The `read_file` description gains a hidden instruction; DRIFT-01 fires, the
poisoning scan finds four rules, the server is quarantined until re-approved.

### 7. Monday's leadership email
`python scripts/leadership_report.py`, then open `reports/leadership_weekly.html`. Point at the Source
column: measured rows vs labelled samples.

## Next

[11_EVALUATION.md](11_EVALUATION.md)
