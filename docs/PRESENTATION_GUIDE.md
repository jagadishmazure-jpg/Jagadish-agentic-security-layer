# Presentation guide

*Step 17 of the reading path.*

## What you'll learn

How to present this repo in 5 or 15 minutes.

## 5 minutes

1. (1 min) The four questions: what AI is in use, what may it do, is it doing only what was asked, how do
   we report it. Show the diagram in [00_START_HERE.md](00_START_HERE.md).
2. (2 min) Run `python scripts/show_guardrails_v2.py`. Point at INTENT-02 (wrong ticket), INTENT-03 (deploy
   during a "check" request) and KILL-02 (unreadable kill switch denies).
3. (1 min) Run `python scripts/show_mcp.py`. Point at the rug-pull rows.
4. (1 min) Open `reports/leadership_weekly.html`. Point at the Source column.

## 15 minutes

Add: the shadow AI inventory and browser policy (step 05), the risk cards and K06 definition (step 06),
the evaluation and known misses (step 11), and the OWASP Agentic mapping (step 14). End on limitations
(step 13).

## Likely questions

- *Why a keyword parser for intent?* Deterministic floor that fails closed; a classifier would sit on top.
- *Why are some KPIs samples?* This repo does not own them; inventing a measurement would be dishonest.
- *Would this block real work?* Rollout starts in flag and warn modes (step 15).

## Next

Back to [00_START_HERE.md](00_START_HERE.md).
