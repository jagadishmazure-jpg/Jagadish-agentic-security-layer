# Implementation guide

*Step 15 of the reading path.*

## What you'll learn

- A phased rollout plan
- Where each piece would sit in an Azure-hosted agent platform

## Phased rollout

1. **Inventory (weeks 1-2).** Feed proxy, browser and IDE telemetry into `shadow_ai.discover`. Work the
   decision queue with app owners. Track K01, K15, K17, K18.
2. **Browser policy in warn mode (weeks 3-4).** Default `warn` everywhere except finance and HR. Coach,
   do not block. Track K16 and the outcome mix.
3. **Agent registry and bridge.** Register every agent with an owner and approval path; route all tool calls
   through the bridge. Track K05, K06.
4. **Guardrails v2 in flag mode, then block.** Start `GuardedSession(intent_mode="flag")`, review flagged
   calls for two weeks, then switch to `block`. Set budgets from observed p95 usage plus headroom. Track K07,
   K08.
5. **MCP.** Approve and pin each server, grant per agent, mint tokens per server with TTL ≤ 900 s, run
   discovery weekly. Track K09.
6. **Report.** Schedule `scripts/leadership_report.py` daily and weekly; replace sample rows as the owning
   repos go live.

## Azure deployment mapping (design, not built here)

| This repo | In an Azure-hosted agent platform |
|---|---|
| registry + risk cards | agent inventory with owner and approval-group metadata |
| `GuardedSession` + bridge | a tool-call middleware in front of every agent tool, logging to the SIEM |
| budgets and kill switch | per-agent token and cost limits plus a feature flag checked on every call |
| MCP gateway | a gateway between agents and MCP servers, with managed identities minting short-lived tokens |
| leadership report | a scheduled job writing to a dashboard |

## Autonomy levels

L0 propose only, L1 read, L2 read and write, L3 full within grant. Destructive tools need L2+ and a
human-issued, single-use approval regardless of level.

## Next

[16_INTERVIEW_POINTS.md](16_INTERVIEW_POINTS.md)
