# Purpose

*Step 01 of the reading path.*

## What you'll learn

- The problem this repo solves
- Who uses each part
- What "done" looks like

## The problem

AI use at work grows faster than governance:

- **Workforce AI.** Staff paste data into chat apps, sign in with personal accounts, install AI extensions
  that read every page, and let coding assistants read `.env` files. Most teams cannot list which AI tools
  are in use, let alone decide on them.
- **Agents.** Agents hold real privileges. They can be steered by injected text into calling tools the user
  never asked for, can loop and burn budget, and are often deployed without a named owner or approval path.
- **MCP.** MCP servers publish tool descriptions that the model reads and people do not. A server can change
  a description after approval ("rug pull"), hide instructions in it, or copy a trusted tool's name.
- **Leadership.** Executives want a short set of numbers that show coverage, risk and trend, not raw alerts.

## Who it is for

| Reader | Uses |
|---|---|
| Security engineer | the bridge, guarded session and MCP gateway as reference designs |
| AI platform owner | risk cards, the registry and budgets |
| IT / workplace team | shadow AI inventory, browser policy, extension scoring |
| CISO / leadership | the daily and weekly KPI report |

## What done looks like

- Every AI tool seen is in the inventory with a sanction state and a decision owner.
- Every agent tool call passes kill switch, budget, intent and bridge checks, and is in the audit chain.
- Every MCP server is approved, pinned and scanned; tokens are short-lived and bound to one server.
- A weekly report states which numbers are measured and which are samples.

## Next

[02_CONCEPTS.md](02_CONCEPTS.md)
