# Concepts

*Step 02 of the reading path.*

## What you'll learn

The words used in the rest of the docs.

| Term | Meaning here |
|---|---|
| Sanction state | `approved` (contract, SSO), `monitored` (allowed with a banner and logging), `unsanctioned`. Plus two per-use states: `personal` (an approved app used with a personal login) and `unclassified` (not in the catalog). |
| Shadow AI | AI apps used without approval, and agents acting without registration. |
| Graduated response | allow → warn → redact → block, picked by state, group and content. Stricter always wins. |
| Autonomy level | L0 propose only, L1 read, L2 read and write, L3 full within grant. Destructive tools always need a human approval. |
| Governed bridge | The single path from agent to tool. Checks registration, grant, autonomy and approval. |
| Intent scope | The tools, action level (read < write < destructive) and resource ids implied by the user's request. |
| Denial of wallet | Cost run-up from loops or huge prompts. Stopped by step, token and cost caps. |
| Kill switch | A global or per-agent stop. If its state cannot be read, every call is denied. |
| Risk card | One page per agent: owner, autonomy, approval path, tools (direct and indirect), MCP servers, last red-team ASR. |
| MCP | Model Context Protocol: servers that publish tools (name, description, input schema) to AI clients. |
| Pinning / drift | Hashing an approved tool listing and alerting when a description or schema changes. |
| Tool poisoning | Hidden instructions in a tool description aimed at the model. |
| Tool shadowing | A tool name that collides with a trusted server's tool. |
| Audience-bound token | A token minted for one MCP server that another server cannot reuse (no passthrough). |
| ASR | Attack success rate: attacks that got through / attacks run (from the red-team repo). |
| Measured vs sample | A KPI this repo computed by running its code, vs a labelled placeholder for a KPI another repo owns. |

## Next

[03_ARCHITECTURE.md](03_ARCHITECTURE.md)
