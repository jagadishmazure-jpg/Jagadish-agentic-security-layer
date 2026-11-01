# Interview points

*Step 16 of the reading path.*

## What you'll learn

Short answers backed by code and tests.

- **Problem:** AI use outpaces governance: shadow AI apps, over-privileged agents, unreviewed MCP servers,
  and leaders with no numbers.
- **Discover first:** you cannot govern what you cannot list. The inventory finds an unknown AI host by its
  API-style path, not only by a catalog match.
- **Graduated, not binary:** allow, warn, redact, block. Blocking everything pushes people to personal
  devices; coaching on approved apps keeps them on governed ones.
- **Monitoring, not surveillance:** the browser engine uses metadata; content checks belong in the DLP step,
  and exec views aggregate by team.
- **Intent-bound actions:** prompt injection is hard to detect, so contain its effect. A call must match
  what the user asked for. Measured on 30 labelled cases; known misses kept as tests.
- **Fail closed:** empty intent scope, unknown tool, unreadable kill switch, unknown MCP server, unknown
  sanction state all deny.
- **Denial of wallet is a security issue:** four scripted runaways stop on four different rules; tokens
  avoided are measured against the script.
- **MCP rug pull:** pin hashes of descriptions and schemas; any drift quarantines until a human re-approves.
- **No token passthrough:** a token minted for one MCP server is rejected by another (TOK-03).
- **Owner and approval path:** risk cards flag L2+ agents without them; K06 reports the share.
- **Honest numbers:** every KPI row says whether it was measured here or is a labelled sample.
- **Approvals the agent cannot forge:** carried from the bridge: single-use, scoped, expiring, by a named
  human.

## Next

[PRESENTATION_GUIDE.md](PRESENTATION_GUIDE.md)
