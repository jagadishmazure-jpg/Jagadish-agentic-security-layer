# MCP security module

*Step 07 of the reading path.*

## What you'll learn

- How MCP servers are allowed, denied and granted per agent
- How tool-description drift and hidden instructions are caught
- How tokens are kept short-lived and bound to one server

## Checks

| Module | Rules |
|---|---|
| `mcp/registry.py` | MCP-01 unknown or pending server (queued for review), MCP-02 deny-listed, MCP-03 not granted to this agent, MCP-04 plain-HTTP transport |
| `mcp/pinning.py` | DRIFT-01 description changed, DRIFT-02 schema changed, DRIFT-03 tool added, DRIFT-04 tool removed. Any drift quarantines the server until a named human re-approves. |
| `mcp/poisoning.py` | POISON-01 instructions to the model, 02 concealment, 03 sensitive paths, 04 exfiltration, 05 hidden text (zero-width, bidi, HTML comments, tag blocks), 06 long base64, 07 steering of other tools. Parameter descriptions are scanned too. |
| `mcp/shadowing.py` | SHADOW-MCP-01 exact name collision, SHADOW-MCP-02 collision after normalising case, separators and look-alike digits |
| `mcp/tokens.py` | TOK-01 bad signature, 02 expired, 03 wrong audience (no passthrough), 04 scope not granted, 05 lifetime above 900 s, 06 revoked |
| `mcp/discovery.py` | MCPD-01 JSON-RPC `initialize` / `tools/list` to an unknown host, MCPD-02 MCP endpoint paths, MCPD-03 local MCP server process |
| `mcp/gateway.py` | applies the above per call; unknown tool names are denied (MCP-05) |

The token signing key comes from `AGELAYER_MCP_TOKEN_KEY` or a random per-process key, and is never logged.
The demo uses a fixed test key so output is deterministic.

## Real output (rendered in CI)

<!-- run: python scripts/show_mcp.py -->
```text
mcp approved server, granted, valid token      allowed -
mcp unknown server                             denied  MCP-01
mcp deny-listed server                         denied  MCP-02
mcp server not granted to agent                denied  MCP-03
mcp plain-http transport                       denied  MCP-04
mcp token for another server (passthrough)     denied  TOK-03
mcp scope not granted                          denied  TOK-04
mcp expired token                              denied  TOK-02
mcp after description drift (quarantined)      denied  DRIFT-Q
mcp after human re-approval of clean listing   allowed -
drift: DRIFT-01 read_file
poisoned: POISON-02, POISON-03, POISON-04, POISON-05
collision SHADOW-MCP-02 [('files-mcp', 'read_file'), ('mcp.toolhub.example', 'read_fi1e')] suspect ['mcp.toolhub.example']
discovered MCPD-03 local:lt-0142:mcp-desktop users 1
discovered MCPD-01 mcp.toolhub.example users 21
discovered MCPD-01 scrape-mcp.example users 25
gateway kpis: {'unapproved_servers_seen': 3, 'denied_servers': 1, 'drift_events': 1, 'poisoned_descriptions': 4, 'quarantined_servers': 0, 'calls': 10, 'allowed': 2}
poison eval: 24 cases, precision 1.0, recall 0.833, misses [{'id': 'p11', 'kind': 'missed'}, {'id': 'p12', 'kind': 'missed'}]
intent eval: 30 cases, precision 0.941, recall 0.941, misses [('false_flag', 'Wipe the cache on the pricing page'), ('missed', 'Show the order ORD-5 and its customer')]
```
<!-- /run -->

The "rug pull" row shows the flow: a description changes after approval and hides an instruction, the
server is quarantined, a human re-approves the clean listing, and calls work again.

## Next

[08_LEADERSHIP_REPORT.md](08_LEADERSHIP_REPORT.md)
