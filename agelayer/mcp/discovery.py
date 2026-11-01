"""Discover MCP traffic in synthetic network / proxy logs.

  MCPD-01  JSON-RPC "initialize" or "tools/list" to a host not in the registry
  MCPD-02  known MCP endpoint path (/mcp, /sse, /messages) to an unknown host
  MCPD-03  local MCP server process seen on a workstation (stdio launch in EDR-style logs)

Output feeds the registry review queue and KPI K09 (unapproved servers).
"""

from __future__ import annotations

import random

MCP_METHODS = ("initialize", "tools/list", "tools/call")
MCP_PATHS = ("/mcp", "/sse", "/messages")


def discover(events: list[dict], known_hosts: set[str]) -> list[dict]:
    found: dict[str, dict] = {}
    for e in events:
        host = e.get("host", "")
        if host in known_hosts:
            continue
        rule = None
        if e.get("kind") == "process" and "mcp" in e.get("cmd", "").lower():
            rule, host = "MCPD-03", f"local:{e.get('device')}:{e.get('cmd').split()[0]}"
        elif e.get("jsonrpc_method") in MCP_METHODS:
            rule = "MCPD-01"
        elif any(e.get("path", "").startswith(p) for p in MCP_PATHS):
            rule = "MCPD-02"
        if rule:
            row = found.setdefault(host, {"host": host, "rule_id": rule, "users": set(), "events": 0})
            row["users"].add(e.get("user", "?"))
            row["events"] += 1
    return [{**r, "users": sorted(r["users"])} for r in sorted(found.values(), key=lambda r: r["host"])]


def synthetic_netlog(seed: int = 5, n: int = 300) -> list[dict]:
    rng = random.Random(seed)
    hosts = ["files-mcp.corp.example", "tickets-mcp.corp.example", "intranet.corp.example",
             "scrape-mcp.example", "mcp.toolhub.example", "news.example"]
    out = []
    for _ in range(n):
        h = rng.choice(hosts)
        e = {"user": f"user{rng.randint(1, 40):03d}", "host": h, "path": "/", "kind": "http"}
        if "mcp" in h:
            r = rng.random()
            if r < 0.4:
                e["jsonrpc_method"] = rng.choice(MCP_METHODS)
            elif r < 0.7:
                e["path"] = rng.choice(MCP_PATHS)
        out.append(e)
    out.append({"kind": "process", "device": "lt-0142", "user": "user017", "cmd": "mcp-desktop --stdio", "host": ""})
    return out
