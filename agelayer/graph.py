"""Privilege graph: agents -> tools -> data scopes.

Nodes are agents, tools, and data scopes; edges are granted access.
``blast_radius`` computes the transitive closure from an agent (everything
it can reach). ``escalation_paths`` finds paths from an agent to
high-privilege nodes (tools/scopes flagged sensitive). All traversals are
deterministic (sorted neighbor order).
"""

from __future__ import annotations

from . import registry


def build(conn, tool_catalog: dict) -> dict:
    """Build adjacency {node: sorted([neighbors])} plus node metadata.

    tool_catalog: {tool: {"category": ..., "sensitivity": 1-5,
                          "scopes": [scope, ...]}}
    Nodes are prefixed: "agent:<id>", "tool:<name>", "scope:<name>".
    """
    adj: dict[str, set[str]] = {}
    meta: dict[str, dict] = {}

    def edge(a, b):
        adj.setdefault(a, set()).add(b)
        adj.setdefault(b, set())
    # Reverse index: which tools lead to each scope (for sensitivity).
    scope_tools: dict[str, set[str]] = {}

    for agent in registry.list_agents(conn):
        anode = f"agent:{agent['agent_id']}"
        meta[anode] = {"kind": "agent", "status": agent["status"]}
        for tool in sorted(agent["tools_granted"]):
            tnode = f"tool:{tool}"
            edge(anode, tnode)
            info = tool_catalog.get(tool, {})
            meta.setdefault(tnode, {
                "kind": "tool",
                "category": info.get("category", "write"),
                "sensitivity": info.get("sensitivity", 3),
            })
            for scope in sorted(info.get("scopes", [])):
                snode = f"scope:{scope}"
                edge(tnode, snode)
                meta.setdefault(snode, {"kind": "scope"})
                scope_tools.setdefault(snode, set()).add(tnode)
    # Scopes inherit the max sensitivity of the tools that can reach them.
    for snode, tools in scope_tools.items():
        sens = [meta[t].get("sensitivity", 3) for t in tools]
        meta[snode]["sensitivity"] = max(sens) if sens else 3
    return {"adj": {k: sorted(v) for k, v in adj.items()}, "meta": meta}


def blast_radius(graph: dict, agent_id: str) -> dict:
    """Transitive closure from the agent: reachable nodes + one path each."""
    adj = graph["adj"]
    start = f"agent:{agent_id}"
    if start not in adj:
        raise KeyError(f"unknown agent node {start}")
    seen = {start: [start]}
    queue = [start]
    while queue:
        node = queue.pop(0)
        for nxt in adj.get(node, []):
            if nxt not in seen:
                seen[nxt] = seen[node] + [nxt]
                queue.append(nxt)
    nodes = sorted(n for n in seen if n != start)
    return {"agent": agent_id, "reachable": nodes,
            "paths": {n: seen[n] for n in nodes}}


def escalation_paths(graph: dict, agent_id: str,
                     sensitivity_at_least: int = 4) -> list[dict]:
    """Paths from the agent to high-privilege tools/scopes."""
    adj, meta = graph["adj"], graph["meta"]
    start = f"agent:{agent_id}"
    if start not in adj:
        raise KeyError(f"unknown agent node {start}")
    targets = sorted(
        n for n, m in meta.items()
        if m.get("kind") in ("tool", "scope")
        and m.get("sensitivity", 0) >= sensitivity_at_least
    )
    results = []
    # DFS with sorted neighbors for determinism; keep shortest path per target
    for target in targets:
        best = None
        stack = [(start, [start])]
        visited_best = {}
        while stack:
            node, path = stack.pop()
            if node == target:
                if best is None or len(path) < len(best):
                    best = path
                continue
            for nxt in adj.get(node, []):
                if nxt in path:
                    continue
                key = (nxt, target)
                if key in visited_best and visited_best[key] <= len(path) + 1:
                    continue
                visited_best[key] = len(path) + 1
                stack.append((nxt, path + [nxt]))
        if best:
            results.append({"target": target, "path": best,
                            "hops": len(best) - 1,
                            "sensitivity": meta[target].get("sensitivity")})
    return results
