"""Compromised-agent impact analysis.

Given a compromised agent id: list every tool and data scope it can reach,
rank by sensitivity, and recommend immediate containment actions in
priority order. Deterministic; pure function of the privilege graph.
"""

from __future__ import annotations

from . import graph as pgraph


def analyze_compromise(graph: dict, agent_id: str) -> dict:
    """Return exposure ranking + prioritized containment actions."""
    radius = pgraph.blast_radius(graph, agent_id)
    meta = graph["meta"]
    exposed = []
    for node in radius["reachable"]:
        m = meta.get(node, {})
        if m.get("kind") == "tool":
            exposed.append({
                "node": node,
                "kind": "tool",
                "sensitivity": m.get("sensitivity", 3),
                "category": m.get("category", "destructive"),
                "path": radius["paths"][node],
            })
        elif m.get("kind") == "scope":
            exposed.append({
                "node": node,
                "kind": "scope",
                "sensitivity": m.get("sensitivity", 3),
                "category": "data",
                "path": radius["paths"][node],
            })
    exposed.sort(key=lambda e: (-e["sensitivity"], e["node"]))

    actions = [{"priority": 1, "action": f"suspend agent {agent_id}",
                "why": "stop further privileged calls immediately"}]
    seen_tools = [e["node"] for e in exposed if e["kind"] == "tool"]
    if seen_tools:
        actions.append({
            "priority": 2,
            "action": "revoke credentials for: " + ", ".join(seen_tools),
            "why": "invalidate anything the compromised agent could reuse"})
    high = [e["node"] for e in exposed if e["sensitivity"] >= 4]
    if high:
        actions.append({
            "priority": 3,
            "action": "rotate secrets on high-sensitivity nodes: "
                      + ", ".join(high),
            "why": "assume lateral movement toward the most valuable targets"})
    actions.append({"priority": 4,
                    "action": f"review bridge audit log for {agent_id}",
                    "why": "establish what the agent actually did"})
    return {"agent": agent_id, "exposed": exposed, "actions": actions,
            "exposed_count": len(exposed)}
