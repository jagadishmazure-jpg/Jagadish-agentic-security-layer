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


def analyze_compromise_effective(conn, agent_id: str,
                                 tool_catalog: dict) -> dict:
    """Compromise analysis over EFFECTIVE privilege, not just direct grants.

    Uses effective.effective_privilege so indirect paths (nested groups,
    wildcards, dormant grants) are included. Exposures reachable only via
    indirect paths are flagged -- direct-grant review would miss them.
    """
    from . import effective as eff_mod
    eff = eff_mod.effective_privilege(conn, agent_id, tool_catalog)
    exposed = []
    for tool in eff["tools"]:
        info = tool_catalog.get(tool, {})
        indirect = tool in eff["indirect_tools"]
        exposed.append({
            "node": f"tool:{tool}",
            "kind": "tool",
            "sensitivity": info.get("sensitivity", 3),
            "category": info.get("category", "destructive"),
            "indirect_only": indirect,
            "mechanisms": eff["mechanisms"].get(tool, []),
            "paths": eff["paths"][tool],
        })
        for scope in sorted(info.get("scopes", [])):
            exposed.append({
                "node": f"scope:{scope}",
                "kind": "scope",
                "sensitivity": info.get("sensitivity", 3),
                "category": "data",
                "indirect_only": indirect,
                "mechanisms": eff["mechanisms"].get(tool, []),
                "paths": [p + [f"scope:{scope}"] for p in eff["paths"][tool]],
            })
    exposed.sort(key=lambda e: (-e["sensitivity"], e["node"]))

    actions = [{"priority": 1, "action": f"suspend agent {agent_id}",
                "why": "stop further privileged calls immediately"}]
    hidden = sorted({e["node"] for e in exposed if e["indirect_only"]})
    if hidden:
        actions.append({
            "priority": 2,
            "action": "revoke indirect-only access first: "
                     + ", ".join(hidden),
            "why": "these paths are invisible to direct-grant review and"
                   " are the most likely to survive a naive cleanup"})
    seen_tools = [e["node"] for e in exposed
                  if e["kind"] == "tool" and not e["indirect_only"]]
    if seen_tools:
        actions.append({
            "priority": 3,
            "action": "revoke credentials for: " + ", ".join(seen_tools),
            "why": "invalidate anything the compromised agent could reuse"})
    actions.append({"priority": 4,
                    "action": f"review bridge audit log for {agent_id}",
                    "why": "establish what the agent actually did"})
    return {"agent": agent_id, "exposed": exposed, "actions": actions,
            "exposed_count": len(exposed),
            "hidden_count": len(hidden)}
