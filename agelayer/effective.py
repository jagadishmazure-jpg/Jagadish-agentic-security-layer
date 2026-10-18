"""Effective privilege: what an agent can *actually* reach, not just its direct grants.

Direct-grant review (agent -> tools_granted) misses three real patterns:

  EFF-01  group-mediated grants: agent -> group (-> group)* -> tool.
          Direct-grant review misses these entirely; multi-level nesting
          (agent -> group -> group -> tool) is the hardest to spot.
  EFF-02  wildcard grants: a group (or agent) granted "*" holds every tool
  EFF-03  dormant grants: rights that exist but look inactive (break-glass
          access never revoked, temp rights never removed)

``effective_privilege`` resolves all three into the full tool/scope set with
every path cited. ``hidden_escalations`` finds privileges reachable ONLY via
indirect paths -- invisible to direct-grant review. Deterministic.
"""

from __future__ import annotations

import json
import sqlite3

EFF_NESTED = "EFF-01"    # nested group membership
EFF_WILDCARD = "EFF-02"  # wildcard grant expansion
EFF_DORMANT = "EFF-03"   # dormant (looks-inactive) grant

_SCHEMA_GROUPS = """
CREATE TABLE IF NOT EXISTS groups (
    group_id      TEXT PRIMARY KEY,
    name          TEXT NOT NULL,
    members       TEXT NOT NULL,   -- JSON list of "agent:<id>" / "group:<id>"
    tools_granted TEXT NOT NULL    -- JSON list of tool names; "*" = all tools
)
"""

_SCHEMA_DORMANT = """
CREATE TABLE IF NOT EXISTS dormant_grants (
    agent_id TEXT NOT NULL,
    tool     TEXT NOT NULL,
    reason   TEXT NOT NULL,
    PRIMARY KEY (agent_id, tool)
)
"""


def init_db(conn: sqlite3.Connection) -> None:
    conn.execute(_SCHEMA_GROUPS)
    conn.execute(_SCHEMA_DORMANT)
    conn.commit()


def add_group(conn, group_id, name, members, tools_granted) -> None:
    if not group_id or not str(group_id).strip():
        raise ValueError("group_id must be non-empty")
    conn.execute(
        "INSERT OR REPLACE INTO groups VALUES (?,?,?,?)",
        (group_id, name, json.dumps(list(members)),
         json.dumps(list(tools_granted))),
    )
    conn.commit()


def add_dormant_grant(conn, agent_id, tool, reason) -> None:
    if not agent_id or not tool:
        raise ValueError("agent_id and tool must be non-empty")
    conn.execute(
        "INSERT OR REPLACE INTO dormant_grants VALUES (?,?,?)",
        (agent_id, tool, reason),
    )
    conn.commit()


def list_groups(conn) -> list[dict]:
    rows = conn.execute(
        "SELECT group_id, name, members, tools_granted FROM groups"
        " ORDER BY group_id").fetchall()
    return [{"group_id": r[0], "name": r[1],
             "members": json.loads(r[2]), "tools_granted": json.loads(r[3])}
            for r in rows]


def seed_effective(conn) -> None:
    """Extend the demo with indirect-privilege patterns (fictional)."""
    init_db(conn)
    # EFF-01: two-level nesting. agt-router -> grp-support-leads
    #         -> grp-data-team. Direct review shows a read-only agent;
    #         effective review shows write_invoice + read_customers.
    add_group(conn, "grp-support-leads", "Support Leads",
              ["agent:agt-router"], ["read_customers"])
    add_group(conn, "grp-data-team", "Data Team",
              ["group:grp-support-leads"], ["write_invoice"])
    # EFF-02: wildcard misconfiguration (legacy, pre-governance).
    add_group(conn, "grp-legacy-admins", "Legacy Admins",
              ["agent:agt-deployer"], ["*"])
    # EFF-03: dormant break-glass grant, never revoked.
    add_dormant_grant(conn, "agt-biller", "deploy_service",
                      "temporary deploy rights from release REL-88, never revoked")
    add_dormant_grant(conn, "agt-router", "rotate_secret",
                      "break-glass access from incident INC-1042, never revoked")


def _agent_node(agent_id: str) -> str:
    return f"agent:{agent_id}"


def _expand_tools(granted: list[str], tool_catalog: dict) -> list[str]:
    if "*" in granted:
        return sorted(tool_catalog)
    return sorted(t for t in granted if t in tool_catalog)


def _resolve(conn, agent_id: str, tool_catalog: dict):
    """BFS over agent/group membership. Returns (tool_paths, mechanisms).

    tool_paths: {tool: [[node, ...], ...]} every membership path to the tool.
    mechanisms: {tool: {EFF-*} } indirect mechanisms observed per tool.
    """
    start = _agent_node(agent_id)
    groups = {g["group_id"]: g for g in list_groups(conn)}
    # membership edges: member -> group
    member_of: dict[str, list[str]] = {}
    for g in groups.values():
        for m in g["members"]:
            member_of.setdefault(m, []).append(g["group_id"])

    tool_paths: dict[str, list[list[str]]] = {}
    mechanisms: dict[str, set[str]] = {}

    def record(tool, path, mechs):
        tool_paths.setdefault(tool, []).append(path)
        mechanisms.setdefault(tool, set()).update(mechs)

    # direct grants (from registry)
    from . import registry
    agent = registry.get_agent(conn, agent_id)
    if agent is None:
        raise KeyError(f"unknown agent {agent_id}")
    for tool in _expand_tools(agent["tools_granted"], tool_catalog):
        mechs = {EFF_WILDCARD} if "*" in agent["tools_granted"] else set()
        record(tool, [start, f"tool:{tool}"], mechs)

    # group traversal (cycle-safe)
    queue = [(start, [start])]
    seen_groups: set[str] = set()
    while queue:
        node, path = queue.pop(0)
        for gid in sorted(member_of.get(node, [])):
            gnode = f"group:{gid}"
            if gnode in path:  # cycle guard
                continue
            gpath = path + [gnode]
            g = groups[gid]
            wildcard = "*" in g["tools_granted"]
            for tool in _expand_tools(g["tools_granted"], tool_catalog):
                mechs = {EFF_NESTED}
                if wildcard:
                    mechs.add(EFF_WILDCARD)
                record(tool, gpath + [f"tool:{tool}"], mechs)
            if gid not in seen_groups:
                seen_groups.add(gid)
                queue.append((gnode, gpath))

    # dormant grants
    rows = conn.execute(
        "SELECT tool, reason FROM dormant_grants WHERE agent_id = ?"
        " ORDER BY tool", (agent_id,)).fetchall()
    for tool, _reason in rows:
        if tool in tool_catalog:
            record(tool, [start, f"dormant:{tool}"], {EFF_DORMANT})

    # deterministic ordering of paths
    for tool in tool_paths:
        tool_paths[tool] = sorted(tool_paths[tool])
    return tool_paths, mechanisms


def effective_privilege(conn, agent_id: str, tool_catalog: dict) -> dict:
    """Full effective privilege set for an agent (direct + indirect)."""
    tool_paths, mechanisms = _resolve(conn, agent_id, tool_catalog)
    from . import registry
    agent = registry.get_agent(conn, agent_id)
    direct = set(_expand_tools(agent["tools_granted"], tool_catalog))
    tools = sorted(tool_paths)
    scopes = sorted({s for t in tools
                     for s in tool_catalog.get(t, {}).get("scopes", [])})
    return {
        "agent": agent_id,
        "tools": tools,
        "scopes": scopes,
        "direct_tools": sorted(direct),
        "indirect_tools": sorted(set(tools) - direct),
        "paths": tool_paths,
        "mechanisms": {t: sorted(m) for t, m in mechanisms.items()},
    }


def privilege_paths(conn, agent_id: str, privilege: str,
                    tool_catalog: dict) -> list[dict]:
    """Every path by which the agent holds a privilege.

    privilege: "tool:<name>" or "scope:<name>". Each returned path lists
    its hops with the mechanism cited.
    """
    eff = effective_privilege(conn, agent_id, tool_catalog)
    results = []
    if privilege.startswith("tool:"):
        tool = privilege[len("tool:"):]
        for path in eff["paths"].get(tool, []):
            results.append({"privilege": privilege, "path": path,
                            "mechanisms": eff["mechanisms"].get(tool, [])})
    elif privilege.startswith("scope:"):
        scope = privilege[len("scope:"):]
        for tool in eff["tools"]:
            if scope in tool_catalog.get(tool, {}).get("scopes", []):
                for path in eff["paths"][tool]:
                    results.append({
                        "privilege": privilege, "tool": tool,
                        "path": path + [f"scope:{scope}"],
                        "mechanisms": eff["mechanisms"].get(tool, [])})
    results.sort(key=lambda r: (r["path"], r["privilege"]))
    return results


def hidden_escalations(conn, tool_catalog: dict,
                       sensitivity_at_least: int = 4) -> list[dict]:
    """Privileges reachable ONLY via indirect paths (EFF-01/02/03).

    These are invisible to direct-grant review -- the core value of the
    effective-privilege layer.
    """
    from . import registry
    findings = []
    for agent in registry.list_agents(conn):
        eff = effective_privilege(conn, agent["agent_id"], tool_catalog)
        for tool in eff["indirect_tools"]:
            sens = tool_catalog.get(tool, {}).get("sensitivity", 3)
            if sens < sensitivity_at_least:
                continue
            mechs = eff["mechanisms"].get(tool, [])
            findings.append({
                "agent": agent["agent_id"],
                "privilege": f"tool:{tool}",
                "sensitivity": sens,
                "mechanisms": mechs,
                "rule_ids": sorted(mechs),
                "paths": eff["paths"][tool],
            })
    findings.sort(key=lambda f: (-f["sensitivity"], f["agent"], f["privilege"]))
    return findings
