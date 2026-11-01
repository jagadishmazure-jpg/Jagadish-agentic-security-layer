"""Agent risk card: one page per agent for owners and reviewers.

Pulls together what the registry, effective-privilege resolver, MCP grants
and red-team results already know, then scores it:

  RISK-01  autonomy L2 or higher with no named owner
  RISK-02  autonomy L2 or higher with no approval path (no human approver group)
  RISK-03  holds a sensitivity-5 tool (directly or indirectly)
  RISK-04  indirect-only privileges (survive naive clean-up)
  RISK-05  last red-team attack success rate above 10% (synthetic results)
  RISK-06  connects to an MCP server that is not on the approved list

Leadership KPI K06 is "agents at autonomy L2 or higher that have both a named
owner and an approval path" (the note says "above L2"; this repo uses L2+
because L2 is where agents first act without a per-call human).
"""

from __future__ import annotations

from . import effective, registry

TIERS = ((60, "critical"), (40, "high"), (20, "medium"), (0, "low"))


def _effective(conn, agent_id, catalog):
    try:
        return effective.effective_privilege(conn, agent_id, catalog)
    except Exception:  # groups table not installed: fall back to direct grants
        a = registry.get_agent(conn, agent_id)
        tools = sorted(a["tools_granted"])
        return {"tools": tools, "indirect_tools": [],
                "scopes": sorted({s for t in tools for s in catalog.get(t, {}).get("scopes", [])})}


def build_card(conn, agent_id: str, catalog: dict, approval_paths: dict | None = None,
               mcp_grants: dict | None = None, approved_mcp: set | None = None,
               redteam_asr: dict | None = None) -> dict:
    a = registry.get_agent(conn, agent_id)
    if a is None:
        raise KeyError(agent_id)
    eff = _effective(conn, agent_id, catalog)
    approval = (approval_paths or {}).get(agent_id)
    servers = sorted((mcp_grants or {}).get(agent_id, []))
    asr = (redteam_asr or {}).get(agent_id)
    owner = (a["owner"] or "").strip()
    flags, score = [], 0
    level = a["autonomy_level"]
    score += level * 8
    if level >= 2 and not owner:
        flags.append("RISK-01")
        score += 20
    if level >= 2 and not approval:
        flags.append("RISK-02")
        score += 15
    max_sens = max((catalog.get(t, {}).get("sensitivity", 5) for t in eff["tools"]), default=0)
    if max_sens >= 5:
        flags.append("RISK-03")
        score += 15
    if eff["indirect_tools"]:
        flags.append("RISK-04")
        score += 10
    if asr is not None and asr > 0.10:
        flags.append("RISK-05")
        score += 10
    unapproved = [s for s in servers if s not in (approved_mcp or set())]
    if unapproved:
        flags.append("RISK-06")
        score += 10
    score = min(score, 100)
    tier = next(name for cut, name in TIERS if score >= cut)
    return {
        "agent_id": agent_id, "name": a["name"], "model": a["model"], "status": a["status"],
        "owner": owner or None, "autonomy": f"L{level}", "approval_path": approval,
        "tools": eff["tools"], "indirect_tools": eff["indirect_tools"], "scopes": eff["scopes"],
        "mcp_servers": servers, "unapproved_mcp": unapproved,
        "redteam_asr": asr, "max_sensitivity": max_sens,
        "flags": flags, "score": score, "tier": tier,
    }


def governed_share(cards: list[dict]) -> dict:
    """K06: L2+ agents with a named owner and an approval path."""
    l2 = [c for c in cards if int(c["autonomy"][1:]) >= 2]
    ok = [c for c in l2 if c["owner"] and c["approval_path"]]
    return {"l2_plus": len(l2), "with_owner_and_path": len(ok),
            "share": round(len(ok) / len(l2), 3) if l2 else 1.0,
            "gaps": sorted(c["agent_id"] for c in l2 if c not in ok)}


def render_markdown(card: dict) -> str:
    lines = [f"### Risk card: {card['agent_id']} ({card['name']})", "",
             "| Field | Value |", "| --- | --- |"]
    for k in ("status", "owner", "autonomy", "approval_path", "model", "tier", "score"):
        lines.append(f"| {k} | {card[k] if card[k] is not None else '**missing**'} |")
    lines.append(f"| tools | {', '.join(card['tools'])} |")
    lines.append(f"| indirect tools | {', '.join(card['indirect_tools']) or '-'} |")
    lines.append(f"| MCP servers | {', '.join(card['mcp_servers']) or '-'} |")
    asr = card["redteam_asr"]
    lines.append(f"| last red-team ASR (synthetic) | {'-' if asr is None else f'{asr:.0%}'} |")
    lines.append(f"| flags | {', '.join(card['flags']) or '-'} |")
    return "\n".join(lines)


DEMO_APPROVAL_PATHS = {"agt-biller": "fin-approvers", "agt-wiper": "platform-oncall"}
DEMO_MCP_GRANTS = {"agt-router": ["files-mcp"], "agt-deployer": ["files-mcp", "scrape-mcp"]}
DEMO_APPROVED_MCP = {"files-mcp", "tickets-mcp"}
DEMO_REDTEAM_ASR = {"agt-router": 0.05, "agt-biller": 0.08, "agt-deployer": 0.16, "agt-wiper": 0.21}


def demo_cards(conn, catalog) -> list[dict]:
    return [build_card(conn, a["agent_id"], catalog, DEMO_APPROVAL_PATHS, DEMO_MCP_GRANTS,
                       DEMO_APPROVED_MCP, DEMO_REDTEAM_ASR)
            for a in registry.list_agents(conn) if a["agent_id"] in DEMO_REDTEAM_ASR]
