"""Shadow-AI detection: find unregistered agents exercising privileges.

Activity logs record tool calls with caller ids. Any caller not present in
the agent registry is a shadow agent. Each shadow agent is scored by the
privilege it exercised and gets an onboard-or-block recommendation:

  SHADOW-01 - unknown caller observed (always raised)
  SHADOW-02 - block recommended: exercised privilege at/above threshold
              (default: any destructive tool use, or score >= 8)
  SHADOW-03 - a suspended or revoked agent is still acting: its credential
              is live somewhere, so block is always recommended
"""

from __future__ import annotations

from . import registry

# Privilege weight per tool category. Unknown tools are treated as destructive
# (fail-closed, same default as the bridge).
_CATEGORY_WEIGHT = {"read": 1, "write": 3, "destructive": 8}
BLOCK_THRESHOLD = 8


def detect(activity: list[dict], conn, tool_catalog: dict,
           block_threshold: int = BLOCK_THRESHOLD) -> list[dict]:
    """Return shadow findings for callers not in the registry.

    activity: list of {caller_id, tool, ts}
    tool_catalog: {tool_name: {"category": "read"|"write"|"destructive"}}
    """
    agents = {a["agent_id"]: a for a in registry.list_agents(conn)}
    known = {k for k, a in agents.items() if a["status"] == "active"}
    by_caller: dict[str, dict] = {}
    for event in activity:
        caller = event.get("caller_id")
        if not caller or caller in known:
            continue
        entry = by_caller.setdefault(caller, {"tools": set(), "events": 0})
        entry["tools"].add(event.get("tool") or "<none>")
        entry["events"] += 1

    findings = []
    for caller in sorted(by_caller):
        info = by_caller[caller]
        score = 0
        for tool in info["tools"]:
            cat = tool_catalog.get(tool, {}).get("category", "destructive")
            score += _CATEGORY_WEIGHT.get(cat, 8)
        destructive = any(
            tool_catalog.get(t, {}).get("category", "destructive") == "destructive"
            for t in info["tools"]
        )
        block = destructive or score >= block_threshold
        inactive = caller in agents
        if inactive:
            block = True
        findings.append({
            "caller_id": caller,
            "rule_id": "SHADOW-03" if inactive else "SHADOW-01",
            "tools_seen": sorted(info["tools"]),
            "events": info["events"],
            "privilege_score": score,
            "recommendation": "block" if block else "onboard",
            "recommendation_rule": ("SHADOW-03" if inactive else
                                    "SHADOW-02" if block else "SHADOW-01"),
        })
    return findings


def persist(conn, findings: list[dict], observed=None) -> int:
    """Write findings to ``shadow_findings`` (read through v_shadow_findings).

    One row per caller (upsert), so repeated scans do not duplicate."""
    ts = (observed.isoformat(timespec="seconds") if observed is not None
          else "1970-01-01T00:00:00")
    for f in findings:
        conn.execute(
            "INSERT OR REPLACE INTO shadow_findings VALUES (?,?,?,?,?)",
            ("SHD-" + f["caller_id"], f["caller_id"], f["privilege_score"],
             f["recommendation"], ts))
    conn.commit()
    return len(findings)
