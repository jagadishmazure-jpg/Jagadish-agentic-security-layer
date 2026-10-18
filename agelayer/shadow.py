"""Shadow-AI detection: find unregistered agents exercising privileges.

Activity logs record tool calls with caller ids. Any caller not present in
the agent registry is a shadow agent. Each shadow agent is scored by the
privilege it exercised and gets an onboard-or-block recommendation:

  SHADOW-01 - unknown caller observed (always raised)
  SHADOW-02 - block recommended: exercised privilege at/above threshold
              (default: any destructive tool use, or score >= 8)
"""

from __future__ import annotations

from . import registry

# Privilege weight per tool category. Unknown tools are treated as write (3).
_CATEGORY_WEIGHT = {"read": 1, "write": 3, "destructive": 8}
BLOCK_THRESHOLD = 8


def detect(activity: list[dict], conn, tool_catalog: dict,
           block_threshold: int = BLOCK_THRESHOLD) -> list[dict]:
    """Return shadow findings for callers not in the registry.

    activity: list of {caller_id, tool, ts}
    tool_catalog: {tool_name: {"category": "read"|"write"|"destructive"}}
    """
    known = {a["agent_id"] for a in registry.list_agents(conn)}
    by_caller: dict[str, dict] = {}
    for event in activity:
        caller = event.get("caller_id")
        if not caller or caller in known:
            continue
        entry = by_caller.setdefault(caller, {"tools": set(), "events": 0})
        entry["tools"].add(event.get("tool"))
        entry["events"] += 1

    findings = []
    for caller in sorted(by_caller):
        info = by_caller[caller]
        score = 0
        for tool in info["tools"]:
            cat = tool_catalog.get(tool, {}).get("category", "write")
            score += _CATEGORY_WEIGHT.get(cat, 3)
        destructive = any(
            tool_catalog.get(t, {}).get("category") == "destructive"
            for t in info["tools"]
        )
        block = destructive or score >= block_threshold
        findings.append({
            "caller_id": caller,
            "rule_id": "SHADOW-01",
            "tools_seen": sorted(info["tools"]),
            "events": info["events"],
            "privilege_score": score,
            "recommendation": "block" if block else "onboard",
            "recommendation_rule": "SHADOW-02" if block else "SHADOW-01",
        })
    return findings
