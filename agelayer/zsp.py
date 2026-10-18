"""Zero-standing-privilege (ZSP) posture scorer.

Scores the environment 0-100 from four components:

  30 pts - share of agents with no standing WRITE access
           (grants are read-only, or writes only via JIT)
  30 pts - share of privileged actions executed via JIT elevation
  20 pts - share of agent credentials rotated within 30 days
  20 pts - shadow penalty: -5 per shadow agent, floored at 0

Returns the score plus a prioritized improvement list.
"""

from __future__ import annotations

from . import registry

WRITE_CATEGORIES = {"write", "destructive"}


def score(conn, tool_catalog: dict, jit_action_count: int,
          total_privileged_actions: int, rotated_within_30d: int,
          total_credentials: int, shadow_count: int) -> dict:
    for name, v in (("jit_action_count", jit_action_count),
                    ("total_privileged_actions", total_privileged_actions),
                    ("rotated_within_30d", rotated_within_30d),
                    ("total_credentials", total_credentials),
                    ("shadow_count", shadow_count)):
        if v < 0:
            raise ValueError(f"ZSP-INPUT-01: {name} must be >= 0")
    if jit_action_count > total_privileged_actions:
        raise ValueError("ZSP-INPUT-01: JIT actions cannot exceed privileged actions")
    if rotated_within_30d > total_credentials:
        raise ValueError("ZSP-INPUT-01: rotated credentials cannot exceed total")
    agents = [a for a in registry.list_agents(conn)
              if a["status"] == "active"]
    n = len(agents)

    if n:
        no_standing_write = sum(
            1 for a in agents
            if not any(tool_catalog.get(t, {}).get("category", "destructive")
                       in WRITE_CATEGORIES
                       for t in a["tools_granted"]))
        comp_write = 100.0 * no_standing_write / n
    else:
        comp_write = 100.0

    comp_jit = (100.0 * jit_action_count / total_privileged_actions
                if total_privileged_actions else 100.0)
    comp_rot = (100.0 * rotated_within_30d / total_credentials
                if total_credentials else 100.0)
    comp_shadow = max(0.0, 100.0 - 25.0 * shadow_count)

    total = round(0.30 * comp_write + 0.30 * comp_jit
                  + 0.20 * comp_rot + 0.20 * comp_shadow, 1)

    improvements = []
    if comp_write < 100:
        improvements.append(
            {"priority": 1, "area": "standing write access",
             "detail": f"{100 - comp_write:.0f}% of agents hold standing write grants; "
                       "move writes behind JIT elevation"})
    if shadow_count:
        improvements.append(
            {"priority": 2, "area": "shadow agents",
             "detail": f"{shadow_count} unregistered caller(s) observed; "
                       "onboard or block"})
    if comp_jit < 100:
        improvements.append(
            {"priority": 3, "area": "JIT adoption",
             "detail": f"only {comp_jit:.0f}% of privileged actions used JIT elevation"})
    if comp_rot < 100:
        improvements.append(
            {"priority": 4, "area": "credential rotation",
             "detail": f"{100 - comp_rot:.0f}% of credentials older than 30 days"})
    improvements.sort(key=lambda i: i["priority"])
    return {
        "score": total,
        "components": {
            "no_standing_write_pct": round(comp_write, 1),
            "jit_pct": round(comp_jit, 1),
            "rotated_pct": round(comp_rot, 1),
            "shadow_component": round(comp_shadow, 1),
        },
        "improvements": improvements,
    }
