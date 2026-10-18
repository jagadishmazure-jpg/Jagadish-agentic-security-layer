"""Print what this repo does that the posture scanner does not: runtime,
per-action enforcement at the bridge (with human approvals the agent cannot
assert itself) and shadow-agent detection from activity logs."""

import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))

from agelayer.demo_helpers import run_scenario  # noqa: E402

out = run_scenario()
for f in out["shadow_findings"]:
    print(f"shadow {f['caller_id']:<14} {f['rule_id']} -> {f['recommendation']} "
          f"(score {f['privilege_score']})")
for d in out["bridge_decisions"]:
    who = f" by {d['approver']}" if d.get("approver") else ""
    print(f"bridge {d['agent_id']:<13} {d['tool']:<15} {d['decision']:<7} "
          f"{d['policy_id'] or ''}{who}")
print(f"denials in v_bridge_denials: {out['denials_in_view']}, "
      f"shadow callers in v_shadow_findings: {out['shadow_in_view']}")
print(f"blast radius of agt-deployer: {out['blast_radius_nodes']} nodes, "
      f"{out['escalation_paths']} escalation paths, {out['compromise_exposed']} exposed on compromise")
print("zsp improvements:", [(i["priority"], i["area"]) for i in out["zsp_improvements"]])
print(f"zsp score: {out['zsp_score']}; audit entries {out['audit_entries']}, "
      f"chain valid: {out['audit_valid']}")
