"""Shadow AI and SaaS discovery, browser AI usage policy, extension risk, coding-agent guard (synthetic data)."""

import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))

from agelayer import extensions, shadow_ai  # noqa: E402
from agelayer.scenarios import browser_scenario, coding_scenario  # noqa: E402

inv = shadow_ai.discover(shadow_ai.synthetic_events())
print("app                                      state         users risk  recommendation")
for r in sorted(inv["apps"], key=lambda r: (-r["risk"], r["key"])):
    print(f"{r['key']:<40} {r['sanction']:<13} {r['users']:>5} {r['risk']:>4}  {r['recommendation']}")
k = shadow_ai.kpis(inv)
print(f"coverage {k['inventory_coverage']:.1%} ({k['ai_apps_known']}/{k['ai_apps_seen']}), "
      f"shadow users {k['shadow_users']}/{k['ai_users']}, personal-account users {k['personal_account_users']}")
print(f"findings: {len(inv['findings'])} ({', '.join(sorted({f['rule_id'] for f in inv['findings']}))})")
b = browser_scenario()
print("browser policy:", ", ".join(f"{a} {n}" for a, n in b["actions"].items()), f"of {b['total']} events")
print("by state:", ", ".join(f"{s} {n}" for s, n in b["by_state"].items()))
for r in extensions.assess(extensions.demo_inventory()):
    print(f"ext {r['ext_id']:<17} score {r['score']:>3} {r['recommendation']:<17} {','.join(r['rules']) or '-'}")
for s in coding_scenario():
    rules = ", ".join(f"{f['rule_id']}:{f['type']}" for f in s["findings"]) or "clean"
    print(f"coding {s['session_id']} blocked turns {s['blocked_turns']} -> {rules}")
