"""MCP security: registry, pinning and drift, poisoning scan, shadowing, scoped tokens, discovery."""

import json
import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))

from agelayer import intent  # noqa: E402
from agelayer.mcp import poisoning  # noqa: E402
from agelayer.scenarios import mcp_scenario  # noqa: E402

ROOT = Path(__file__).resolve().parents[1]
m = mcp_scenario()
for label, decision, rule in m["rows"]:
    print(f"mcp {label:<42} {decision:<7} {rule}")
print("drift:", ", ".join(f"{d['rule_id']} {d['tool']}" for d in m["drift"]))
print("poisoned:", ", ".join(sorted({p["rule_id"] for p in m["poisoned"]})))
for c in m["collisions"]:
    print(f"collision {c['rule_id']} {c['entries']} suspect {c['suspect_servers']}")
for d in m["discovered"]:
    print(f"discovered {d['rule_id']} {d['host']} users {len(d['users'])}")
print("gateway kpis:", m["kpis"])
pe = poisoning.evaluate(json.loads((ROOT / "data/mcp_tool_descriptions.json").read_text())["cases"])
print(f"poison eval: {pe['cases']} cases, precision {pe['precision']}, recall {pe['recall']}, misses {pe['misses']}")
ie = intent.evaluate(json.loads((ROOT / "data/intent_eval.json").read_text())["cases"])
print(f"intent eval: {ie['cases']} cases, precision {ie['precision']}, recall {ie['recall']}, "
      f"misses {[(k, r) for k, r, _t in ie['misses']]}")
