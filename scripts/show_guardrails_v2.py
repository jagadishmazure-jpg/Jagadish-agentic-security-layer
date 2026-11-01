"""Runtime guardrails v2: intent-bound actions, budgets, loop detection, kill switch, risk cards."""

import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))

from agelayer import effective, risk_card  # noqa: E402
from agelayer.demo_helpers import TOOL_CATALOG, build_demo_db  # noqa: E402
from agelayer.scenarios import budget_scenario, guard_scenario  # noqa: E402

g = guard_scenario()
for agent, tool, decision, rule in g["rows"]:
    print(f"guard {agent:<13} {tool:<15} {decision:<8} {rule}")
print(f"out-of-intent attempts {g['out_of_intent']}, blocked {g['out_of_intent_blocked']}; "
      f"audit chain valid: {g['chain_valid']}")
b = budget_scenario()
for name, r in b["runs"].items():
    print(f"budget {name:<14} ran {r['ran']:>3}/{r['planned_steps']} stop {r['stop_rule']:<9} "
          f"tokens avoided {r['tokens_avoided']:>10,} cost avoided ${r['cost_avoided']:.2f}")
print("(costs use synthetic per-1k-token prices, not vendor prices)")
conn = build_demo_db()
effective.init_db(conn)
effective.seed_effective(conn)
cards = risk_card.demo_cards(conn, TOOL_CATALOG)
for c in cards:
    print(f"card {c['agent_id']:<13} {c['autonomy']} owner={c['owner'] or '-':<14} "
          f"path={c['approval_path'] or 'MISSING':<16} score {c['score']:>3} {c['tier']:<8} {','.join(c['flags'])}")
gs = risk_card.governed_share(cards)
print(f"L2+ agents with owner and approval path: {gs['with_owner_and_path']}/{gs['l2_plus']}")
