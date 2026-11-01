import pytest

from agelayer.bridge import Bridge, BridgeDenied
from agelayer.budget import Budget, BudgetStop, KillSwitch
from agelayer.demo_helpers import DEMO_APPROVER, DEMO_NOW, TOOL_CATALOG, build_demo_db
from agelayer.guarded import GuardedSession, runaway_simulation
from agelayer.scenarios import budget_scenario, guard_scenario


@pytest.fixture
def br():
    return Bridge(build_demo_db(), TOOL_CATALOG, clock=lambda: DEMO_NOW)


def test_in_scope_call_allowed(br):
    s = GuardedSession(br, "agt-router", "Summarise ticket TCK-1")
    assert s.call("read_tickets", {"ticket_id": "TCK-1"}) is not None
    assert s.stats.allowed == 1


def test_out_of_intent_blocked_before_bridge(br):
    s = GuardedSession(br, "agt-router", "Summarise ticket TCK-1")
    with pytest.raises(BridgeDenied) as e:
        s.call("read_orders", {})
    assert e.value.policy_id == "INTENT-01"
    assert s.stats.out_of_intent_blocked == 1


def test_flag_mode_still_hits_bridge(br):
    s = GuardedSession(br, "agt-router", "Summarise ticket TCK-1", intent_mode="flag")
    s.call("read_orders", {})
    assert s.stats.out_of_intent == 1 and s.stats.out_of_intent_blocked == 0
    assert s.log[0]["decision"] == "flagged"


def test_bad_mode(br):
    with pytest.raises(ValueError):
        GuardedSession(br, "agt-router", "x", intent_mode="off")


def test_bridge_still_enforces_grants(br):
    s = GuardedSession(br, "agt-router", "Create an invoice for order ORD-1")
    with pytest.raises(BridgeDenied) as e:
        s.call("write_invoice", {"order_id": "ORD-1"})
    assert e.value.policy_id == "BRIDGE-02"
    assert s.stats.bridge_denials == 1


def test_destructive_still_needs_human_approval():
    from agelayer import registry
    conn = build_demo_db()
    registry.register_agent(conn, "agt-cache", "Cache", "fm-small-1", ["purge_cache"], ["cache"], 3, "ops-team")
    br = Bridge(conn, TOOL_CATALOG, clock=lambda: DEMO_NOW)
    s = GuardedSession(br, "agt-cache", "Clear the cache for pricing")
    with pytest.raises(BridgeDenied) as e:
        s.call("purge_cache", {})
    assert e.value.policy_id == "BRIDGE-04"
    aid = br.approve("agt-cache", "purge_cache", DEMO_APPROVER)
    from agelayer.bridge import ActionRequest
    assert br.execute(ActionRequest("agt-cache", "purge_cache", {}, approval_id=aid)) is not None


def test_kill_switch_stops_session(br):
    k = KillSwitch()
    s = GuardedSession(br, "agt-router", "Summarise ticket TCK-1", kill_switch=k)
    s.call("read_tickets", {"ticket_id": "TCK-1"})
    k.trip("r.osei", agent_id="agt-router")
    with pytest.raises(BudgetStop):
        s.call("read_tickets", {"ticket_id": "TCK-1", "n": 2})
    assert s.stats.budget_stops == {"KILL-01": 1}


def test_token_cap_stops_next_call(br):
    s = GuardedSession(br, "agt-router", "List tickets", budget=Budget(max_tokens=1000))
    s.call("read_tickets", {"p": 1}, tokens_in=1200, tokens_out=0)
    with pytest.raises(BudgetStop) as e:
        s.call("read_tickets", {"p": 2})
    assert e.value.rule_id == "BUDGET-02"


def test_decisions_in_hash_chain(br):
    s = GuardedSession(br, "agt-router", "List tickets")
    s.call("read_tickets", {})
    with pytest.raises(BridgeDenied):
        s.call("drop_database", {})
    assert br.chain.verify()
    guard = [e["payload"] for e in br.chain.entries if e["kind"] == "guard.decision"]
    assert [g["decision"] for g in guard] == ["allowed", "denied"]


def test_runaway_always_stops(br):
    r = runaway_simulation(br, "agt-router", "List tickets", 1000, "read_tickets", 1000, "fm-med-1",
                           Budget(max_steps=30, max_tokens=10_000))
    assert r["stop_rule"] == "BUDGET-02" and r["ran"] == 10
    assert r["tokens_avoided"] == 1000 * 1000 - 10_000


def test_guard_scenario_measured():
    g = guard_scenario()
    assert (g["out_of_intent"], g["out_of_intent_blocked"], g["chain_valid"]) == (6, 6, True)
    assert [r[3] for r in g["rows"] if r[2] == "stopped"] == ["KILL-01", "KILL-02"]


def test_budget_scenario_measured():
    b = budget_scenario()
    assert {k: v["stop_rule"] for k, v in b["runs"].items()} == {
        "token_runaway": "BUDGET-02", "cost_runaway": "BUDGET-03",
        "step_runaway": "BUDGET-01", "tight_loop": "LOOP-01"}
    assert b["tokens_avoided"] == 12_056_900
