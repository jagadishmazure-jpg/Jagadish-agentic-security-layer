"""Regression checks for the agentic security layer (stdlib only)."""

import sqlite3

import pytest

from agelayer import audit as audit_mod
from agelayer import bridge as bridge_mod
from agelayer import feedback as feedback_mod
from agelayer import graph as pgraph
from agelayer import impact as impact_mod
from agelayer import registry, views, zsp
from agelayer import shadow as shadow_mod
from agelayer.demo_helpers import TOOL_CATALOG, run_scenario

# ---------------------------------------------------------------- helpers


def fresh_db():
    conn = sqlite3.connect(":memory:")
    views.install(conn)
    return conn


def seeded_db():
    conn = fresh_db()
    registry.seed_demo(conn)
    return conn


# ---------------------------------------------------------------- registry

def test_register_and_get_roundtrip():
    conn = fresh_db()
    registry.register_agent(conn, "a1", "Agent One", "m1", ["read_tickets"],
                            ["support"], 1, "ops")
    got = registry.get_agent(conn, "a1")
    assert got["name"] == "Agent One"
    assert got["tools_granted"] == ["read_tickets"]
    assert got["autonomy_level"] == 1


def test_register_rejects_bad_autonomy():
    conn = fresh_db()
    with pytest.raises(ValueError):
        registry.register_agent(conn, "a1", "x", "m", [], [], 9, "ops")


def test_register_rejects_empty_id():
    conn = fresh_db()
    with pytest.raises(ValueError):
        registry.register_agent(conn, "", "x", "m", [], [], 1, "ops")


def test_register_rejects_bad_status():
    conn = fresh_db()
    with pytest.raises(ValueError):
        registry.register_agent(conn, "a1", "x", "m", [], [], 1, "ops",
                                status="ghost")


def test_seed_demo_deterministic():
    c1, c2 = seeded_db(), seeded_db()
    assert [a["agent_id"] for a in registry.list_agents(c1)] == \
           [a["agent_id"] for a in registry.list_agents(c2)]
    assert len(registry.list_agents(c1)) == 4


def test_set_status_suspend():
    conn = seeded_db()
    registry.set_status(conn, "agt-router", "suspended")
    assert registry.get_agent(conn, "agt-router")["status"] == "suspended"


# ---------------------------------------------------------------- shadow

def test_shadow_detects_unknown_caller():
    conn = seeded_db()
    activity = [{"caller_id": "ghost-1", "tool": "read_tickets",
                 "ts": "2026-10-18T08:00:00"}]
    findings = shadow_mod.detect(activity, conn, TOOL_CATALOG)
    assert len(findings) == 1
    assert findings[0]["caller_id"] == "ghost-1"
    assert findings[0]["rule_id"] == "SHADOW-01"


def test_shadow_ignores_registered_callers():
    conn = seeded_db()
    activity = [{"caller_id": "agt-router", "tool": "read_tickets",
                 "ts": "2026-10-18T08:00:00"}]
    assert shadow_mod.detect(activity, conn, TOOL_CATALOG) == []


def test_shadow_onboard_for_low_privilege():
    conn = seeded_db()
    activity = [{"caller_id": "ghost-1", "tool": "read_tickets",
                 "ts": "2026-10-18T08:00:00"}]
    (f,) = shadow_mod.detect(activity, conn, TOOL_CATALOG)
    assert f["recommendation"] == "onboard"
    assert f["privilege_score"] == 1


def test_shadow_block_for_destructive():
    conn = seeded_db()
    activity = [{"caller_id": "ghost-2", "tool": "purge_cache",
                 "ts": "2026-10-18T08:00:00"}]
    (f,) = shadow_mod.detect(activity, conn, TOOL_CATALOG)
    assert f["recommendation"] == "block"
    assert f["recommendation_rule"] == "SHADOW-02"


def test_shadow_block_for_high_score():
    conn = seeded_db()
    activity = [
        {"caller_id": "ghost-3", "tool": "write_invoice", "ts": "t1"},
        {"caller_id": "ghost-3", "tool": "deploy_service", "ts": "t2"},
        {"caller_id": "ghost-3", "tool": "rotate_secret", "ts": "t3"},
    ]
    (f,) = shadow_mod.detect(activity, conn, TOOL_CATALOG)
    assert f["privilege_score"] == 9
    assert f["recommendation"] == "block"


# ---------------------------------------------------------------- graph

def test_graph_blast_radius_reaches_tools_and_scopes():
    conn = seeded_db()
    g = pgraph.build(conn, TOOL_CATALOG)
    r = pgraph.blast_radius(g, "agt-deployer")
    assert "tool:deploy_service" in r["reachable"]
    assert "scope:production" in r["reachable"]
    assert "scope:secrets" in r["reachable"]
    assert r["paths"]["tool:deploy_service"] == [
        "agent:agt-deployer", "tool:deploy_service"]


def test_graph_blast_radius_transitive():
    conn = seeded_db()
    g = pgraph.build(conn, TOOL_CATALOG)
    r = pgraph.blast_radius(g, "agt-biller")
    # agent -> tool -> scope is two hops; all must appear
    assert "tool:read_customers" in r["reachable"]
    assert "scope:customers" in r["reachable"]
    assert len(r["paths"]["scope:customers"]) == 3


def test_graph_blast_radius_unknown_agent():
    conn = seeded_db()
    g = pgraph.build(conn, TOOL_CATALOG)
    with pytest.raises(KeyError):
        pgraph.blast_radius(g, "nope")


def test_graph_escalation_paths_find_sensitive():
    conn = seeded_db()
    g = pgraph.build(conn, TOOL_CATALOG)
    paths = pgraph.escalation_paths(g, "agt-deployer")
    targets = {p["target"] for p in paths}
    assert "tool:rotate_secret" in targets  # sensitivity 5
    assert "scope:secrets" in targets      # inherits 5
    for p in paths:
        assert p["path"][0] == "agent:agt-deployer"
        assert p["hops"] == len(p["path"]) - 1


def test_graph_escalation_paths_none_for_low_priv():
    conn = seeded_db()
    g = pgraph.build(conn, TOOL_CATALOG)
    paths = pgraph.escalation_paths(g, "agt-router")
    assert paths == []


# ---------------------------------------------------------------- impact

def test_impact_ranks_by_sensitivity():
    conn = seeded_db()
    g = pgraph.build(conn, TOOL_CATALOG)
    out = impact_mod.analyze_compromise(g, "agt-deployer")
    sens = [e["sensitivity"] for e in out["exposed"]]
    assert sens == sorted(sens, reverse=True)
    assert out["exposed"][0]["sensitivity"] == 5
    assert out["exposed"][0]["node"] in ("tool:rotate_secret", "scope:secrets")


def test_impact_actions_prioritized():
    conn = seeded_db()
    g = pgraph.build(conn, TOOL_CATALOG)
    out = impact_mod.analyze_compromise(g, "agt-deployer")
    prios = [a["priority"] for a in out["actions"]]
    assert prios == sorted(prios)
    assert out["actions"][0]["action"].startswith("suspend agent")
    assert any("revoke credentials" in a["action"] for a in out["actions"])


# ---------------------------------------------------------------- bridge

def test_bridge_allows_registered_read():
    conn = seeded_db()
    br = bridge_mod.Bridge(conn, TOOL_CATALOG)
    out = br.execute(bridge_mod.ActionRequest("agt-router", "read_tickets"))
    assert out["decision"] == "allowed"
    assert out["result"]["ok"] is True


def test_bridge_denies_unregistered_agent():
    conn = seeded_db()
    br = bridge_mod.Bridge(conn, TOOL_CATALOG)
    with pytest.raises(bridge_mod.BridgeDenied) as e:
        br.execute(bridge_mod.ActionRequest("ghost-1", "read_tickets"))
    assert e.value.policy_id == "BRIDGE-01"


def test_bridge_denies_ungranted_tool():
    conn = seeded_db()
    br = bridge_mod.Bridge(conn, TOOL_CATALOG)
    with pytest.raises(bridge_mod.BridgeDenied) as e:
        br.execute(bridge_mod.ActionRequest("agt-router", "write_invoice"))
    assert e.value.policy_id == "BRIDGE-02"


def test_bridge_denies_suspended_agent():
    conn = seeded_db()
    registry.set_status(conn, "agt-router", "suspended")
    br = bridge_mod.Bridge(conn, TOOL_CATALOG)
    with pytest.raises(bridge_mod.BridgeDenied) as e:
        br.execute(bridge_mod.ActionRequest("agt-router", "read_tickets"))
    assert e.value.policy_id == "BRIDGE-01"


def test_bridge_denies_l0_execution():
    conn = fresh_db()
    registry.register_agent(conn, "l0", "L0", "m", ["read_tickets"],
                            ["support"], 0, "ops")
    br = bridge_mod.Bridge(conn, TOOL_CATALOG)
    with pytest.raises(bridge_mod.BridgeDenied) as e:
        br.execute(bridge_mod.ActionRequest("l0", "read_tickets"))
    assert e.value.policy_id == "BRIDGE-03"


def test_bridge_write_needs_l2_or_elevation():
    conn = fresh_db()
    registry.register_agent(conn, "w1", "W1", "m", ["write_invoice"],
                            ["billing"], 1, "ops")
    br = bridge_mod.Bridge(conn, TOOL_CATALOG)
    with pytest.raises(bridge_mod.BridgeDenied) as e:
        br.execute(bridge_mod.ActionRequest("w1", "write_invoice"))
    assert e.value.policy_id == "BRIDGE-03"


def test_bridge_write_allowed_with_jit_elevation():
    conn = fresh_db()
    registry.register_agent(conn, "w1", "W1", "m", ["write_invoice"],
                            ["billing"], 1, "ops")
    br = bridge_mod.Bridge(conn, TOOL_CATALOG)
    elv = br.grant_elevation("w1", "write_invoice", approver="ops-lead")
    out = br.execute(bridge_mod.ActionRequest("w1", "write_invoice"),
                     elevation_id=elv)
    assert out["decision"] == "allowed"


def test_bridge_elevation_wrong_tool_denied():
    conn = fresh_db()
    registry.register_agent(conn, "w1", "W1", "m",
                            ["write_invoice", "deploy_service"],
                            ["billing"], 1, "ops")
    br = bridge_mod.Bridge(conn, TOOL_CATALOG)
    elv = br.grant_elevation("w1", "write_invoice", approver="ops-lead")
    with pytest.raises(bridge_mod.BridgeDenied):
        br.execute(bridge_mod.ActionRequest("w1", "deploy_service"),
                   elevation_id=elv)


def test_bridge_destructive_needs_human_approval():
    conn = fresh_db()
    registry.register_agent(conn, "d1", "D1", "m", ["purge_cache"],
                            ["cache"], 3, "ops")
    br = bridge_mod.Bridge(conn, TOOL_CATALOG)
    with pytest.raises(bridge_mod.BridgeDenied) as e:
        br.execute(bridge_mod.ActionRequest("d1", "purge_cache"))
    assert e.value.policy_id == "BRIDGE-04"


def test_bridge_destructive_allowed_with_approval():
    conn = fresh_db()
    registry.register_agent(conn, "d1", "D1", "m", ["purge_cache"],
                            ["cache"], 3, "ops")
    br = bridge_mod.Bridge(conn, TOOL_CATALOG)
    apr = br.approve("d1", "purge_cache", approver="ops-lead")
    out = br.execute(bridge_mod.ActionRequest("d1", "purge_cache",
                                              approval_id=apr))
    assert out["decision"] == "allowed"


def test_bridge_logs_every_decision():
    conn = seeded_db()
    decisions = []
    br = bridge_mod.Bridge(conn, TOOL_CATALOG, audit_log=decisions)
    br.execute(bridge_mod.ActionRequest("agt-router", "read_tickets"))
    with pytest.raises(bridge_mod.BridgeDenied):
        br.execute(bridge_mod.ActionRequest("ghost-1", "read_tickets"))
    assert [d["decision"] for d in decisions] == ["allowed", "denied"]
    assert decisions[1]["policy_id"] == "BRIDGE-01"


# ---------------------------------------------------------------- zsp

def test_zsp_perfect_score():
    conn = fresh_db()
    registry.register_agent(conn, "r1", "R1", "m", ["read_tickets"],
                            ["support"], 1, "ops")
    out = zsp.score(conn, TOOL_CATALOG, jit_action_count=5,
                    total_privileged_actions=5, rotated_within_30d=2,
                    total_credentials=2, shadow_count=0)
    assert out["score"] == 100.0
    assert out["improvements"] == []


def test_zsp_penalizes_shadow():
    conn = fresh_db()
    registry.register_agent(conn, "r1", "R1", "m", ["read_tickets"],
                            ["support"], 1, "ops")
    out = zsp.score(conn, TOOL_CATALOG, jit_action_count=5,
                    total_privileged_actions=5, rotated_within_30d=2,
                    total_credentials=2, shadow_count=2)
    # 2 shadows -> shadow component 50 -> contributes 10 instead of 20
    assert out["score"] == 90.0
    assert any(i["area"] == "shadow agents" for i in out["improvements"])


def test_zsp_flags_standing_write():
    conn = seeded_db()
    out = zsp.score(conn, TOOL_CATALOG, jit_action_count=0,
                    total_privileged_actions=4, rotated_within_30d=0,
                    total_credentials=4, shadow_count=0)
    assert out["components"]["no_standing_write_pct"] < 100
    assert out["improvements"][0]["area"] == "standing write access"


# ---------------------------------------------------------------- gateway + authorizer

def test_gateway_allows_view_query():
    conn = seeded_db()
    rows = views.run_query(conn, "SELECT agent_id FROM v_agent_posture")
    assert {r[0] for r in rows} == {"agt-router", "agt-biller",
                                   "agt-deployer", "agt-wiper"}


def test_gateway_denies_raw_table_text_check():
    conn = seeded_db()
    with pytest.raises(views.GatewayDenied) as e:
        views.run_query(conn, "SELECT * FROM agents")
    assert e.value.policy_id == "SEC-SELECT-02"


def test_gateway_denies_write():
    conn = seeded_db()
    with pytest.raises(views.GatewayDenied) as e:
        views.run_query(conn, "DELETE FROM agents")
    assert e.value.policy_id == "SEC-SELECT-01"


def _authorizer_denies(sql):
    """Helper: text check bypassed, authorizer must deny alone."""
    conn = seeded_db()
    with pytest.raises(views.GatewayDenied) as e:
        views.run_query_authorizer_only(conn, sql)
    assert e.value.policy_id == "SEC-SELECT-03"


def test_authorizer_denies_raw_table_bypassed_check():
    _authorizer_denies("SELECT * FROM agents")


def test_authorizer_denies_comma_join_bypassed_check():
    _authorizer_denies("SELECT * FROM agents, v_agent_posture")


def test_authorizer_denies_quoted_table_bypassed_check():
    _authorizer_denies('SELECT * FROM "agents"')


def test_authorizer_denies_parenthesised_table_bypassed_check():
    _authorizer_denies("SELECT * FROM (agents)")


def test_authorizer_denies_comment_whitespace_bypassed_check():
    _authorizer_denies("SELECT * FROM/**/agents")


def test_authorizer_denies_sqlite_master_bypassed_check():
    _authorizer_denies("SELECT name FROM sqlite_master")


def test_authorizer_denies_load_extension_bypassed_check():
    conn = seeded_db()
    with pytest.raises(views.GatewayDenied):
        views.run_query_authorizer_only(conn, "SELECT load_extension('x')")


def test_authorizer_allows_legit_view_bypassed_check():
    conn = seeded_db()
    rows = views.run_query_authorizer_only(
        conn, "SELECT agent_id FROM v_agent_posture WHERE status='active'")
    assert len(rows) == 3


def test_authorizer_allows_count_star_bypassed_check():
    conn = seeded_db()
    rows = views.run_query_authorizer_only(
        conn, "SELECT count(*) FROM v_agent_posture")
    assert rows[0][0] == 4


# ---------------------------------------------------------------- audit

def test_audit_chain_verifies():
    log = audit_mod.AuditLog()
    log.record("bridge", {"a": 1})
    log.record("shadow_finding", {"b": 2})
    assert log.verify()


def test_audit_tamper_detected():
    log = audit_mod.AuditLog()
    log.record("bridge", {"a": 1})
    log.entries[0]["payload"]["a"] = 999
    assert not log.verify()


# ---------------------------------------------------------------- feedback

def test_feedback_scrubs_phones():
    assert feedback_mod.scrub("call (555) 123-4567 now") == "call [PHONE] now"
    assert feedback_mod.scrub("call 555.123.4567 now") == "call [PHONE] now"
    assert feedback_mod.scrub("call +1 (555) 123-4567") == "call [PHONE]"


def test_feedback_scrubs_ssn_and_email():
    assert feedback_mod.scrub("ssn 123-45-6789") == "ssn [SSN]"
    assert feedback_mod.scrub("mail a@b.com here") == "mail [EMAIL] here"


def test_feedback_keeps_dates():
    assert feedback_mod.scrub("on 2026-10-18 we met") == "on 2026-10-18 we met"


def test_feedback_validate_reports_pii():
    out = feedback_mod.validate_feedback("call (555) 123-4567")
    assert out["pii_found"] is True
    assert "[PHONE]" in out["scrubbed"]


# ---------------------------------------------------------------- demo

def test_demo_scenario_deterministic():
    a, b = run_scenario(), run_scenario()
    assert a["zsp_score"] == b["zsp_score"]
    assert a["blast_radius_nodes"] == b["blast_radius_nodes"]
    assert a["audit_valid"] and b["audit_valid"]


def test_demo_scenario_finds_both_shadows():
    out = run_scenario()
    recs = {f["caller_id"]: f["recommendation"]
            for f in out["shadow_findings"]}
    assert recs == {"ghost-helper": "onboard", "rogue-cleaner": "block"}


# ---------- review fixes (grokbot-portfolio, 2026-10-18) ----------
from datetime import datetime, timedelta, timezone  # noqa: E402

from agelayer.audit import AuditLog  # noqa: E402

T0 = datetime(2026, 10, 18, 9, 0, tzinfo=timezone.utc)


class Clock:
    def __init__(self):
        self.now = T0

    def __call__(self):
        return self.now


def _destructive_agent(conn, level=3):
    registry.register_agent(conn, "d1", "D1", "m", ["purge_cache"], ["cache"], level, "ops")


def test_agent_cannot_approve_its_own_destructive_action():
    conn = fresh_db()
    _destructive_agent(conn)
    br = bridge_mod.Bridge(conn, TOOL_CATALOG)
    with pytest.raises(bridge_mod.BridgeDenied) as e:
        br.execute(bridge_mod.ActionRequest("d1", "purge_cache", human_approved=True))
    assert e.value.policy_id == "BRIDGE-04"
    for who in ("d1", "", "agt-router"):  # the agent itself, nobody, another agent
        registry.seed_demo(conn)
        with pytest.raises(bridge_mod.BridgeDenied) as e:
            br.approve("d1", "purge_cache", approver=who)
        assert e.value.policy_id == "BRIDGE-06"


def test_approval_is_single_use_scoped_and_expires():
    conn = fresh_db()
    _destructive_agent(conn)
    registry.register_agent(conn, "d2", "D2", "m", ["purge_cache"], ["cache"], 3, "ops")
    clock = Clock()
    br = bridge_mod.Bridge(conn, TOOL_CATALOG, clock=clock)
    apr = br.approve("d1", "purge_cache", approver="ops-lead")
    with pytest.raises(bridge_mod.BridgeDenied) as e:  # other agent
        br.execute(bridge_mod.ActionRequest("d2", "purge_cache", approval_id=apr))
    assert e.value.policy_id == "BRIDGE-05"
    assert br.execute(bridge_mod.ActionRequest("d1", "purge_cache", approval_id=apr))["decision"] == "allowed"
    with pytest.raises(bridge_mod.BridgeDenied) as e:  # reuse
        br.execute(bridge_mod.ActionRequest("d1", "purge_cache", approval_id=apr))
    assert e.value.policy_id == "BRIDGE-05"
    late = br.approve("d1", "purge_cache", approver="ops-lead", ttl_min=15)
    clock.now = T0 + timedelta(minutes=16)
    with pytest.raises(bridge_mod.BridgeDenied) as e:
        br.execute(bridge_mod.ActionRequest("d1", "purge_cache", approval_id=late))
    assert e.value.policy_id == "BRIDGE-05"


def test_destructive_still_needs_l2_even_with_approval():
    conn = fresh_db()
    _destructive_agent(conn, level=1)
    br = bridge_mod.Bridge(conn, TOOL_CATALOG)
    apr = br.approve("d1", "purge_cache", approver="ops-lead")
    with pytest.raises(bridge_mod.BridgeDenied) as e:
        br.execute(bridge_mod.ActionRequest("d1", "purge_cache", approval_id=apr))
    assert e.value.policy_id == "BRIDGE-04"


def test_jit_elevation_expires():
    conn = fresh_db()
    registry.register_agent(conn, "w1", "W1", "m", ["write_invoice"], ["billing"], 1, "ops")
    clock = Clock()
    br = bridge_mod.Bridge(conn, TOOL_CATALOG, clock=clock)
    elv = br.grant_elevation("w1", "write_invoice", approver="ops-lead", expires_min=30)
    assert br.execute(bridge_mod.ActionRequest("w1", "write_invoice"), elevation_id=elv)["decision"] == "allowed"
    clock.now = T0 + timedelta(minutes=31)
    with pytest.raises(bridge_mod.BridgeDenied) as e:
        br.execute(bridge_mod.ActionRequest("w1", "write_invoice"), elevation_id=elv)
    assert e.value.policy_id == "BRIDGE-05"
    with pytest.raises(ValueError):
        br.grant_elevation("w1", "write_invoice", approver="ops-lead", expires_min=10_000)


def test_tool_missing_from_catalog_is_treated_as_destructive():
    conn = fresh_db()
    registry.register_agent(conn, "x1", "X1", "m", ["wipe_everything"], ["prod"], 3, "ops")
    br = bridge_mod.Bridge(conn, TOOL_CATALOG)
    with pytest.raises(bridge_mod.BridgeDenied) as e:
        br.execute(bridge_mod.ActionRequest("x1", "wipe_everything"))
    assert e.value.policy_id == "BRIDGE-04"
    f = shadow_mod.detect([{"caller_id": "ghost", "tool": "wipe_everything"}], conn, TOOL_CATALOG)
    assert f[0]["recommendation"] == "block"


def test_revoked_agent_denied_and_its_activity_flagged():
    conn = seeded_db()
    registry.set_status(conn, "agt-router", "revoked")
    br = bridge_mod.Bridge(conn, TOOL_CATALOG)
    with pytest.raises(bridge_mod.BridgeDenied) as e:
        br.execute(bridge_mod.ActionRequest("agt-router", "read_tickets"))
    assert e.value.policy_id == "BRIDGE-01"
    findings = shadow_mod.detect([{"caller_id": "agt-wiper", "tool": "read_logs"},
                                  {"caller_id": "agt-router", "tool": "read_tickets"}],
                                 conn, TOOL_CATALOG)
    assert {(f["caller_id"], f["rule_id"], f["recommendation"]) for f in findings} == {
        ("agt-router", "SHADOW-03", "block"), ("agt-wiper", "SHADOW-03", "block")}


def test_every_bridge_decision_is_hash_chained():
    conn = seeded_db()
    log = AuditLog()
    br = bridge_mod.Bridge(conn, TOOL_CATALOG, chain=log)
    br.execute(bridge_mod.ActionRequest("agt-router", "read_tickets"))
    with pytest.raises(bridge_mod.BridgeDenied):
        br.execute(bridge_mod.ActionRequest("agt-router", "write_invoice"))
    decisions = [e for e in log.entries if e["kind"] == "bridge.decision"]
    assert [d["payload"]["decision"] for d in decisions] == ["allowed", "denied"]
    assert log.verify()
    log.entries[0]["payload"]["decision"] = "denied"
    assert not log.verify()


def test_denials_and_shadow_callers_reach_the_read_views():
    conn = seeded_db()
    br = bridge_mod.Bridge(conn, TOOL_CATALOG, clock=Clock())
    for req in (bridge_mod.ActionRequest("agt-router", "write_invoice"),
                bridge_mod.ActionRequest("ghost-7", "purge_cache")):
        with pytest.raises(bridge_mod.BridgeDenied):
            br.execute(req)
    denials = views.run_query(conn, "SELECT agent_id, policy_id FROM v_bridge_denials ORDER BY denial_id")
    assert [tuple(r) for r in denials] == [("agt-router", "BRIDGE-02"), ("ghost-7", "BRIDGE-01")]
    shadows = views.run_query(conn, "SELECT caller_id, recommendation FROM v_shadow_findings")
    assert [tuple(r) for r in shadows] == [("ghost-7", "block")]


def test_posture_view_tool_count_is_exact():
    conn = fresh_db()
    registry.register_agent(conn, "a0", "A0", "m", [], [], 0, "ops")
    registry.register_agent(conn, "a3", "A3", "m", ["t1", "t2", "t3"], [], 1, "ops")
    rows = dict(tuple(r) for r in views.run_query(conn, "SELECT agent_id, tool_count FROM v_agent_posture"))
    assert rows == {"a0": 0, "a3": 3}


def test_zsp_counts_unknown_tools_as_standing_write_and_validates_inputs():
    conn = fresh_db()
    registry.register_agent(conn, "x1", "X1", "m", ["mystery_tool"], [], 2, "ops")
    s = zsp.score(conn, TOOL_CATALOG, 0, 0, 0, 0, 0)
    assert s["components"]["no_standing_write_pct"] == 0.0
    with pytest.raises(ValueError, match="ZSP-INPUT-01"):
        zsp.score(conn, TOOL_CATALOG, 5, 3, 0, 0, 0)
    with pytest.raises(ValueError, match="ZSP-INPUT-01"):
        zsp.score(conn, TOOL_CATALOG, 0, 0, 0, 0, -1)
