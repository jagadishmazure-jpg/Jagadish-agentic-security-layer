"""Regression checks for the effective-privilege layer (stdlib only)."""

import sqlite3

import pytest

from agelayer import effective as eff_mod
from agelayer import impact as impact_mod
from agelayer import registry
from agelayer import views
from agelayer.demo_helpers import TOOL_CATALOG


def fresh_db():
    conn = sqlite3.connect(":memory:")
    views.install(conn)
    return conn


def seeded_db():
    conn = fresh_db()
    registry.seed_demo(conn)
    eff_mod.seed_effective(conn)
    return conn


# ------------------------------------------------------- nested groups (EFF-01)

def test_nested_group_single_level_resolves():
    conn = seeded_db()
    eff = eff_mod.effective_privilege(conn, "agt-router", TOOL_CATALOG)
    assert "read_customers" in eff["tools"]  # via grp-support-leads
    assert "read_customers" in eff["indirect_tools"]
    assert eff_mod.EFF_NESTED in eff["mechanisms"]["read_customers"]


def test_nested_group_two_levels_resolves():
    conn = seeded_db()
    eff = eff_mod.effective_privilege(conn, "agt-router", TOOL_CATALOG)
    # agt-router -> grp-support-leads -> grp-data-team -> write_invoice
    assert "write_invoice" in eff["tools"]
    paths = eff["paths"]["write_invoice"]
    assert any(p == ["agent:agt-router", "group:grp-support-leads",
                     "group:grp-data-team", "tool:write_invoice"]
               for p in paths)


# ------------------------------------------------------- wildcard (EFF-02)

def test_wildcard_grant_expands_to_all_tools():
    conn = seeded_db()
    eff = eff_mod.effective_privilege(conn, "agt-deployer", TOOL_CATALOG)
    for tool in TOOL_CATALOG:
        assert tool in eff["tools"]
    assert eff_mod.EFF_WILDCARD in eff["mechanisms"]["drop_database"]


def test_wildcard_does_not_leak_to_non_members():
    conn = seeded_db()
    eff = eff_mod.effective_privilege(conn, "agt-biller", TOOL_CATALOG)
    assert "drop_database" not in eff["tools"]


# ------------------------------------------------------- dormant grants (EFF-03)

def test_dormant_grant_included_in_effective():
    conn = seeded_db()
    eff = eff_mod.effective_privilege(conn, "agt-biller", TOOL_CATALOG)
    assert "deploy_service" in eff["tools"]
    assert eff_mod.EFF_DORMANT in eff["mechanisms"]["deploy_service"]


def test_dormant_grant_absent_from_direct_review():
    conn = seeded_db()
    eff = eff_mod.effective_privilege(conn, "agt-biller", TOOL_CATALOG)
    assert "deploy_service" not in eff["direct_tools"]


# ------------------------------------------------------- hidden escalations

def test_hidden_escalations_finds_indirect_only_privilege():
    conn = seeded_db()
    findings = eff_mod.hidden_escalations(conn, TOOL_CATALOG)
    hit = [f for f in findings
           if f["agent"] == "agt-router"
           and f["privilege"] == "tool:rotate_secret"]
    assert len(hit) == 1
    assert hit[0]["sensitivity"] == 5
    assert eff_mod.EFF_DORMANT in hit[0]["rule_ids"]


def test_hidden_escalations_cites_rule_ids():
    conn = seeded_db()
    findings = eff_mod.hidden_escalations(conn, TOOL_CATALOG)
    assert findings, "seed must produce at least one hidden escalation"
    for f in findings:
        assert f["rule_ids"], "every finding must cite its rule IDs"
        assert set(f["rule_ids"]) <= {eff_mod.EFF_NESTED, eff_mod.EFF_WILDCARD,
                                      eff_mod.EFF_DORMANT}
        assert f["paths"], "every finding must cite its paths"


def test_direct_grant_review_misses_hidden_escalation():
    """Core value prop: direct-only review says agt-router is low-privilege;
    effective review proves it can touch secrets."""
    conn = seeded_db()
    eff = eff_mod.effective_privilege(conn, "agt-router", TOOL_CATALOG)
    assert "rotate_secret" not in eff["direct_tools"]
    assert "rotate_secret" in eff["tools"]
    assert "secrets" in eff["scopes"]


# ------------------------------------------------------- privilege paths

def test_privilege_paths_lists_every_hop():
    conn = seeded_db()
    paths = eff_mod.privilege_paths(conn, "agt-router", "tool:write_invoice",
                                    TOOL_CATALOG)
    assert paths, "expected at least one path"
    for p in paths:
        assert p["path"][0] == "agent:agt-router"
        assert p["path"][-1] == "tool:write_invoice"
        assert "group:grp-data-team" in p["path"]
        assert p["mechanisms"], "each path must cite its mechanism"


def test_privilege_paths_scope_resolution():
    conn = seeded_db()
    paths = eff_mod.privilege_paths(conn, "agt-router", "scope:secrets",
                                    TOOL_CATALOG)
    assert paths, "agt-router reaches scope:secrets via dormant rotate_secret"
    assert all(p["path"][-1] == "scope:secrets" for p in paths)


def test_privilege_paths_empty_for_unheld_privilege():
    conn = seeded_db()
    assert eff_mod.privilege_paths(conn, "agt-router", "tool:no_such_tool",
                                   TOOL_CATALOG) == []


# ------------------------------------------------------- robustness

def test_group_cycle_does_not_hang():
    conn = seeded_db()
    eff_mod.add_group(conn, "grp-loop-a", "Loop A", ["group:grp-loop-b"], [])
    eff_mod.add_group(conn, "grp-loop-b", "Loop B",
                      ["group:grp-loop-a", "agent:agt-router"],
                      ["read_logs"])
    eff = eff_mod.effective_privilege(conn, "agt-router", TOOL_CATALOG)
    assert "read_logs" in eff["tools"]  # reached despite the cycle


def test_unknown_agent_raises():
    conn = seeded_db()
    with pytest.raises(KeyError):
        eff_mod.effective_privilege(conn, "no-such-agent", TOOL_CATALOG)


def test_add_group_validates():
    conn = seeded_db()
    with pytest.raises(ValueError):
        eff_mod.add_group(conn, "", "Empty", [], [])


# ------------------------------------------------------- impact over effective privilege

def test_impact_effective_flags_indirect_exposures():
    conn = seeded_db()
    result = impact_mod.analyze_compromise_effective(conn, "agt-router",
                                                     TOOL_CATALOG)
    by_node = {e["node"]: e for e in result["exposed"]}
    assert by_node["tool:rotate_secret"]["indirect_only"] is True
    assert by_node["tool:read_tickets"]["indirect_only"] is False
    assert result["hidden_count"] > 0


def test_impact_effective_prioritizes_hidden_revocation():
    conn = seeded_db()
    result = impact_mod.analyze_compromise_effective(conn, "agt-router",
                                                     TOOL_CATALOG)
    p2 = [a for a in result["actions"] if a["priority"] == 2][0]
    assert "indirect" in p2["action"].lower()
    assert "tool:rotate_secret" in p2["action"]
