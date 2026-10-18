"""Deterministic demo scenario: stdlib only, fully tested (no Streamlit here)."""

from __future__ import annotations

import sqlite3

from . import audit as audit_mod
from . import bridge as bridge_mod
from . import graph as pgraph
from . import impact as impact_mod
from . import registry
from . import shadow as shadow_mod
from . import views
from . import zsp

TOOL_CATALOG = {
    "read_tickets": {"category": "read", "sensitivity": 2,
                     "scopes": ["support"]},
    "read_orders": {"category": "read", "sensitivity": 2,
                    "scopes": ["orders"]},
    "read_customers": {"category": "read", "sensitivity": 4,
                       "scopes": ["customers"]},
    "write_invoice": {"category": "write", "sensitivity": 3,
                      "scopes": ["billing"]},
    "read_builds": {"category": "read", "sensitivity": 1, "scopes": ["ci"]},
    "deploy_service": {"category": "write", "sensitivity": 4,
                       "scopes": ["production"]},
    "rotate_secret": {"category": "write", "sensitivity": 5,
                      "scopes": ["secrets"]},
    "read_logs": {"category": "read", "sensitivity": 1, "scopes": ["logs"]},
    "purge_cache": {"category": "destructive", "sensitivity": 3,
                    "scopes": ["cache"]},
    "drop_database": {"category": "destructive", "sensitivity": 5,
                      "scopes": ["production"]},
}

ACTIVITY = [
    {"caller_id": "agt-router", "tool": "read_tickets", "ts": "2026-10-18T08:00:00"},
    {"caller_id": "agt-biller", "tool": "write_invoice", "ts": "2026-10-18T08:05:00"},
    # shadow callers: one low-privilege, one exercising destructive tools
    {"caller_id": "ghost-helper", "tool": "read_tickets", "ts": "2026-10-18T08:10:00"},
    {"caller_id": "rogue-cleaner", "tool": "read_logs", "ts": "2026-10-18T08:12:00"},
    {"caller_id": "rogue-cleaner", "tool": "purge_cache", "ts": "2026-10-18T08:13:00"},
]


def build_demo_db() -> sqlite3.Connection:
    conn = sqlite3.connect(":memory:")
    views.install(conn)
    registry.seed_demo(conn)
    return conn


def run_scenario() -> dict:
    """End-to-end deterministic scenario; returns a summary dict."""
    conn = build_demo_db()
    log = audit_mod.AuditLog()

    findings = shadow_mod.detect(ACTIVITY, conn, TOOL_CATALOG)
    for f in findings:
        log.record("shadow_finding", f)

    g = pgraph.build(conn, TOOL_CATALOG)
    radius = pgraph.blast_radius(g, "agt-deployer")
    esc = pgraph.escalation_paths(g, "agt-deployer")
    compromise = impact_mod.analyze_compromise(g, "agt-deployer")
    log.record("impact_analysis",
               {"agent": "agt-deployer",
                "exposed_count": compromise["exposed_count"]})

    decisions = []
    br = bridge_mod.Bridge(conn, TOOL_CATALOG, audit_log=decisions)
    # allowed read
    br.execute(bridge_mod.ActionRequest("agt-router", "read_tickets"))
    log.record("bridge", decisions[-1])
    # denied: tool not granted
    try:
        br.execute(bridge_mod.ActionRequest("agt-router", "write_invoice"))
    except bridge_mod.BridgeDenied as e:
        log.record("bridge", {"agent_id": "agt-router", "tool": "write_invoice",
                              "decision": "denied", "policy_id": e.policy_id})
    # denied: shadow agent
    try:
        br.execute(bridge_mod.ActionRequest("rogue-cleaner", "purge_cache"))
    except bridge_mod.BridgeDenied as e:
        log.record("bridge", {"agent_id": "rogue-cleaner", "tool": "purge_cache",
                              "decision": "denied", "policy_id": e.policy_id})
    # JIT write: register an L1 agent with a write grant, deny without
    # elevation, allow with a live elevation
    registry.register_agent(conn, "agt-jit-demo", "JIT Demo", "fm-small-1",
                            ["write_invoice"], ["billing"], 1, "ops-team")
    try:
        br.execute(bridge_mod.ActionRequest("agt-jit-demo", "write_invoice"))
    except bridge_mod.BridgeDenied as e:
        log.record("bridge", {"agent_id": "agt-jit-demo", "tool": "write_invoice",
                              "decision": "denied", "policy_id": e.policy_id})
    elv = br.grant_elevation("agt-jit-demo", "write_invoice")
    br.execute(bridge_mod.ActionRequest("agt-jit-demo", "write_invoice"),
               elevation_id=elv)
    log.record("bridge", decisions[-1])
    # L2 direct write (no elevation needed)
    br.execute(bridge_mod.ActionRequest("agt-biller", "write_invoice"))
    log.record("bridge", decisions[-1])

    posture = zsp.score(conn, TOOL_CATALOG, jit_action_count=3,
                        total_privileged_actions=5, rotated_within_30d=2,
                        total_credentials=4, shadow_count=len(findings))

    return {
        "shadow_findings": findings,
        "blast_radius_nodes": len(radius["reachable"]),
        "escalation_paths": len(esc),
        "compromise_exposed": compromise["exposed_count"],
        "bridge_decisions": decisions,
        "zsp_score": posture["score"],
        "zsp_improvements": posture["improvements"],
        "audit_valid": log.verify(),
        "audit_entries": len(log.entries),
    }
