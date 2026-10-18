"""Agent identity registry: the inventory of known AI agents.

Every AI agent that acts in the environment must be registered here with its
granted tools, data scopes, autonomy level, and owner. Unregistered callers
are shadow AI (see shadow.py). Autonomy levels:

  L0 - propose only (no tool execution)
  L1 - read-only tool execution
  L2 - reads + writes, destructive actions need confirmation
  L3 - full autonomy within granted tools, destructive still gated by bridge
"""

from __future__ import annotations

import json
import sqlite3

STATUSES = {"active", "suspended", "revoked"}
AUTONOMY_LEVELS = {0, 1, 2, 3}

_SCHEMA = """
CREATE TABLE IF NOT EXISTS agents (
    agent_id       TEXT PRIMARY KEY,
    name           TEXT NOT NULL,
    model          TEXT NOT NULL,
    tools_granted  TEXT NOT NULL,   -- JSON list of tool names
    data_scopes    TEXT NOT NULL,   -- JSON list of scope names
    autonomy_level INTEGER NOT NULL,
    owner          TEXT NOT NULL,
    status         TEXT NOT NULL
)
"""


def init_db(conn: sqlite3.Connection) -> None:
    conn.execute(_SCHEMA)
    conn.commit()


def register_agent(conn, agent_id, name, model, tools_granted,
                   data_scopes, autonomy_level, owner,
                   status="active") -> dict:
    """Register an agent. Raises ValueError on invalid input."""
    if not agent_id or not str(agent_id).strip():
        raise ValueError("agent_id must be non-empty")
    if not name or not str(name).strip():
        raise ValueError("name must be non-empty")
    if autonomy_level not in AUTONOMY_LEVELS:
        raise ValueError(f"autonomy_level must be one of {sorted(AUTONOMY_LEVELS)}")
    if status not in STATUSES:
        raise ValueError(f"status must be one of {sorted(STATUSES)}")
    tools = list(tools_granted or [])
    scopes = list(data_scopes or [])
    conn.execute(
        "INSERT OR REPLACE INTO agents VALUES (?,?,?,?,?,?,?,?)",
        (agent_id, name, model, json.dumps(tools), json.dumps(scopes),
         autonomy_level, owner, status),
    )
    conn.commit()
    return get_agent(conn, agent_id)


def get_agent(conn, agent_id) -> dict | None:
    row = conn.execute(
        "SELECT agent_id, name, model, tools_granted, data_scopes,"
        " autonomy_level, owner, status FROM agents WHERE agent_id = ?",
        (agent_id,),
    ).fetchone()
    if row is None:
        return None
    return {
        "agent_id": row[0], "name": row[1], "model": row[2],
        "tools_granted": json.loads(row[3]), "data_scopes": json.loads(row[4]),
        "autonomy_level": row[5], "owner": row[6], "status": row[7],
    }


def list_agents(conn) -> list[dict]:
    rows = conn.execute(
        "SELECT agent_id, name, model, tools_granted, data_scopes,"
        " autonomy_level, owner, status FROM agents ORDER BY agent_id"
    ).fetchall()
    return [get_agent(conn, r[0]) for r in rows]


def set_status(conn, agent_id, status) -> None:
    if status not in STATUSES:
        raise ValueError(f"status must be one of {sorted(STATUSES)}")
    conn.execute("UPDATE agents SET status = ? WHERE agent_id = ?",
                 (status, agent_id))
    conn.commit()


def seed_demo(conn) -> None:
    """Deterministic demo population (fictional agents)."""
    demo = [
        ("agt-router", "Triage Router", "fm-small-1",
         ["read_tickets", "read_orders"], ["support", "orders"], 1,
         "ops-team", "active"),
        ("agt-biller", "Billing Agent", "fm-med-1",
         ["read_orders", "write_invoice", "read_customers"],
         ["orders", "billing"], 2, "fin-team", "active"),
        ("agt-deployer", "Deploy Agent", "fm-med-1",
         ["read_builds", "deploy_service", "rotate_secret"],
         ["ci", "secrets"], 2, "platform-team", "active"),
        ("agt-wiper", "Cleanup Agent", "fm-small-1",
         ["read_logs", "purge_cache"], ["logs"], 3, "platform-team",
         "suspended"),
    ]
    for a in demo:
        register_agent(conn, *a)
