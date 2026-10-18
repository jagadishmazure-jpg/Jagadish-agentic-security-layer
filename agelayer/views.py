"""Read-only views + SELECT-only gateway with strict authorizer backstop.

Views:
  v_agent_posture   - per-agent posture (autonomy, tool count, status)
  v_shadow_findings - shadow findings persisted by the demo/audit flow
  v_bridge_denials  - bridge denials persisted by the demo/audit flow

The gateway enforces two independent layers:
  1. text check: single SELECT, FROM/JOIN targets must be allowed views
  2. SQLite authorizer (authz.views_only): denies base-table reads unless
     SQLite reads them on behalf of an allowed view
"""

from __future__ import annotations

import re
import sqlite3

from .authz import views_only

ALLOWED_VIEWS = ("v_agent_posture", "v_shadow_findings", "v_bridge_denials")
MAX_ROWS = 500

_VIEW_SQL = {
    "v_agent_posture": """
        CREATE VIEW IF NOT EXISTS v_agent_posture AS
        SELECT agent_id, name, model, autonomy_level, owner, status,
               json_array_length(tools_granted) AS tool_count
        FROM agents
    """,
    "v_shadow_findings": """
        CREATE VIEW IF NOT EXISTS v_shadow_findings AS
        SELECT finding_id, caller_id, privilege_score, recommendation,
               observed_ts
        FROM shadow_findings
    """,
    "v_bridge_denials": """
        CREATE VIEW IF NOT EXISTS v_bridge_denials AS
        SELECT denial_id, agent_id, tool, policy_id, decided_ts
        FROM bridge_denials
    """,
}

_TABLE_SQL = """
CREATE TABLE IF NOT EXISTS shadow_findings (
    finding_id TEXT PRIMARY KEY, caller_id TEXT NOT NULL,
    privilege_score INTEGER NOT NULL, recommendation TEXT NOT NULL,
    observed_ts TEXT NOT NULL
);
CREATE TABLE IF NOT EXISTS bridge_denials (
    denial_id TEXT PRIMARY KEY, agent_id TEXT NOT NULL, tool TEXT NOT NULL,
    policy_id TEXT NOT NULL, decided_ts TEXT NOT NULL
);
"""

_SINGLE_SELECT = re.compile(r"^\s*select\b", re.IGNORECASE)
_FROM_JOIN = re.compile(r"\b(?:from|join)\s+([\"`\[]?[\w]+[\"`\]]?)",
                        re.IGNORECASE)


class GatewayDenied(Exception):
    def __init__(self, policy_id, message):
        super().__init__(message)
        self.policy_id = policy_id


def install(conn: sqlite3.Connection) -> None:
    from . import registry
    registry.init_db(conn)
    conn.executescript(_TABLE_SQL)
    for sql in _VIEW_SQL.values():
        conn.execute(sql)
    conn.commit()


def _text_check(sql: str) -> None:
    if not _SINGLE_SELECT.match(sql):
        raise GatewayDenied("SEC-SELECT-01", "only single SELECT allowed")
    if ";" in sql.strip().rstrip(";"):
        raise GatewayDenied("SEC-SELECT-01", "multi-statement denied")
    targets = {t.strip('"`[]').lower() for t in _FROM_JOIN.findall(sql)}
    bad = targets - set(ALLOWED_VIEWS)
    if bad:
        raise GatewayDenied("SEC-SELECT-02",
                            f"not an allowed view: {sorted(bad)}")


def run_query(conn: sqlite3.Connection, sql: str,
              params: tuple = ()) -> list[tuple]:
    """Run a read query through both gateway layers."""
    _text_check(sql)
    with views_only(conn, ALLOWED_VIEWS) as denied:
        try:
            cur = conn.execute(sql, params)
            rows = cur.fetchmany(MAX_ROWS + 1)
        except sqlite3.DatabaseError as exc:
            raise GatewayDenied("SEC-SELECT-03",
                                f"authorizer denied: {denied or exc}") from None
    if len(rows) > MAX_ROWS:
        raise GatewayDenied("SEC-SELECT-04",
                            f"row cap exceeded ({MAX_ROWS})")
    return rows


def run_query_authorizer_only(conn: sqlite3.Connection, sql: str,
                              params: tuple = ()) -> list[tuple]:
    """Run with the authorizer but WITHOUT the text check.

    Used by regression tests to prove the authorizer alone denies
    raw-table reads (the bypass class caught in earlier builds).
    """
    with views_only(conn, ALLOWED_VIEWS) as denied:
        try:
            cur = conn.execute(sql, params)
            return cur.fetchmany(MAX_ROWS + 1)
        except sqlite3.DatabaseError as exc:
            raise GatewayDenied("SEC-SELECT-03",
                                f"authorizer denied: {denied or exc}") from None
