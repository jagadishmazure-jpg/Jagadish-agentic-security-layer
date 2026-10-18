"""Governed tool bridge (MCP-style pattern): the centerpiece.

Agents never call tools directly. They submit an ActionRequest to the
bridge, which verifies registration, grant, and autonomy policy before
executing against a fake tool backend. Every decision is written to a
hash-chained audit log, and denials are persisted for the read views.

Policy IDs:
  BRIDGE-01 - agent not registered or not active (unregistered callers are
              also recorded as shadow findings)
  BRIDGE-02 - tool not in the agent's grant
  BRIDGE-03 - autonomy level insufficient for the tool category
  BRIDGE-04 - destructive action needs a recorded human approval (fail-closed)
  BRIDGE-05 - approval or elevation is missing, expired, used, or for a
              different agent/tool
  BRIDGE-06 - approver is not a named human distinct from the agent

Autonomy policy:
  read        -> any autonomy level >= 1
  write       -> autonomy >= 2, or a live JIT elevation for (agent, tool)
  destructive -> autonomy >= 2 AND a single-use human approval for
                 (agent, tool) issued by ``approve()``
Tools missing from the catalog are treated as destructive (fail-closed).
L0 agents may not execute tools at all.

Approvals and elevations are records the bridge issues to a named human.
The agent cannot assert them in its own request: ``human_approved=True`` on
an ActionRequest has no effect (it was self-asserted, see the README review).
"""

from __future__ import annotations

from dataclasses import dataclass, field
from datetime import datetime, timedelta, timezone

from . import registry
from .audit import AuditLog

DEFAULT_APPROVAL_MIN = 15
MAX_ELEVATION_MIN = 8 * 60


class BridgeDenied(Exception):
    def __init__(self, policy_id, message):
        super().__init__(message)
        self.policy_id = policy_id


@dataclass
class ActionRequest:
    agent_id: str
    tool: str
    args: dict = field(default_factory=dict)
    justification: str = ""
    human_approved: bool = False  # ignored: approval must come from approve()
    approval_id: str | None = None


@dataclass
class Elevation:
    elevation_id: str
    agent_id: str
    tool: str
    approver: str
    expires_at: datetime


@dataclass
class Approval:
    approval_id: str
    agent_id: str
    tool: str
    approver: str
    expires_at: datetime
    used: bool = False


class FakeToolBackend:
    """Deterministic stand-in for real tools. No network, no side effects."""

    def execute(self, tool: str, args: dict) -> dict:
        return {"tool": tool, "ok": True, "echo_args": dict(args),
                "backend": "fake"}


def _utcnow() -> datetime:
    return datetime.now(timezone.utc)


class Bridge:
    def __init__(self, conn, tool_catalog: dict, backend=None,
                 audit_log=None, chain: AuditLog | None = None, clock=None):
        self.conn = conn
        self.catalog = tool_catalog
        self.backend = backend or FakeToolBackend()
        self.audit = audit_log      # optional plain list of decision dicts
        self.chain = chain or AuditLog()  # every decision, hash-chained
        self.clock = clock or _utcnow
        self._elevations: dict[str, Elevation] = {}
        self._approvals: dict[str, Approval] = {}
        self._counter = 0
        self._denials = 0

    # ---- issuing approvals and elevations ---------------------------------
    def _check_approver(self, agent_id: str, approver: str) -> None:
        name = (approver or "").strip()
        if not name or name == agent_id or registry.get_agent(self.conn, name):
            raise BridgeDenied(
                "BRIDGE-06",
                "approver must be a named human, not the agent or another agent")

    def _next(self, prefix: str) -> str:
        self._counter += 1
        return f"{prefix}-{self._counter:04d}"

    def approve(self, agent_id, tool, approver,
                ttl_min=DEFAULT_APPROVAL_MIN) -> str:
        """A named human approves one destructive call of ``tool`` by ``agent_id``."""
        self._check_approver(agent_id, approver)
        aid = self._next("APR")
        self._approvals[aid] = Approval(
            aid, agent_id, tool, approver.strip(),
            self.clock() + timedelta(minutes=ttl_min))
        self.chain.record("bridge.approval", {"id": aid, "agent_id": agent_id,
                                              "tool": tool, "approver": approver})
        return aid

    def grant_elevation(self, agent_id, tool, approver, expires_min=60) -> str:
        """A named human grants time-boxed write access to one tool."""
        self._check_approver(agent_id, approver)
        if not 0 < expires_min <= MAX_ELEVATION_MIN:
            raise ValueError(f"expires_min must be in (0, {MAX_ELEVATION_MIN}]")
        eid = self._next("ELV")
        self._elevations[eid] = Elevation(
            eid, agent_id, tool, approver.strip(),
            self.clock() + timedelta(minutes=expires_min))
        self.chain.record("bridge.elevation", {"id": eid, "agent_id": agent_id,
                                               "tool": tool, "approver": approver,
                                               "expires_min": expires_min})
        return eid

    def _elevation_live(self, elevation_id, agent_id, tool) -> bool:
        e = self._elevations.get(elevation_id or "")
        return bool(e and e.agent_id == agent_id and e.tool == tool
                    and self.clock() < e.expires_at)

    def _take_approval(self, approval_id, agent_id, tool) -> Approval | None:
        a = self._approvals.get(approval_id or "")
        if (a is None or a.used or a.agent_id != agent_id or a.tool != tool
                or self.clock() >= a.expires_at):
            return None
        a.used = True
        return a

    # ---- execution ------------------------------------------------------
    def _deny(self, request, policy_id, note, message):
        self._log(request, "denied", policy_id, note)
        raise BridgeDenied(policy_id, message)

    def execute(self, request: ActionRequest, elevation_id=None) -> dict:
        agent = registry.get_agent(self.conn, request.agent_id)
        if agent is None or agent["status"] != "active":
            if agent is None:
                self._record_shadow(request)
            self._deny(request, "BRIDGE-01", "agent not registered or not active",
                       f"unregistered or inactive agent: {request.agent_id}")
        tool = request.tool
        if tool not in agent["tools_granted"]:
            self._deny(request, "BRIDGE-02", f"tool {tool} not in agent grant",
                       f"tool {tool} not granted to {request.agent_id}")
        category = self.catalog.get(tool, {}).get("category", "destructive")
        level = agent["autonomy_level"]
        if level < 1:
            self._deny(request, "BRIDGE-03", "L0 agents may not execute tools",
                       "L0 agents are propose-only")
        approver = None
        if category == "destructive":
            if level < 2:
                self._deny(request, "BRIDGE-04", "destructive needs L2",
                           "destructive actions require autonomy L2")
            approval = self._take_approval(request.approval_id,
                                           request.agent_id, tool)
            if approval is None:
                pid = "BRIDGE-05" if request.approval_id else "BRIDGE-04"
                self._deny(request, pid,
                           "destructive needs a live human approval",
                           "destructive actions require human approval (fail-closed)")
            approver = approval.approver
        elif category == "write":
            if level < 2 and not self._elevation_live(elevation_id,
                                                      request.agent_id, tool):
                pid = "BRIDGE-05" if elevation_id else "BRIDGE-03"
                self._deny(request, pid, "write needs L2 or live JIT elevation",
                           "write tools need autonomy L2 or a live JIT elevation")
        result = self.backend.execute(tool, request.args)
        self._log(request, "allowed", None, "executed via fake backend",
                  approver=approver)
        return {"request": request, "result": result, "decision": "allowed"}

    # ---- recording ------------------------------------------------------
    def _log(self, request, decision, policy_id, note, approver=None):
        entry = {"agent_id": request.agent_id, "tool": request.tool,
                 "decision": decision, "policy_id": policy_id, "note": note}
        if approver:
            entry["approver"] = approver
        self.chain.record("bridge.decision", entry)
        if self.audit is not None:
            self.audit.append(entry)
        if decision == "denied":
            self._persist_denial(request, policy_id)

    def _has_table(self, name) -> bool:
        return self.conn.execute(
            "SELECT 1 FROM sqlite_master WHERE type='table' AND name=?",
            (name,)).fetchone() is not None

    def _persist_denial(self, request, policy_id):
        if not self._has_table("bridge_denials"):
            return
        self._denials += 1
        self.conn.execute(
            "INSERT INTO bridge_denials VALUES (?,?,?,?,?)",
            (f"DEN-{self._denials:04d}", request.agent_id, request.tool,
             policy_id, self.clock().isoformat(timespec="seconds")))
        self.conn.commit()

    def _record_shadow(self, request):
        from . import shadow
        findings = shadow.detect(
            [{"caller_id": request.agent_id, "tool": request.tool}],
            self.conn, self.catalog)
        shadow.persist(self.conn, findings, self.clock())
