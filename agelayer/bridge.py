"""Governed tool bridge (MCP-style pattern): the centerpiece.

Agents never call tools directly. They submit an ActionRequest to the
bridge, which verifies registration, grant, and autonomy policy before
executing against a fake tool backend. Every decision is audit-logged.

Policy IDs:
  BRIDGE-01 - agent not registered (shadow finding recorded)
  BRIDGE-02 - tool not in the agent's grant
  BRIDGE-03 - autonomy level insufficient for the tool category
  BRIDGE-04 - destructive action needs human confirmation (fail-closed)

Autonomy policy:
  read        -> any autonomy level >= 1
  write       -> autonomy >= 2, or a live JIT elevation for (agent, tool)
  destructive -> human_approved=True always; autonomy >= 2 required too
L0 agents may not execute tools at all.
"""

from __future__ import annotations

from dataclasses import dataclass, field

from . import registry


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
    human_approved: bool = False


@dataclass
class Elevation:
    elevation_id: str
    agent_id: str
    tool: str
    expires_min: int = 60


class FakeToolBackend:
    """Deterministic stand-in for real tools. No network, no side effects."""

    def execute(self, tool: str, args: dict) -> dict:
        return {"tool": tool, "ok": True, "echo_args": dict(args),
                "backend": "fake"}


class Bridge:
    def __init__(self, conn, tool_catalog: dict,
                 backend=None, audit_log=None):
        self.conn = conn
        self.catalog = tool_catalog
        self.backend = backend or FakeToolBackend()
        self.audit = audit_log  # optional list to append decision dicts
        self._elevations: dict[str, Elevation] = {}
        self._counter = 0

    # ---- JIT elevation -------------------------------------------------
    def grant_elevation(self, agent_id, tool, expires_min=60) -> str:
        self._counter += 1
        eid = f"ELV-{self._counter:04d}"
        self._elevations[eid] = Elevation(eid, agent_id, tool, expires_min)
        return eid

    def _elevation_live(self, agent_id, tool) -> bool:
        return any(e.agent_id == agent_id and e.tool == tool
                   for e in self._elevations.values())

    # ---- execution ------------------------------------------------------
    def execute(self, request: ActionRequest, elevation_id=None) -> dict:
        agent = registry.get_agent(self.conn, request.agent_id)
        if agent is None or agent["status"] != "active":
            self._log(request, "denied", "BRIDGE-01",
                      "agent not registered or not active")
            raise BridgeDenied("BRIDGE-01",
                               f"unregistered or inactive agent: {request.agent_id}")
        tool = request.tool
        if tool not in agent["tools_granted"]:
            self._log(request, "denied", "BRIDGE-02",
                      f"tool {tool} not in agent grant")
            raise BridgeDenied("BRIDGE-02",
                               f"tool {tool} not granted to {request.agent_id}")
        category = self.catalog.get(tool, {}).get("category", "write")
        level = agent["autonomy_level"]
        if level < 1:
            self._log(request, "denied", "BRIDGE-03",
                      "L0 agents may not execute tools")
            raise BridgeDenied("BRIDGE-03", "L0 agents are propose-only")
        if category == "destructive":
            if not request.human_approved or level < 2:
                self._log(request, "denied", "BRIDGE-04",
                          "destructive needs human approval + L2")
                raise BridgeDenied(
                    "BRIDGE-04",
                    "destructive actions require human approval (fail-closed)")
        elif category == "write":
            elevated = (elevation_id
                        and elevation_id in self._elevations
                        and self._elevations[elevation_id].agent_id
                        == request.agent_id
                        and self._elevations[elevation_id].tool == tool)
            if level < 2 and not elevated:
                self._log(request, "denied", "BRIDGE-03",
                          "write needs L2 or live JIT elevation")
                raise BridgeDenied(
                    "BRIDGE-03",
                    "write tools need autonomy L2 or a live JIT elevation")
        result = self.backend.execute(tool, request.args)
        self._log(request, "allowed", None, f"executed via fake backend")
        return {"request": request, "result": result, "decision": "allowed"}

    def _log(self, request, decision, policy_id, note):
        if self.audit is not None:
            self.audit.append({
                "agent_id": request.agent_id, "tool": request.tool,
                "decision": decision, "policy_id": policy_id, "note": note,
            })
