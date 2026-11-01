"""MCP server registry: allow list, deny list, and per-agent grants.

  MCP-01  server is not in the registry (unknown) -> deny, queue for review
  MCP-02  server is on the deny list -> deny
  MCP-03  agent is not granted this server -> deny
  MCP-04  server transport is not allowed (only stdio and https; plain http denied)
"""

from __future__ import annotations

from dataclasses import dataclass, field

ALLOWED_TRANSPORTS = ("stdio", "https")


@dataclass
class MCPServer:
    server_id: str
    url: str
    owner: str
    transport: str = "https"
    status: str = "approved"       # approved | denied | pending


@dataclass
class MCPDecision:
    allowed: bool
    rule_id: str | None
    reason: str


@dataclass
class MCPRegistry:
    servers: dict = field(default_factory=dict)
    grants: dict = field(default_factory=dict)      # agent_id -> set(server_id)
    review_queue: list = field(default_factory=list)

    def add(self, server: MCPServer) -> None:
        if server.status not in ("approved", "denied", "pending"):
            raise ValueError("status must be approved, denied or pending")
        self.servers[server.server_id] = server

    def deny(self, server_id: str, approver: str, reason: str) -> None:
        if not (approver or "").strip() or approver.startswith("agt-"):
            raise PermissionError("MCP: deny-listing needs a named human")
        s = self.servers.get(server_id) or MCPServer(server_id, "", "unknown")
        s.status = "denied"
        self.servers[server_id] = s

    def grant(self, agent_id: str, server_id: str, approver: str) -> None:
        if not (approver or "").strip() or approver.startswith("agt-"):
            raise PermissionError("MCP: grants need a named human approver")
        if self.servers.get(server_id) is None or self.servers[server_id].status != "approved":
            raise ValueError("can only grant approved servers")
        self.grants.setdefault(agent_id, set()).add(server_id)

    def check(self, agent_id: str, server_id: str) -> MCPDecision:
        s = self.servers.get(server_id)
        if s is None:
            if server_id not in self.review_queue:
                self.review_queue.append(server_id)
            return MCPDecision(False, "MCP-01", f"unknown MCP server {server_id}")
        if s.status == "denied":
            return MCPDecision(False, "MCP-02", f"{server_id} is deny-listed")
        if s.status != "approved":
            return MCPDecision(False, "MCP-01", f"{server_id} is pending review")
        if s.transport not in ALLOWED_TRANSPORTS:
            return MCPDecision(False, "MCP-04", f"transport {s.transport} not allowed")
        if server_id not in self.grants.get(agent_id, set()):
            return MCPDecision(False, "MCP-03", f"{agent_id} is not granted {server_id}")
        return MCPDecision(True, None, "approved and granted")

    def posture(self) -> dict:
        by = {"approved": 0, "denied": 0, "pending": 0}
        for s in self.servers.values():
            by[s.status] += 1
        return {**by, "unknown_seen": len(self.review_queue)}
