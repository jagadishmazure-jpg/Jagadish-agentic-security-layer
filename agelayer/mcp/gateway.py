"""MCP gateway: one checkpoint between agents and MCP servers.

For each tool call: registry (MCP-01..04) -> quarantine from drift
(DRIFT-*) -> poisoned description (POISON-*) -> token (TOK-*). First failure
wins. Counters feed leadership KPI K09.
"""

from __future__ import annotations

from dataclasses import dataclass, field

from . import poisoning
from .pinning import PinStore
from .registry import MCPRegistry
from .tokens import TokenError, TokenIssuer


@dataclass
class GatewayResult:
    allowed: bool
    rule_id: str | None
    reason: str


@dataclass
class MCPGateway:
    registry: MCPRegistry
    pins: PinStore
    issuer: TokenIssuer
    listings: dict = field(default_factory=dict)      # server -> tools (latest)
    counters: dict = field(default_factory=dict)

    def _count(self, key):
        self.counters[key] = self.counters.get(key, 0) + 1

    def refresh_listing(self, server_id: str, tools: list[dict]) -> dict:
        self.listings[server_id] = tools
        drift = self.pins.compare(server_id, tools)
        poisoned = poisoning.scan_listing(server_id, tools)
        for d in drift:
            self._count(d["rule_id"])
        for p in poisoned:
            self._count(p["rule_id"])
        if poisoned:
            self.pins.quarantined.add(server_id)
        return {"drift": drift, "poisoned": poisoned}

    def call(self, agent_id: str, server_id: str, tool: str, token: str, scope: str,
             now: int) -> GatewayResult:
        self._count("calls")
        d = self.registry.check(agent_id, server_id)
        if not d.allowed:
            self._count(d.rule_id)
            return GatewayResult(False, d.rule_id, d.reason)
        if server_id in self.pins.quarantined:
            self._count("QUARANTINE")
            return GatewayResult(False, "DRIFT-Q", f"{server_id} quarantined until re-approved")
        names = {t["name"] for t in self.listings.get(server_id, [])}
        if tool not in names:
            self._count("UNKNOWN-TOOL")
            return GatewayResult(False, "MCP-05", f"{tool} not in the approved listing")
        try:
            self.issuer.verify(token, server_id, scope, now)
        except TokenError as e:
            self._count(e.rule_id)
            return GatewayResult(False, e.rule_id, str(e))
        self._count("allowed")
        return GatewayResult(True, None, "ok")

    def kpis(self) -> dict:
        p = self.registry.posture()
        return {"unapproved_servers_seen": p["unknown_seen"] + p["pending"],
                "denied_servers": p["denied"],
                "drift_events": sum(v for k, v in self.counters.items() if k.startswith("DRIFT-")),
                "poisoned_descriptions": sum(v for k, v in self.counters.items() if k.startswith("POISON-")),
                "quarantined_servers": len(self.pins.quarantined),
                "calls": self.counters.get("calls", 0),
                "allowed": self.counters.get("allowed", 0)}
