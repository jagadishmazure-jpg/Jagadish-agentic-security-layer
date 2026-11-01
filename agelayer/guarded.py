"""Runtime guardrails v2: one session wrapper in front of the governed bridge.

Order of checks for every tool call (first failure wins, fail-closed):
  1. kill switch           (KILL-01/02)
  2. loop and step budget  (LOOP-01/02, BUDGET-01)
  3. intent scope          (INTENT-01..04)
  4. governed bridge       (BRIDGE-01..06: registration, grant, autonomy, approval)
  5. token and cost budget after the call (BUDGET-02/03 stop the *next* call)

Every decision goes into the bridge's hash-chained audit log.
"""

from __future__ import annotations

from dataclasses import dataclass, field

from .bridge import ActionRequest, Bridge, BridgeDenied
from .budget import Budget, BudgetStop, KillSwitch, Meter
from .intent import IntentScope


@dataclass
class GuardStats:
    calls: int = 0
    allowed: int = 0
    out_of_intent: int = 0
    out_of_intent_blocked: int = 0
    budget_stops: dict = field(default_factory=dict)
    bridge_denials: int = 0


class GuardedSession:
    def __init__(self, bridge: Bridge, agent_id: str, user_request: str, model: str = "fm-med-1",
                 budget: Budget | None = None, kill_switch: KillSwitch | None = None,
                 intent_mode: str = "block"):
        if intent_mode not in ("block", "flag"):
            raise ValueError("intent_mode must be block or flag")
        self.bridge = bridge
        self.agent_id = agent_id
        self.model = model
        self.scope = IntentScope.from_request(user_request)
        self.meter = Meter(budget or Budget())
        self.kill = kill_switch or KillSwitch()
        self.mode = intent_mode
        self.stats = GuardStats()
        self.log: list[dict] = []

    def _record(self, tool, decision, rule, note=""):
        entry = {"agent_id": self.agent_id, "tool": tool, "decision": decision,
                 "rule_id": rule, "note": note}
        self.log.append(entry)
        self.bridge.chain.record("guard.decision", entry)

    def call(self, tool: str, args: dict | None = None, tokens_in: int = 500,
             tokens_out: int = 200, **bridge_kwargs) -> dict:
        args = dict(args or {})
        self.stats.calls += 1
        try:
            self.kill.check(self.agent_id)
            self.meter.pre_check(tool, args)
        except BudgetStop as stop:
            self.stats.budget_stops[stop.rule_id] = self.stats.budget_stops.get(stop.rule_id, 0) + 1
            self._record(tool, "stopped", stop.rule_id, str(stop))
            raise
        d = self.scope.check(tool, args)
        if not d.in_scope:
            self.stats.out_of_intent += 1
            if self.mode == "block":
                self.stats.out_of_intent_blocked += 1
                self._record(tool, "denied", d.rule_id, d.reason)
                raise BridgeDenied(d.rule_id, d.reason)
            self._record(tool, "flagged", d.rule_id, d.reason)
        try:
            out = self.bridge.execute(ActionRequest(self.agent_id, tool, args), **bridge_kwargs)
        except BridgeDenied as denied:
            self.stats.bridge_denials += 1
            self._record(tool, "denied", denied.policy_id, str(denied))
            raise
        self.meter.account(self.model, tokens_in, tokens_out)
        self.stats.allowed += 1
        self._record(tool, "allowed", None)
        try:
            self.meter.post_check()
        except BudgetStop as stop:
            self.stats.budget_stops[stop.rule_id] = self.stats.budget_stops.get(stop.rule_id, 0) + 1
            self._record(tool, "stopped-after", stop.rule_id, str(stop))
        return out


def runaway_simulation(bridge: Bridge, agent_id: str, request: str, planned_steps: int,
                       tool: str, tokens_per_step: int, model: str, budget: Budget,
                       vary_args: bool = True) -> dict:
    """Simulate an agent stuck in a loop. Returns steps run vs planned and what was avoided."""
    from .budget import cost_usd
    s = GuardedSession(bridge, agent_id, request, model=model, budget=budget)
    ran, stop_rule = 0, None
    for i in range(planned_steps):
        try:
            s.call(tool, {"page": i} if vary_args else {}, tokens_in=tokens_per_step, tokens_out=0)
            ran += 1
        except (BudgetStop, BridgeDenied) as e:
            stop_rule = getattr(e, "rule_id", None) or getattr(e, "policy_id", None)
            break
    planned_tokens = planned_steps * tokens_per_step
    used_tokens = s.meter.tokens
    return {"planned_steps": planned_steps, "ran": ran, "stop_rule": stop_rule,
            "tokens_used": used_tokens, "tokens_avoided": planned_tokens - used_tokens,
            "cost_used": round(s.meter.cost, 4),
            "cost_avoided": round(cost_usd(model, planned_tokens, 0) - s.meter.cost, 4)}
