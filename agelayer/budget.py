"""Loop and Denial-of-Wallet limits with a fail-closed kill switch.

  BUDGET-01  step cap reached for the session
  BUDGET-02  token cap reached
  BUDGET-03  cost cap reached
  LOOP-01    the same tool call (tool + arguments) repeated >= 3 times in the last 5 calls
  LOOP-02    A-B-A-B oscillation between two calls
  KILL-01    kill switch tripped (global or for this agent)
  KILL-02    kill switch state could not be read: deny (fail-closed)

A stopped session stays stopped until a named human resets it.
Prices are synthetic placeholders per 1,000 tokens (as of 2026-10-31), not
any vendor's list price.
"""

from __future__ import annotations

import json
from dataclasses import dataclass, field

SYNTHETIC_PRICE_PER_1K = {  # (input, output) USD per 1k tokens, synthetic
    "fm-small-1": (0.0002, 0.0008),
    "fm-med-1": (0.0010, 0.0040),
    "fm-large-1": (0.0050, 0.0150),
}


def cost_usd(model: str, tokens_in: int, tokens_out: int) -> float:
    pin, pout = SYNTHETIC_PRICE_PER_1K.get(model, SYNTHETIC_PRICE_PER_1K["fm-large-1"])  # unknown: priciest
    return tokens_in / 1000 * pin + tokens_out / 1000 * pout


class BudgetStop(Exception):
    def __init__(self, rule_id, message):
        super().__init__(message)
        self.rule_id = rule_id


@dataclass
class Budget:
    max_steps: int = 20
    max_tokens: int = 50_000
    max_cost_usd: float = 0.50

    def __post_init__(self):
        if self.max_steps <= 0 or self.max_tokens <= 0 or self.max_cost_usd <= 0:
            raise ValueError("budget caps must be positive")


class KillSwitch:
    """Global and per-agent stop. ``reader`` can be swapped to simulate a broken store."""

    def __init__(self):
        self._global = False
        self._agents: set[str] = set()
        self.reader = None          # optional callable returning (global, agents)
        self.events: list[dict] = []

    def trip(self, who: str, agent_id: str | None = None, reason: str = "") -> None:
        if agent_id:
            self._agents.add(agent_id)
        else:
            self._global = True
        self.events.append({"tripped_by": who, "agent_id": agent_id, "reason": reason})

    def reset(self, approver: str, agent_id: str | None = None) -> None:
        if not (approver or "").strip() or approver.startswith("agt-"):
            raise PermissionError("KILL: reset needs a named human")
        if agent_id:
            self._agents.discard(agent_id)
        else:
            self._global = False

    def check(self, agent_id: str) -> None:
        try:
            g, agents = self.reader() if self.reader else (self._global, self._agents)
        except Exception as exc:  # any failure to read the switch denies
            raise BudgetStop("KILL-02", f"kill switch unreadable: {type(exc).__name__}") from exc
        if g or agent_id in agents:
            raise BudgetStop("KILL-01", "kill switch is on")


@dataclass
class Meter:
    budget: Budget
    steps: int = 0
    tokens: int = 0
    cost: float = 0.0
    history: list = field(default_factory=list)
    stopped: str | None = None

    def pre_check(self, tool: str, args: dict) -> None:
        if self.stopped:
            raise BudgetStop(self.stopped, "session already stopped")
        if self.steps >= self.budget.max_steps:
            self._stop("BUDGET-01", "step cap reached")
        sig = tool + json.dumps(args, sort_keys=True, default=str)
        recent = self.history[-4:] + [sig]
        if recent.count(sig) >= 3:
            self._stop("LOOP-01", f"{tool} repeated {recent.count(sig)} times in the last 5 calls")
        last4 = (self.history + [sig])[-4:]
        if len(last4) == 4 and last4[0] == last4[2] and last4[1] == last4[3] and last4[0] != last4[1]:
            self._stop("LOOP-02", "A-B-A-B oscillation")
        self.history.append(sig)

    def account(self, model: str, tokens_in: int, tokens_out: int) -> None:
        if tokens_in < 0 or tokens_out < 0:
            raise ValueError("token counts must be >= 0")
        self.steps += 1
        self.tokens += tokens_in + tokens_out
        self.cost += cost_usd(model, tokens_in, tokens_out)

    def post_check(self) -> None:
        if self.tokens >= self.budget.max_tokens:
            self._stop("BUDGET-02", "token cap reached")
        if self.cost >= self.budget.max_cost_usd:
            self._stop("BUDGET-03", "cost cap reached")

    def _stop(self, rule, msg):
        self.stopped = rule
        raise BudgetStop(rule, msg)

    def reset(self, approver: str) -> None:
        if not (approver or "").strip() or approver.startswith("agt-"):
            raise PermissionError("BUDGET: reset needs a named human")
        self.stopped = None
        self.history.clear()
