"""Intent-bound actions: tool calls must match what the user asked for.

The user's request is turned into a declared *intent scope*: which tools it
implies, the highest action category it implies (read < write < destructive),
and which resources it names (ticket, invoice, service ids). Each tool call is
checked against that scope before it reaches the bridge.

  INTENT-01  tool not implied by the request
  INTENT-02  call targets a resource the user did not name
  INTENT-03  call is a higher category than the request implies
             (for example, a write or delete during a "summarise" request)
  INTENT-04  the request implies no tools at all (fail-closed: nothing runs)

A human can widen a scope for one tool (``widen``); the widening is recorded.

This is a deterministic keyword parser, a stand-in for an intent classifier.
Its accuracy on a small labelled set is measured in ``evaluate`` and reported
in the docs; synonyms it does not know are kept as known misses.
"""

from __future__ import annotations

import re
from dataclasses import dataclass, field

CATEGORY_RANK = {"read": 1, "write": 2, "destructive": 3}

# tool -> (verbs that imply it, nouns that imply it, category)
INTENT_MAP: dict[str, tuple[tuple[str, ...], tuple[str, ...], str]] = {
    "read_tickets": (("read", "show", "summar", "list", "check", "look"), ("ticket",), "read"),
    "read_orders": (("read", "show", "summar", "list", "check", "look", "find"), ("order",), "read"),
    "read_customers": (("read", "show", "look up", "find"), ("customer",), "read"),
    "write_invoice": (("create", "issue", "send", "draft", "correct", "fix"), ("invoice",), "write"),
    "read_builds": (("read", "show", "check", "list"), ("build",), "read"),
    "deploy_service": (("deploy", "release", "roll out", "ship"), ("service", "svc-"), "write"),
    "rotate_secret": (("rotate", "renew"), ("secret", "credential", "key"), "write"),
    "read_logs": (("read", "show", "check", "search", "summar"), ("log",), "read"),
    "purge_cache": (("purge", "clear", "flush"), ("cache",), "destructive"),
    "drop_database": (("drop", "delete"), ("database", "db"), "destructive"),
}
RESOURCE_RX = re.compile(r"\b(TCK-\d+|INV-\d+|ORD-\d+|svc-[a-z0-9-]+)\b")
RESOURCE_ARGS = ("ticket_id", "invoice_id", "order_id", "service")


@dataclass
class IntentDecision:
    in_scope: bool
    rule_id: str | None
    reason: str


@dataclass
class IntentScope:
    request: str
    tools: set = field(default_factory=set)
    max_category: str | None = None
    resources: set = field(default_factory=set)
    widened: list = field(default_factory=list)

    @classmethod
    def from_request(cls, request: str, intent_map=INTENT_MAP) -> IntentScope:
        text = request.lower()
        tools, top = set(), 0
        for tool, (verbs, nouns, cat) in intent_map.items():
            if any(v in text for v in verbs) and any(n in text for n in nouns):
                tools.add(tool)
                top = max(top, CATEGORY_RANK[cat])
        inv = {v: k for k, v in CATEGORY_RANK.items()}
        return cls(request, tools, inv.get(top), set(RESOURCE_RX.findall(request)))

    def widen(self, tool: str, approver: str, reason: str) -> None:
        if not (approver or "").strip() or approver.startswith("agt-"):
            raise PermissionError("INTENT: scope widening needs a named human")
        self.tools.add(tool)
        cat = INTENT_MAP.get(tool, ((), (), "destructive"))[2]
        if self.max_category is None or CATEGORY_RANK[cat] > CATEGORY_RANK[self.max_category]:
            self.max_category = cat
        self.widened.append({"tool": tool, "approver": approver, "reason": reason})

    def check(self, tool: str, args: dict | None = None) -> IntentDecision:
        args = args or {}
        if not self.tools:
            return IntentDecision(False, "INTENT-04", "request implies no tool; nothing runs")
        cat = INTENT_MAP.get(tool, ((), (), "destructive"))[2]   # unknown tool: destructive
        if CATEGORY_RANK[cat] > CATEGORY_RANK[self.max_category]:
            return IntentDecision(False, "INTENT-03",
                                  f"{cat} call during a {self.max_category}-only request")
        if tool not in self.tools:
            return IntentDecision(False, "INTENT-01", f"{tool} is not implied by the request")
        if self.resources:
            for key in RESOURCE_ARGS:
                if key in args and str(args[key]) not in self.resources:
                    return IntentDecision(False, "INTENT-02",
                                          f"{key}={args[key]} was not named by the user")
        return IntentDecision(True, None, "in scope")


def evaluate(cases: list[dict]) -> dict:
    """cases: {request, tool, args, expected: in|out}. Positive class = out-of-intent."""
    tp = fp = fn = tn = 0
    misses = []
    for c in cases:
        d = IntentScope.from_request(c["request"]).check(c["tool"], c.get("args"))
        flagged = not d.in_scope
        want = c["expected"] == "out"
        if flagged and want:
            tp += 1
        elif flagged and not want:
            fp += 1
            misses.append(("false_flag", c["request"], c["tool"]))
        elif not flagged and want:
            fn += 1
            misses.append(("missed", c["request"], c["tool"]))
        else:
            tn += 1
    prec = tp / (tp + fp) if tp + fp else 1.0
    rec = tp / (tp + fn) if tp + fn else 1.0
    return {"cases": len(cases), "tp": tp, "fp": fp, "fn": fn, "tn": tn,
            "precision": round(prec, 3), "recall": round(rec, 3), "misses": misses}
