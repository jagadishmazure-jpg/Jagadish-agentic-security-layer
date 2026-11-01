"""Browser AI usage policy engine (synthetic browser telemetry).

Each browser event (a user opens or sends to an AI or SaaS app) gets one
decision: ``allow``, ``warn``, ``redact`` or ``block``. The decision depends
on the app's sanction state, whether the user signed in with a personal
account, the user's group, and whether the content was flagged as sensitive
by the DLP step (pii-guard's gateway does this in its own repo; here it is a
boolean on the event).

States:
  approved      contract + SSO; allowed
  monitored     allowed with a banner and logging (warn)
  unsanctioned  blocked for sensitive groups, warned for others
  personal      an approved or monitored app used through a personal account
  unclassified  not in the catalog; warned and queued for a person to classify

Changing an app's state is a *policy change*: the engine only proposes it.
A named human (not an agent) approves it before it takes effect (BPOL-05).

Rule ids:
  BPOL-01 state default        BPOL-02 group override
  BPOL-03 sensitive content    BPOL-04 personal account
  BPOL-05 policy change needs a named human approver
"""

from __future__ import annotations

from dataclasses import dataclass

from .shadow_ai import CATALOG, AIApp, catalog_by_host

ACTIONS = ("allow", "warn", "redact", "block")
_RANK = {a: i for i, a in enumerate(ACTIONS)}
CORPORATE_LOGIN_DOMAIN = "corp.example"

DEFAULT_POLICY = {
    "state_defaults": {"approved": "allow", "monitored": "warn", "unsanctioned": "warn",
                       "personal": "warn", "unclassified": "warn"},
    # group -> state -> action (stricter groups)
    "group_overrides": {
        "finance": {"unsanctioned": "block", "personal": "block", "unclassified": "block"},
        "hr": {"unsanctioned": "block", "personal": "block", "unclassified": "block"},
    },
    # what happens when the DLP step flags the content as sensitive
    "sensitive": {"approved": "redact", "monitored": "redact", "unsanctioned": "block",
                  "personal": "block", "unclassified": "block"},
}


def stricter(a: str, b: str) -> str:
    return a if _RANK[a] >= _RANK[b] else b


@dataclass
class BrowserDecision:
    action: str
    state: str
    app_key: str
    rules: list[str]
    reason: str


@dataclass
class PolicyChange:
    change_id: str
    app_id: str
    new_state: str
    proposed_by: str
    reason: str
    approver: str | None = None
    status: str = "pending"


class BrowserPolicyEngine:
    def __init__(self, catalog=CATALOG, policy: dict | None = None,
                 agent_ids: set | None = None):
        self.apps: dict[str, AIApp] = catalog_by_host(catalog)
        self.state_by_app = {a.app_id: a.sanction for a in catalog}
        self.policy = policy or DEFAULT_POLICY
        self.agent_ids = set(agent_ids or ())
        self.changes: dict[str, PolicyChange] = {}
        self.decisions: list[BrowserDecision] = []

    def state_for(self, event: dict) -> tuple[str, str]:
        app = self.apps.get(event.get("host", ""))
        if app is None:
            return "unclassified", f"unclassified:{event.get('host', '')}"
        state = self.state_by_app[app.app_id]
        login = event.get("login_domain", CORPORATE_LOGIN_DOMAIN)
        if state in ("approved", "monitored") and login != CORPORATE_LOGIN_DOMAIN:
            return "personal", app.app_id
        return state, app.app_id

    def evaluate(self, event: dict) -> BrowserDecision:
        state, key = self.state_for(event)
        rules = ["BPOL-01"]
        action = self.policy["state_defaults"].get(state, "block")   # unknown state: fail closed
        if state == "personal":
            rules.append("BPOL-04")
        override = self.policy["group_overrides"].get(event.get("group", ""), {}).get(state)
        if override:
            action = stricter(action, override)
            rules.append("BPOL-02")
        if event.get("sensitive"):
            action = stricter(action, self.policy["sensitive"].get(state, "block"))
            rules.append("BPOL-03")
        d = BrowserDecision(action, state, key, rules,
                            f"{state} app, group {event.get('group', '?')}"
                            + (", sensitive content" if event.get("sensitive") else ""))
        self.decisions.append(d)
        return d

    # ---- policy changes: proposed by anyone, approved by a named human ----
    def propose(self, app_id: str, new_state: str, proposed_by: str, reason: str) -> str:
        if new_state not in ("approved", "monitored", "unsanctioned"):
            raise ValueError("new_state must be approved, monitored or unsanctioned")
        if app_id not in self.state_by_app:
            raise KeyError(app_id)
        cid = f"BPC-{len(self.changes) + 1:03d}"
        self.changes[cid] = PolicyChange(cid, app_id, new_state, proposed_by, reason)
        return cid

    def approve(self, change_id: str, approver: str) -> PolicyChange:
        ch = self.changes[change_id]
        name = (approver or "").strip()
        if not name or name == ch.proposed_by or name in self.agent_ids or name.startswith("agt-"):
            raise PermissionError("BPOL-05: a named human other than the proposer must approve")
        if ch.status != "pending":
            raise PermissionError("BPOL-05: change already decided")
        ch.approver, ch.status = name, "approved"
        self.state_by_app[ch.app_id] = ch.new_state
        return ch

    def summary(self) -> dict:
        out = {a: 0 for a in ACTIONS}
        by_state: dict[str, int] = {}
        for d in self.decisions:
            out[d.action] += 1
            by_state[d.state] = by_state.get(d.state, 0) + 1
        return {"actions": out, "by_state": dict(sorted(by_state.items())),
                "total": len(self.decisions)}


def synthetic_browser_events(seed: int = 11, n: int = 400) -> list[dict]:
    import random
    rng = random.Random(seed)
    hosts = [a.host for a in CATALOG] + ["summarize-anything.example"]
    groups = ("finance", "engineering", "sales", "support", "hr")
    out = []
    for i in range(n):
        host = rng.choice(hosts)
        out.append({"user": f"user{i % 60:03d}", "group": groups[i % 5], "host": host,
                    "login_domain": "gmail-like.example" if rng.random() < 0.06 else CORPORATE_LOGIN_DOMAIN,
                    "sensitive": rng.random() < 0.08})
    return out
