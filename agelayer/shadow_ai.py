"""Shadow AI and SaaS app discovery for the workforce (synthetic logs only).

``shadow.py`` finds unregistered *agents* from tool-call activity. This module
finds the AI and SaaS *apps* people use: web chat tools, browser extensions,
coding assistants, desktop agents, AI features inside SaaS apps, MCP clients
and tools, and ordinary SaaS apps. It reads synthetic proxy, CASB,
browser-extension, IDE-plugin and browsing records, matches them to an app
catalog, scores each app's risk, and builds a decision queue
(keep, review-to-sanction, restrict, block). Every queue item is a
recommendation that a named person decides.

Sanction states (per app): approved, monitored, unsanctioned. A fourth state,
``personal``, is per use: an approved or monitored app used through a
personal (non-SSO) account.

Rules:
  SAI-01  app seen and in the catalog, but unsanctioned (shadow AI or SaaS)
  SAI-02  AI-like traffic to a host not in the catalog (unclassified);
          treated as "restrict" until a person classifies it (fail-closed)
  SAI-03  approved or monitored app used through a personal account
  SAI-04  upload volume to an unsanctioned or unclassified app above threshold

All names, hosts and users are fictional. Hosts use the reserved ``.example``
domain.
"""

from __future__ import annotations

import random
from dataclasses import dataclass, field

APP_TYPES = ("web_chat", "browser_extension", "coding_assistant",
             "desktop_agent", "saas_embedded", "mcp_client", "mcp_tool", "saas")
SANCTION_STATES = ("approved", "monitored", "unsanctioned")

AI_PATH_HINTS = ("/v1/chat/completions", "/v1/messages", "/v1/responses",
                 "/api/generate", "/mcp", "/sse")

UPLOAD_ALERT_BYTES = 5_000_000
BUSINESS_UNITS = ("finance", "engineering", "sales", "support", "hr")


@dataclass(frozen=True)
class AIApp:
    app_id: str
    name: str
    host: str
    app_type: str
    sanction: str
    trains_on_data: bool
    retention_days: int
    sso: bool
    is_ai: bool = True

    def __post_init__(self):
        if self.app_type not in APP_TYPES:
            raise ValueError(f"unknown app_type {self.app_type}")
        if self.sanction not in SANCTION_STATES:
            raise ValueError(f"unknown sanction state {self.sanction}")
        if self.retention_days < 0:
            raise ValueError("retention_days must be >= 0")

    @property
    def sanctioned(self) -> bool:
        return self.sanction in ("approved", "monitored")


CATALOG: tuple[AIApp, ...] = (
    AIApp("app-quillwise", "Quillwise Chat (enterprise)", "chat.quillwise.example",
          "web_chat", "approved", False, 0, True),
    AIApp("app-stackwise", "Stackwise Code Assist", "api.stackwise.example",
          "coding_assistant", "approved", False, 30, True),
    AIApp("app-ledgerlens", "Ledgerlens AI (in the finance suite)", "ai.ledgerlens.example",
          "saas_embedded", "approved", False, 30, True),
    AIApp("app-files-mcp", "Local files MCP tool", "mcp.files.internal.example",
          "mcp_tool", "approved", False, 0, True),
    AIApp("app-notetaker", "Owlnote meeting bot", "owlnote.example",
          "saas_embedded", "monitored", False, 365, True),
    AIApp("app-parrotly", "Parrotly free chat", "parrotly.example",
          "web_chat", "unsanctioned", True, 365, False),
    AIApp("app-draftbird", "Draftbird writing extension", "ext.draftbird.example",
          "browser_extension", "unsanctioned", True, 180, False),
    AIApp("app-gitmuse", "Gitmuse code helper", "gitmuse.example",
          "coding_assistant", "unsanctioned", False, 90, False),
    AIApp("app-deskgenie", "DeskGenie desktop agent", "sync.deskgenie.example",
          "desktop_agent", "unsanctioned", True, 30, False),
    AIApp("app-scrape-mcp", "FreeScrape MCP server", "freescrape-mcp.example",
          "mcp_tool", "unsanctioned", True, 30, False),
    AIApp("app-mcp-desktop", "Generic MCP desktop client", "mcp-desktop.example",
          "mcp_client", "unsanctioned", False, 0, False),
    AIApp("saas-boxdrop", "Boxdrop file sharing (personal tier)", "boxdrop.example",
          "saas", "unsanctioned", False, 365, False, is_ai=False),
    AIApp("saas-tasklane", "Tasklane project boards", "tasklane.example",
          "saas", "approved", False, 365, True, is_ai=False),
)

_TYPE_WEIGHT = {"web_chat": 5, "browser_extension": 15, "coding_assistant": 10,
                "desktop_agent": 15, "saas_embedded": 5, "mcp_client": 10,
                "mcp_tool": 15, "saas": 5}


def catalog_by_host(catalog=CATALOG) -> dict[str, AIApp]:
    return {a.host: a for a in catalog}


def risk_score(app: AIApp, upload_bytes: int = 0) -> int:
    """0-100. Higher means riskier to allow without controls."""
    score = _TYPE_WEIGHT[app.app_type]
    if app.trains_on_data:
        score += 25
    if app.retention_days > 180:
        score += 20
    elif app.retention_days > 30:
        score += 10
    if not app.sso:
        score += 15
    if upload_bytes > UPLOAD_ALERT_BYTES:
        score += 10
    if not app.sanctioned:
        score += 10
    return max(0, min(100, score))


def risk_band(score: int) -> str:
    return "high" if score >= 60 else "medium" if score >= 35 else "low"


def recommend(app: AIApp | None, score: int) -> str:
    if app is None:
        return "restrict"            # SAI-02, fail-closed
    if app.sanctioned:
        return "keep"
    if score >= 60:
        return "block"
    if score >= 35:
        return "restrict"
    return "review-to-sanction"


@dataclass
class AppUsage:
    key: str
    app: AIApp | None
    host: str
    users: set = field(default_factory=set)
    business_units: dict = field(default_factory=dict)
    events: int = 0
    upload_bytes: int = 0
    personal_users: set = field(default_factory=set)
    sources: set = field(default_factory=set)
    weeks: dict = field(default_factory=dict)
    first_seen: str = ""


def _is_ai_traffic(event: dict) -> bool:
    path = event.get("path", "")
    return any(path.startswith(h) or path.endswith(h) for h in AI_PATH_HINTS)


def discover(events: list[dict], catalog=CATALOG) -> dict:
    """Build the AI and SaaS inventory from synthetic log events.

    event keys: ts (ISO date), week, user, bu, host, path, bytes_up,
    source (proxy | casb | extension | ide | mcp | browser), account (sso | personal)
    """
    by_host = catalog_by_host(catalog)
    usage: dict[str, AppUsage] = {}
    for ev in events:
        host = ev.get("host", "")
        app = by_host.get(host)
        if app is None and not _is_ai_traffic(ev):
            continue
        key = app.app_id if app else f"unclassified:{host}"
        u = usage.setdefault(key, AppUsage(key=key, app=app, host=host))
        user = ev.get("user", "?")
        u.users.add(user)
        u.business_units.setdefault(ev.get("bu", "unknown"), set()).add(user)
        u.events += 1
        u.upload_bytes += int(ev.get("bytes_up", 0))
        if ev.get("account") == "personal":
            u.personal_users.add(user)
        u.sources.add(ev.get("source", "proxy"))
        u.weeks.setdefault(ev.get("week", "w?"), set()).add(user)
        ts = ev.get("ts", "")
        if ts and (not u.first_seen or ts < u.first_seen):
            u.first_seen = ts

    rows, findings = [], []
    for key in sorted(usage):
        u = usage[key]
        if u.app is None:
            score = 50 + (10 if u.upload_bytes > UPLOAD_ALERT_BYTES else 0)
            rule = "SAI-02"
            state = "unclassified"
        else:
            score = risk_score(u.app, u.upload_bytes)
            rule = None if u.app.sanctioned else "SAI-01"
            state = u.app.sanction
        rec = recommend(u.app, score)
        row = {
            "key": key,
            "name": u.app.name if u.app else f"(unclassified) {u.host}",
            "app_type": u.app.app_type if u.app else "unknown",
            "is_ai": bool(u.app.is_ai) if u.app else True,
            "sanction": state,
            "sanctioned": bool(u.app and u.app.sanctioned),
            "users": len(u.users),
            "personal_users": len(u.personal_users),
            "events": u.events,
            "upload_mb": round(u.upload_bytes / 1_000_000, 1),
            "risk": score,
            "band": risk_band(score),
            "recommendation": rec,
            "first_seen": u.first_seen,
            "sources": sorted(u.sources),
        }
        rows.append(row)
        if rule:
            findings.append({"rule_id": rule, "key": key, "recommendation": rec,
                             "users": len(u.users)})
        if u.app and u.app.sanctioned and u.personal_users:
            findings.append({"rule_id": "SAI-03", "key": key, "recommendation": "enforce-sso",
                             "users": len(u.personal_users)})
        if (not row["sanctioned"]) and u.upload_bytes > UPLOAD_ALERT_BYTES:
            findings.append({"rule_id": "SAI-04", "key": key, "recommendation": rec,
                             "users": len(u.users)})
    return {"apps": rows, "findings": findings, "usage": usage}


def decision_queue(inventory: dict) -> list[dict]:
    """Items a person must decide, riskiest first. Nothing is auto-applied."""
    items = [r for r in inventory["apps"] if r["recommendation"] != "keep"]
    return sorted(items, key=lambda r: (-r["risk"], r["key"]))


def kpis(inventory: dict) -> dict:
    """K01 inventory coverage and K02 shadow AI users, plus sanction counts."""
    usage: dict[str, AppUsage] = inventory["usage"]
    ai = {k: u for k, u in usage.items() if u.app is None or u.app.is_ai}
    seen = len(ai)
    known = sum(1 for u in ai.values() if u.app is not None)
    total_events = sum(u.events for u in ai.values()) or 1
    sanctioned_events = sum(u.events for u in ai.values() if u.app and u.app.sanctioned)
    personal = [u.personal_users for u in ai.values() if u.app and u.app.sanctioned]
    personal_events_users = set().union(*personal) if personal else set()
    shadow_by_bu: dict[str, set] = {}
    for u in ai.values():
        if u.app and u.app.sanctioned:
            continue
        for bu, users in u.business_units.items():
            shadow_by_bu.setdefault(bu, set()).update(users)
    shadow = set().union(*shadow_by_bu.values()) if shadow_by_bu else set()
    all_users = set().union(*(u.users for u in ai.values())) if ai else set()
    by_state: dict[str, int] = {}
    for r in inventory["apps"]:
        if r["is_ai"]:
            by_state[r["sanction"]] = by_state.get(r["sanction"], 0) + 1
    return {
        "ai_apps_seen": seen,
        "ai_apps_known": known,
        "inventory_coverage": round(known / seen, 3) if seen else 1.0,
        "sanctioned_share": round(sanctioned_events / total_events, 3),
        "shadow_share": round(1 - sanctioned_events / total_events, 3),
        "shadow_users": len(shadow),
        "ai_users": len(all_users),
        "personal_account_users": len(personal_events_users),
        "shadow_users_by_bu": {bu: len(s) for bu, s in sorted(shadow_by_bu.items())},
        "ai_apps_by_state": dict(sorted(by_state.items())),
    }


def adoption_trend(inventory: dict) -> dict[str, dict[str, int]]:
    return {key: {w: len(s) for w, s in sorted(u.weeks.items())}
            for key, u in sorted(inventory["usage"].items())}


_WEIGHTS = {
    "app-quillwise": 30, "app-stackwise": 12, "app-ledgerlens": 6, "app-files-mcp": 4,
    "app-notetaker": 3, "app-parrotly": 9, "app-draftbird": 5, "app-gitmuse": 4,
    "app-deskgenie": 2, "app-scrape-mcp": 1, "app-mcp-desktop": 1,
    "saas-boxdrop": 3, "saas-tasklane": 8,
}
_SOURCE = {"web_chat": "proxy", "browser_extension": "extension", "coding_assistant": "ide",
           "desktop_agent": "proxy", "saas_embedded": "casb", "mcp_client": "mcp",
           "mcp_tool": "mcp", "saas": "browser"}


def synthetic_events(seed: int = 7, users: int = 60, days: int = 7, start_day: int = 25,
                     catalog=CATALOG) -> list[dict]:
    """Deterministic synthetic proxy, CASB, extension, IDE, MCP and browsing records."""
    rng = random.Random(seed)
    people = [(f"user{i:03d}", BUSINESS_UNITS[i % len(BUSINESS_UNITS)]) for i in range(users)]
    prone = {u for u, _ in people if rng.random() < 0.35}   # users who try shadow tools
    apps = {a.app_id: a for a in catalog}
    keys = sorted(k for k in _WEIGHTS if k in apps)
    w = [_WEIGHTS[k] for k in keys]
    events = []
    for day in range(days):
        dnum = start_day + day
        date = f"2026-10-{dnum:02d}" if dnum <= 31 else f"2026-11-{dnum - 31:02d}"
        week = "2026-W44" if dnum < 26 + 7 else "2026-W45"
        for user, bu in people:
            for _ in range(rng.randint(0, 4)):
                app = apps[rng.choices(keys, weights=w)[0]]
                if not app.sanctioned and user not in prone:
                    continue
                if app.app_type == "coding_assistant" and bu != "engineering" and rng.random() < 0.8:
                    continue
                personal = app.sanctioned and rng.random() < 0.03
                events.append({
                    "ts": date, "week": week, "user": user, "bu": bu,
                    "host": app.host, "path": "/v1/chat/completions" if app.is_ai else "/files",
                    "bytes_up": rng.randint(500, 40_000) * (40 if app.app_id == "app-deskgenie" else 1),
                    "source": _SOURCE[app.app_type],
                    "account": "personal" if personal or not app.sso else "sso",
                })
            if user in prone and rng.random() < 0.05:
                events.append({"ts": date, "week": week, "user": user, "bu": bu,
                               "host": "summarize-anything.example", "path": "/api/generate",
                               "bytes_up": rng.randint(1000, 9000), "source": "proxy",
                               "account": "personal"})
            if rng.random() < 0.5:
                events.append({"ts": date, "week": week, "user": user, "bu": bu,
                               "host": "intranet.example", "path": "/home",
                               "bytes_up": 200, "source": "proxy", "account": "sso"})
    return events
