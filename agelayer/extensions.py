"""Browser extension risk scoring (synthetic inventory).

Each installed extension is scored from its manifest permissions and a few
hygiene signals, then gets a recommendation: ``force-install`` (corporate
extension everyone needs), ``allow``, ``allow-with-review`` or ``block``.
A block is a recommendation; the extension owner signs off (EXT-04).

  EXT-01 high-risk permission (all-sites access, clipboard read, cookies,
         native messaging, request interception)
  EXT-02 sideloaded (not from the store) or not updated in over a year
  EXT-03 AI extension that sends page content to a remote service
  EXT-04 block needs a named owner sign-off
"""

from __future__ import annotations

from dataclasses import dataclass, field
from datetime import date

PERMISSION_WEIGHTS = {
    "<all_urls>": 30, "clipboardRead": 20, "cookies": 20, "nativeMessaging": 20,
    "webRequest": 15, "scripting": 15, "downloads": 10, "history": 10,
    "tabs": 5, "storage": 1, "activeTab": 2, "clipboardWrite": 3,
}
HIGH_RISK = {"<all_urls>", "clipboardRead", "cookies", "nativeMessaging", "webRequest"}


@dataclass
class Extension:
    ext_id: str
    name: str
    permissions: list[str]
    users: int
    from_store: bool = True
    last_update: str = "2026-09-01"
    ai_remote: bool = False
    corporate: bool = False
    flagged_on: str | None = None
    removed_on: str | None = None
    rules: list[str] = field(default_factory=list)


def score(ext: Extension, today: date = date(2026, 10, 31)) -> tuple[int, list[str]]:
    rules: list[str] = []
    s = sum(PERMISSION_WEIGHTS.get(p, 10) for p in set(ext.permissions))  # unknown permission: 10
    if HIGH_RISK & set(ext.permissions):
        rules.append("EXT-01")
    stale = (today - date.fromisoformat(ext.last_update)).days > 365
    if not ext.from_store or stale:
        s += 15
        rules.append("EXT-02")
    if ext.ai_remote:
        s += 15
        rules.append("EXT-03")
    return min(100, s), rules


def recommend(ext: Extension, s: int) -> str:
    if ext.corporate:
        return "force-install"
    if s >= 60:
        return "block"
    if s >= 30 or HIGH_RISK & set(ext.permissions):
        return "allow-with-review"   # any high-risk permission gets a human look
    return "allow"


def assess(inventory: list[Extension]) -> list[dict]:
    rows = []
    for e in inventory:
        s, rules = score(e)
        rows.append({"ext_id": e.ext_id, "name": e.name, "users": e.users, "score": s,
                     "rules": rules, "recommendation": recommend(e, s),
                     "high_risk_permissions": sorted(HIGH_RISK & set(e.permissions))})
    return sorted(rows, key=lambda r: (-r["score"], r["ext_id"]))


@dataclass
class BlockDecision:
    ext_id: str
    owner: str
    decided_on: str


def sign_off_block(row: dict, owner: str, decided_on: str) -> BlockDecision:
    if row["recommendation"] != "block":
        raise ValueError("only block recommendations need a sign-off")
    if not (owner or "").strip() or owner.startswith("agt-"):
        raise PermissionError("EXT-04: a named human owner must sign off a block")
    return BlockDecision(row["ext_id"], owner.strip(), decided_on)


def kpis(inventory: list[Extension]) -> dict:
    rows = assess(inventory)
    n = len(rows) or 1
    high = sum(1 for r in rows if r["high_risk_permissions"])
    blocked = sum(1 for e in inventory if e.removed_on)
    days = [(date.fromisoformat(e.removed_on) - date.fromisoformat(e.flagged_on)).days
            for e in inventory if e.flagged_on and e.removed_on]
    return {"extensions": len(rows), "high_risk_share": round(high / n, 3),
            "blocked_share": round(blocked / n, 3),
            "block_recommended": sum(1 for r in rows if r["recommendation"] == "block"),
            "mean_days_to_remove": round(sum(days) / len(days), 1) if days else None}


def demo_inventory() -> list[Extension]:
    """Fictional extensions. Dates are synthetic."""
    return [
        Extension("ext-sso-helper", "Corp SSO helper", ["storage", "activeTab"], 60, corporate=True),
        Extension("ext-pwmgr", "Vaultkeep password manager", ["storage", "activeTab", "clipboardWrite"], 41),
        Extension("ext-draftbird", "Draftbird writing assistant", ["<all_urls>", "clipboardRead", "storage"],
                  12, ai_remote=True, flagged_on="2026-10-20", removed_on="2026-10-23"),
        Extension("ext-coupon", "Snapcoupon deals", ["<all_urls>", "cookies", "webRequest", "tabs"], 6,
                  flagged_on="2026-10-21", removed_on="2026-10-22"),
        Extension("ext-tabsort", "Tabsort", ["tabs", "storage"], 17),
        Extension("ext-pdfquick", "PDF Quick", ["downloads", "activeTab"], 9, last_update="2024-03-01"),
        Extension("ext-devtool", "Header inspector (sideloaded)", ["webRequest", "<all_urls>"], 3,
                  from_store=False, flagged_on="2026-10-28"),
        Extension("ext-summarize", "Pagewise summarizer", ["activeTab", "scripting"], 14, ai_remote=True),
        Extension("ext-nativebridge", "Desktop bridge", ["nativeMessaging", "storage"], 2,
                  flagged_on="2026-10-29"),
    ]
