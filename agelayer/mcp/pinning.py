"""Pin MCP tool descriptions and schemas; alert when they change ("rug pull").

The first approved tools/list response is pinned as SHA-256 hashes per tool.
Later listings are compared:

  DRIFT-01  a tool's description changed
  DRIFT-02  a tool's input schema changed
  DRIFT-03  a new tool appeared
  DRIFT-04  a pinned tool disappeared

Any drift quarantines the server until a named human re-approves the new
listing (``approve``). Quarantined servers are denied by the gateway.
"""

from __future__ import annotations

import hashlib
import json


def _h(obj) -> str:
    return hashlib.sha256(json.dumps(obj, sort_keys=True).encode()).hexdigest()


def fingerprint(tools: list[dict]) -> dict:
    return {t["name"]: {"description": _h(t.get("description", "")),
                        "schema": _h(t.get("inputSchema", {}))} for t in tools}


class PinStore:
    def __init__(self):
        self.pins: dict[str, dict] = {}
        self.quarantined: set[str] = set()
        self.events: list[dict] = []
        self.approvals: list[dict] = []

    def pin(self, server_id: str, tools: list[dict], approver: str) -> None:
        if not (approver or "").strip() or approver.startswith("agt-"):
            raise PermissionError("DRIFT: pinning needs a named human")
        self.pins[server_id] = fingerprint(tools)
        self.quarantined.discard(server_id)
        self.approvals.append({"server_id": server_id, "approver": approver, "tools": len(tools)})

    approve = pin

    def compare(self, server_id: str, tools: list[dict]) -> list[dict]:
        if server_id not in self.pins:
            return [{"rule_id": "DRIFT-00", "server_id": server_id, "tool": None,
                     "detail": "no pin yet; listing needs human approval"}]
        old, new = self.pins[server_id], fingerprint(tools)
        found = []
        for name, fp in new.items():
            if name not in old:
                found.append(("DRIFT-03", name, "new tool"))
                continue
            if fp["description"] != old[name]["description"]:
                found.append(("DRIFT-01", name, "description changed"))
            if fp["schema"] != old[name]["schema"]:
                found.append(("DRIFT-02", name, "input schema changed"))
        for name in old:
            if name not in new:
                found.append(("DRIFT-04", name, "tool removed"))
        events = [{"rule_id": r, "server_id": server_id, "tool": t, "detail": d} for r, t, d in found]
        if events:
            self.quarantined.add(server_id)
            self.events.extend(events)
        return events
