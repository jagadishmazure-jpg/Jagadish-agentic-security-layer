"""Hash-chained audit log: tamper-evident record of bridge decisions,
shadow findings, and impact analyses."""

from __future__ import annotations

import hashlib
import json
from datetime import datetime, timezone


def _utcnow() -> str:
    return datetime.now(timezone.utc).isoformat(timespec="seconds")


class AuditLog:
    def __init__(self):
        self.entries: list[dict] = []

    def record(self, kind: str, payload: dict) -> dict:
        prev = self.entries[-1]["digest"] if self.entries else "GENESIS"
        body = {"seq": len(self.entries), "ts": _utcnow(), "kind": kind,
                "payload": payload, "prev": prev}
        digest = hashlib.sha256(
            json.dumps(body, sort_keys=True).encode()).hexdigest()
        body["digest"] = digest
        self.entries.append(body)
        return body

    def verify(self) -> bool:
        prev = "GENESIS"
        for i, entry in enumerate(self.entries):
            if entry["seq"] != i or entry["prev"] != prev:
                return False
            body = {k: v for k, v in entry.items() if k != "digest"}
            if hashlib.sha256(json.dumps(body, sort_keys=True).encode()
                              ).hexdigest() != entry["digest"]:
                return False
            prev = entry["digest"]
        return True
