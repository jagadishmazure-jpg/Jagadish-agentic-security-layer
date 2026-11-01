"""Coding-agent session prompt guard (synthetic IDE-assistant transcripts).

Coding assistants send prompts, open files and tool outputs to a model. This
guard reads a session transcript (a list of turns) and checks what would
leave the machine:

  CSG-01  secret in a prompt or in context sent to the model -> block the turn
  CSG-02  a secrets file (.env, key files, cloud credential files) read into context -> block
  CSG-03  code from a restricted path sent to an assistant not approved for it -> block
  CSG-04  session by an agent id that is not registered -> shadow finding
  CSG-05  assistant app is unsanctioned (see shadow_ai) -> warn, queue for review

Findings carry the type and turn number only, never the secret value.
"""

from __future__ import annotations

import fnmatch

from . import registry
from .secrets_scan import find_secrets

SECRET_FILES = ("*.env", ".env", "*.pem", "*id_rsa*", "*credentials*", "*.pfx", "*secrets.json")
RESTRICTED_PATHS = ("payments/*", "restricted/*", "crypto/*")
APPROVED_FOR_RESTRICTED = {"app-stackwise"}
SANCTIONED_ASSISTANTS = {"app-stackwise"}


def _is_secret_file(path: str) -> bool:
    name = path.rsplit("/", 1)[-1]
    return any(fnmatch.fnmatch(name, p) or fnmatch.fnmatch(path, p) for p in SECRET_FILES)


def guard_session(session: dict, conn=None) -> dict:
    """session: {session_id, agent_id, app_id, user, turns: [{role, content, file?}]}"""
    findings, blocked_turns = [], set()
    app = session.get("app_id", "")
    if app not in SANCTIONED_ASSISTANTS:
        findings.append({"rule_id": "CSG-05", "turn": None, "type": "unsanctioned_assistant",
                         "action": "warn"})
    if conn is not None:
        agent = registry.get_agent(conn, session.get("agent_id", ""))
        if agent is None or agent["status"] != "active":
            findings.append({"rule_id": "CSG-04", "turn": None, "type": "unregistered_agent",
                             "action": "shadow-finding"})
    for i, turn in enumerate(session.get("turns", [])):
        if turn.get("role") not in ("user", "context", "tool"):
            continue                      # model replies do not leave the machine
        path = turn.get("file", "")
        if path and _is_secret_file(path):
            findings.append({"rule_id": "CSG-02", "turn": i, "type": "secrets_file", "action": "block"})
            blocked_turns.add(i)
        for kind, _s, _e in find_secrets(turn.get("content", "")):
            findings.append({"rule_id": "CSG-01", "turn": i, "type": kind, "action": "block"})
            blocked_turns.add(i)
        if path and any(fnmatch.fnmatch(path, p) for p in RESTRICTED_PATHS) \
                and app not in APPROVED_FOR_RESTRICTED:
            findings.append({"rule_id": "CSG-03", "turn": i, "type": "restricted_code", "action": "block"})
            blocked_turns.add(i)
    return {"session_id": session.get("session_id"), "findings": findings,
            "blocked_turns": sorted(blocked_turns),
            "turns_sent": len(session.get("turns", [])) - len(blocked_turns)}


def demo_sessions() -> list[dict]:
    from .secrets_scan import fake_secret
    return [
        {"session_id": "cs-001", "agent_id": "agt-ide-stackwise", "app_id": "app-stackwise", "user": "user003",
         "turns": [
             {"role": "user", "content": "Refactor the retry helper in utils/http.py"},
             {"role": "context", "file": "utils/http.py", "content": "def retry(fn, n=3):\n    ..."},
             {"role": "assistant", "content": "Here is a version with backoff."},
         ]},
        {"session_id": "cs-002", "agent_id": "agt-ide-stackwise", "app_id": "app-stackwise", "user": "user008",
         "turns": [
             {"role": "user", "content": "Why does the deploy fail? config: api_key = \""
              + fake_secret("generic_secret", 2) + "\""},
             {"role": "context", "file": "deploy/.env", "content": "DB_PASSWORD=..."},
             {"role": "context", "file": "payments/ledger.py", "content": "class Ledger: ..."},
         ]},
        {"session_id": "cs-003", "agent_id": "gitmuse-cli", "app_id": "app-gitmuse", "user": "user013",
         "turns": [
             {"role": "user", "content": "Push with this token " + fake_secret("git_token", 3)},
             {"role": "context", "file": "payments/refunds.py", "content": "def refund(...): ..."},
         ]},
    ]
