"""Scan MCP tool descriptions for hidden instructions (tool poisoning).

Descriptions are read by the model, not by people, so a malicious server can
hide instructions in them. Rules:

  POISON-01  instructions aimed at the model ("ignore previous", "you must", "before using any tool")
  POISON-02  concealment ("do not tell the user", "don't mention")
  POISON-03  sensitive file or credential paths (~/.ssh, .env, id_rsa, credentials)
  POISON-04  exfiltration ("send ... to", "include ... in the <param>", URLs in descriptions)
  POISON-05  hidden text: zero-width or bidi control characters, HTML comments, <IMPORTANT>-style tags
  POISON-06  long base64-looking blobs
  POISON-07  cross-tool steering: tells the model how to use *another* tool

Pattern-based. Paraphrased or translated instructions can be missed; those
cases are kept in data/mcp_tool_descriptions.json as known misses.
"""

from __future__ import annotations

import re
import unicodedata

HIDDEN_CHARS = {"\u200b", "\u200c", "\u200d", "\u2060", "\ufeff",
                "\u202a", "\u202b", "\u202c", "\u202d", "\u202e", "\u2066", "\u2067", "\u2068", "\u2069"}

RULES = [
    ("POISON-01", re.compile(r"(?i)\b(ignore (all |any )?(previous|prior|above) (instructions|rules)|"
                             r"you must|before using (any|this|the) tool|always (first )?call|"
                             r"system prompt|as the assistant,? you)")),
    ("POISON-02", re.compile(r"(?i)\b(do not|don't|never) (tell|mention|inform|reveal|show)\b.{0,30}\b(user|them|human)|"
                             r"\b(keep this|this is) (secret|hidden)|\bsilently\b")),
    ("POISON-03", re.compile(r"(?i)(~/\.ssh|id_rsa|\.env\b|/etc/passwd|credentials(\.json)?\b|\.aws/|private key)")),
    ("POISON-04", re.compile(r"(?i)(send (it|them|the \w+|all \w+) to|forward (it|them|\w+) to|"
                             r"include (it|them|the \w+|its contents) (in|as) the \w+|https?://)")),
    ("POISON-06", re.compile(r"[A-Za-z0-9+/]{60,}={0,2}")),
    ("POISON-07", re.compile(r"(?i)when (the user |you )?(call|use)s? (the )?[`'\"]?[a-z_]+[`'\"]? tool|"
                             r"instead of (the )?[a-z_]+ tool|(also|instead) call [a-z_]+")),
]
TAG_RX = re.compile(r"(?i)<!--.*?-->|</?(important|system|instructions?|secret)>", re.S)


def scan(description: str) -> list[dict]:
    hits = []
    if any(c in HIDDEN_CHARS for c in description) or TAG_RX.search(description):
        hits.append({"rule_id": "POISON-05", "detail": "hidden text or control characters"})
    clean = unicodedata.normalize("NFKC", "".join(c for c in description if c not in HIDDEN_CHARS))
    clean = TAG_RX.sub(" ", clean) + " " + " ".join(m.group(0) for m in TAG_RX.finditer(description))
    for rule, rx in RULES:
        m = rx.search(clean)
        if m:
            hits.append({"rule_id": rule, "detail": m.group(0)[:60]})
    return hits


def scan_listing(server_id: str, tools: list[dict]) -> list[dict]:
    out = []
    for t in tools:
        for h in scan(t.get("description", "")):
            out.append({"server_id": server_id, "tool": t["name"], **h})
        # descriptions hidden inside parameter descriptions count too
        for pname, p in (t.get("inputSchema", {}).get("properties", {}) or {}).items():
            for h in scan(str(p.get("description", ""))):
                out.append({"server_id": server_id, "tool": f"{t['name']}.{pname}", **h})
    return out


def evaluate(cases: list[dict]) -> dict:
    tp = fp = fn = tn = 0
    misses = []
    for c in cases:
        flagged = bool(scan(c["description"]))
        want = c["label"] == "poisoned"
        tp += flagged and want
        fp += flagged and not want
        fn += (not flagged) and want
        tn += (not flagged) and not want
        if flagged != want:
            misses.append({"id": c["id"], "kind": "missed" if want else "false_flag"})
    return {"cases": len(cases), "tp": tp, "fp": fp, "fn": fn, "tn": tn,
            "precision": round(tp / (tp + fp), 3) if tp + fp else 1.0,
            "recall": round(tp / (tp + fn), 3) if tp + fn else 1.0, "misses": misses}
