"""Tool-name shadowing across MCP servers.

A malicious server can publish a tool with the same (or nearly the same) name
as a trusted one so the model calls the wrong one.

  SHADOW-MCP-01  exact name collision between two servers
  SHADOW-MCP-02  collision after normalisation (case, '-', '_', '.', digits 0/1 for o/l)
"""

from __future__ import annotations


def normalise(name: str) -> str:
    n = name.lower().replace("-", "").replace("_", "").replace(".", "")
    return n.translate(str.maketrans({"0": "o", "1": "l", "3": "e", "5": "s"}))


def find_collisions(listings: dict[str, list[str]], trusted: set | None = None) -> list[dict]:
    trusted = trusted or set()
    seen: dict[str, list[tuple[str, str]]] = {}
    for server, names in listings.items():
        for n in names:
            seen.setdefault(normalise(n), []).append((server, n))
    out = []
    for key, entries in seen.items():
        servers = {s for s, _ in entries}
        if len(servers) < 2:
            continue
        exact = len({n for _, n in entries}) == 1
        out.append({"rule_id": "SHADOW-MCP-01" if exact else "SHADOW-MCP-02",
                    "normalised": key, "entries": sorted(entries),
                    "suspect_servers": sorted(servers - trusted)})
    return sorted(out, key=lambda x: x["normalised"])
