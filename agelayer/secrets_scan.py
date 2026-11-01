"""Small secret detector used by the coding-agent session guard.

Pattern families (generic names, no provider branding):
  cloud_access_key  20-char key id with a 4-letter prefix (AK + 2 letters)
  git_token         "gh" + one letter + "_" + 36 alphanumerics
  chat_bot_token    "xox" + letter + "-" + digit groups
  private_key       a PEM private-key header
  generic_secret    secret/token/password/api_key = "<high-entropy value>"

A longer version with validators and an eval set lives in Jagadish-pii-guard
(``piiguard/gateway``). Test secrets are assembled at runtime by
``fake_secret`` so no secret-shaped literal is stored in the repo (and secret
scanners such as gitleaks stay quiet on the fixtures).
"""

from __future__ import annotations

import math
import random
import re
import string

_PEM = "-----BEGIN " + "(?:RSA |EC |OPENSSH )?PRIVATE KEY-----"
PATTERNS = {
    "cloud_access_key": re.compile(r"\b(?:AK|AS)IA[A-Z0-9]{16}\b"),
    "git_token": re.compile(r"\bgh[pousr]_[A-Za-z0-9]{36}\b"),
    "chat_bot_token": re.compile(r"\bxox[abpr]-\d{6,}-\d{6,}-[A-Za-z0-9]{12,}\b"),
    "private_key": re.compile(_PEM),
    "generic_secret": re.compile(
        r"(?i)\b(?:secret|token|passwd|password|api[_-]?key)\s*[:=]\s*['\"]([^'\"\s]{16,})['\"]"),
}


def entropy(s: str) -> float:
    if not s:
        return 0.0
    counts = {c: s.count(c) for c in set(s)}
    return -sum(n / len(s) * math.log2(n / len(s)) for n in counts.values())


def find_secrets(text: str) -> list[tuple[str, int, int]]:
    hits = []
    for kind, rx in PATTERNS.items():
        for m in rx.finditer(text):
            if kind == "generic_secret":
                value = m.group(1)
                if entropy(value) < 3.5 or value.lower().startswith(("changeme", "example", "xxxx")):
                    continue
            hits.append((kind, m.start(), m.end()))
    return sorted(hits, key=lambda h: h[1])


def fake_secret(kind: str, seed: int = 1) -> str:
    """Build a synthetic, never-valid secret of the given shape at runtime."""
    rng = random.Random(f"{kind}:{seed}")
    up = string.ascii_uppercase + string.digits
    an = string.ascii_letters + string.digits
    if kind == "cloud_access_key":
        return "AK" + "IA" + "".join(rng.choice(up) for _ in range(16))
    if kind == "git_token":
        return "gh" + "p_" + "".join(rng.choice(an) for _ in range(36))
    if kind == "chat_bot_token":
        return ("xo" + "xb-" + "".join(rng.choice(string.digits) for _ in range(10)) + "-"
                + "".join(rng.choice(string.digits) for _ in range(10)) + "-"
                + "".join(rng.choice(an) for _ in range(24)))
    if kind == "private_key":
        return "-----BEGIN " + "RSA PRIVATE KEY-----\n" + "".join(rng.choice(an) for _ in range(40))
    if kind == "generic_secret":
        return "".join(rng.choice(an) for _ in range(32))
    raise ValueError(kind)
