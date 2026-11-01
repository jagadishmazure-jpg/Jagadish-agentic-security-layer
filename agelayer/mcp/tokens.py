"""Short-lived, scoped tokens for agent -> MCP server calls.

Tokens are HMAC-SHA256 signed claims: subject (agent), audience (one MCP
server), scopes, issued-at and expiry. Rules on verification:

  TOK-01  bad signature or malformed token
  TOK-02  expired
  TOK-03  audience mismatch (token minted for another server: no passthrough)
  TOK-04  scope not granted
  TOK-05  lifetime above the 900-second cap (refused at mint time)
  TOK-06  token replayed after revocation

The signing key comes from AGELAYER_MCP_TOKEN_KEY or a random per-process
key. It is never logged. This is a teaching model of the pattern, not a
replacement for an OAuth server.
"""

from __future__ import annotations

import base64
import hashlib
import hmac
import json
import os
import secrets

MAX_TTL = 900


class TokenError(Exception):
    def __init__(self, rule_id, message):
        super().__init__(message)
        self.rule_id = rule_id


def _b64(b: bytes) -> str:
    return base64.urlsafe_b64encode(b).decode().rstrip("=")


def _unb64(s: str) -> bytes:
    return base64.urlsafe_b64decode(s + "=" * (-len(s) % 4))


class TokenIssuer:
    def __init__(self, key: bytes | None = None):
        env = os.environ.get("AGELAYER_MCP_TOKEN_KEY")
        self._key = key or (env.encode() if env else os.urandom(32))
        self.revoked: set[str] = set()
        self.issued = 0

    def mint(self, agent_id: str, audience: str, scopes: list[str], now: int, ttl: int = 300) -> str:
        if ttl <= 0 or ttl > MAX_TTL:
            raise TokenError("TOK-05", f"ttl must be 1..{MAX_TTL} seconds")
        if not scopes:
            raise TokenError("TOK-04", "at least one scope")
        claims = {"sub": agent_id, "aud": audience, "scp": sorted(scopes),
                  "iat": now, "exp": now + ttl, "jti": secrets.token_hex(8)}
        body = _b64(json.dumps(claims, sort_keys=True).encode())
        sig = _b64(hmac.new(self._key, body.encode(), hashlib.sha256).digest())
        self.issued += 1
        return f"{body}.{sig}"

    def verify(self, token: str, audience: str, scope: str, now: int) -> dict:
        try:
            body, sig = token.split(".")
            good = _b64(hmac.new(self._key, body.encode(), hashlib.sha256).digest())
            if not hmac.compare_digest(sig, good):
                raise ValueError
            claims = json.loads(_unb64(body))
        except Exception as exc:
            raise TokenError("TOK-01", "bad signature or malformed token") from exc
        if claims["jti"] in self.revoked:
            raise TokenError("TOK-06", "token revoked")
        if now >= claims["exp"]:
            raise TokenError("TOK-02", "token expired")
        if claims["aud"] != audience:
            raise TokenError("TOK-03", "token audience is another server")
        if scope not in claims["scp"]:
            raise TokenError("TOK-04", f"scope {scope} not granted")
        return claims

    def revoke(self, token: str) -> None:
        body = token.split(".")[0]
        self.revoked.add(json.loads(_unb64(body))["jti"])
