"""MCP (Model Context Protocol) security module.

Submodules:
  registry   server allow / deny lists and per-agent server grants (MCP-01..04)
  pinning    pin tool descriptions and schemas; alert on drift (DRIFT-01..04)
  poisoning  scan tool descriptions for hidden instructions (POISON-01..07)
  shadowing  tool-name collisions across servers (SHADOW-MCP-01/02)
  tokens     short-lived, audience- and scope-bound tokens (TOK-01..06)
  discovery  find MCP traffic in synthetic network / proxy logs (MCPD-01..03)
  gateway    one checkpoint that applies all of the above per tool call

Everything runs offline on synthetic data; no real MCP server is contacted.
"""
