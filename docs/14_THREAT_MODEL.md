# Threat model

*Step 14 of the reading path.*

## What you'll learn

- STRIDE threats and the control for each
- How the repo maps to the OWASP Top 10 for LLM Applications (2025) and the OWASP Top 10 for Agentic
  Applications (2026)

## STRIDE

| Threat | Control |
|---|---|
| **Spoofing**: unregistered agent calls tools | BRIDGE-01, shadow findings, CSG-04 |
| **Spoofing**: agent claims a human approved | BRIDGE-05/06; approvals, widening, resets, pins and policy changes all need a named non-agent human |
| **Spoofing**: token minted for one MCP server replayed at another | TOK-03 audience check |
| **Tampering**: MCP tool description changed after approval | DRIFT-01..04 pin and quarantine |
| **Tampering**: audit log edited | hash chain, `verify()` |
| **Repudiation**: "the agent didn't do that" | every guard and bridge decision is chained |
| **Information disclosure**: secrets sent by a coding assistant | CSG-01/02 |
| **Information disclosure**: sensitive paste to an unsanctioned app | BPOL-03 block, BPOL-02 group overrides |
| **Denial of service / wallet**: runaway agent | BUDGET-01..03, LOOP-01/02, KILL-01 |
| **Elevation of privilege**: injected agent calls tools the user did not ask for | INTENT-01..03 |
| **Elevation of privilege**: indirect privilege | EFF-01..03, RISK-04 |

## OWASP Top 10 for LLM Applications (2025)

| ID | Risk | Coverage here |
|---|---|---|
| LLM01 | Prompt Injection | Effect contained: INTENT checks stop injected tool calls; POISON scan for tool-description injection. Detection of injected text itself is in the red-team repo. |
| LLM02 | Sensitive Information Disclosure | CSG-01/02 coding guard; BPOL-03; full DLP in `Jagadish-pii-guard` |
| LLM03 | Supply Chain | MCP registry, pinning and drift; extension scoring |
| LLM04 | Data and Model Poisoning | not covered (no training here) |
| LLM05 | Improper Output Handling | partly: bridge treats unknown tools as destructive |
| LLM06 | Excessive Agency | bridge, autonomy levels, intent scope, risk cards |
| LLM07 | System Prompt Leakage | not covered here (red-team repo) |
| LLM08 | Vector and Embedding Weaknesses | not covered |
| LLM09 | Misinformation | not covered |
| LLM10 | Unbounded Consumption | BUDGET, LOOP, KILL |

## OWASP Top 10 for Agentic Applications (2026)

| ID | Risk | Coverage here |
|---|---|---|
| ASI01 | Agent Goal Hijack | INTENT-01..04 keep actions inside the user's request |
| ASI02 | Tool Misuse and Exploitation | bridge grants, MCP-05 unknown tools, POISON-07 cross-tool steering, SHADOW-MCP |
| ASI03 | Identity and Privilege Abuse | registry, effective privilege, TOK-03/04 scoped tokens, risk cards |
| ASI04 | Agentic Supply Chain Vulnerabilities | MCP allow and deny lists, pinning, discovery |
| ASI05 | Unexpected Code Execution | partly: destructive tools need approval; no code sandbox here |
| ASI06 | Memory and Context Poisoning | partly: poisoned tool descriptions; no memory store here |
| ASI07 | Insecure Inter-Agent Communication | not covered |
| ASI08 | Cascading Failures | kill switch (global), fail-closed defaults |
| ASI09 | Human-Agent Trust Exploitation | approvals by named humans only; risk cards show approval paths |
| ASI10 | Rogue Agents | shadow agents, SHADOW-03 suspended agents still acting, per-agent kill switch |

## Out of scope

Real secret storage, network controls, endpoint control, session recording, model training data.

## Next

[15_IMPLEMENTATION_GUIDE.md](15_IMPLEMENTATION_GUIDE.md)
