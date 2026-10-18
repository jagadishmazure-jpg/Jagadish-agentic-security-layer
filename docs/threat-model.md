# Threat model (STRIDE-lite)

| Threat | Mitigation in this repo |
|---|---|
| **Spoofing** — unregistered agent calls privileged tools | Bridge denies with BRIDGE-01; shadow detection flags the caller |
| **Tampering** — audit log edited to hide actions | Hash-chained log; `verify()` recomputes digests |
| **Repudiation** — "the agent didn't do that" | Every bridge decision logged with agent, tool, policy |
| **Information disclosure** — gateway reads raw tables | Strict authorizer denies base-table reads unless via allowed views |
| **Denial of service** — runaway agent floods tools | Autonomy levels + JIT expiry bound what an agent may do |
| **Elevation of privilege** — agent uses a tool outside its grant | BRIDGE-02; escalation paths surface grant creep proactively |

## Out of scope (honest)

- Real vault/secret storage (simulated here).
- Network-level controls, endpoint application control, session recording.
- Prompt-injection resistance of the agents themselves.
- The fake tool backend performs no real privileged operations.
