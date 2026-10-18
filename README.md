# Agentic Security Layer

**Recruiter summary.** AI agents wield privileges across tools and data with
no governance. This repo is the cross-cutting control plane: it discovers
unregistered ("shadow") agents from activity logs, maps every agent's blast
radius on a privilege graph, and forces all tool calls through a governed
bridge that checks registration, grant, and autonomy policy per action.
**52 tests, all green, deterministic — every number below from a real run.**

## What it does

1. **Agent registry** — every AI agent registered with granted tools, data
   scopes, autonomy level (L0-L3), and owner.
2. **Shadow-AI detection** — callers in activity logs but not in the
   registry are scored by privilege exercised and get an onboard-or-block
   recommendation (SHADOW-01/02).
3. **Privilege graph** — agents -> tools -> data scopes. `blast_radius`
   returns everything a compromised agent can reach; `escalation_paths`
   finds paths to high-sensitivity nodes.
4. **Compromised-agent impact** — exposure ranked by sensitivity with
   prioritized containment actions (suspend, revoke, rotate, review).
5. **Governed tool bridge (centerpiece)** — agents never call tools
   directly; the bridge verifies registration (BRIDGE-01), grant
   (BRIDGE-02), autonomy level (BRIDGE-03), and human approval for
   destructive actions (BRIDGE-04, fail-closed). JIT elevation unlocks
   writes for L1 agents with expiry.
6. **Zero-standing-privilege posture** — environment score 0-100 with a
   prioritized improvement list.

## Real run output

Demo scenario (`agelayer/demo_helpers.py::run_scenario`, deterministic):

```
shadow: [('ghost-helper', 'onboard', 1), ('rogue-cleaner', 'block', 9)]
blast nodes: 6   esc paths: 4   exposed on compromise: 6
zsp: 45.5
improvements: [(1, 'standing write access'), (2, 'shadow agents'),
               (3, 'JIT adoption'), (4, 'credential rotation')]
bridge: [('agt-router', 'read_tickets', 'allowed', None),
         ('agt-router', 'write_invoice', 'denied', 'BRIDGE-02'),
         ('rogue-cleaner', 'purge_cache', 'denied', 'BRIDGE-01'),
         ('agt-jit-demo', 'write_invoice', 'denied', 'BRIDGE-03'),
         ('agt-jit-demo', 'write_invoice', 'allowed', None),   # via JIT
         ('agt-biller', 'write_invoice', 'allowed', None)]
audit: 9 entries, chain valid: True
```

## How this differs from machine-identity-security

The sibling `Jagadish-machine-identity-security` repo governs the
**identities** themselves: lifecycle scoring, vaulting, compromise signals,
revocation. This repo governs what AI agents **do** with identities:
discovery of unregistered agents, blast-radius analysis, per-action
governance through the bridge, and posture measurement. Identities vs
actions — the two halves of non-human identity security.

## How this differs from agent-identity-security and agent-auth-security

- **vs `agent-identity-security`**: that repo is a posture *scanner* for the
  Microsoft identity stack (Entra ID, PIM, Azure RBAC, Foundry agents) with
  graph-based privilege-path analysis across people, workloads, and AI
  agents. This repo is *runtime governance* for AI agents: a registry they
  must be in, a bridge every privileged action passes through, shadow-agent
  detection from activity logs, and blast-radius analysis scoped to agent
  tool/data grants. Assessment vs enforcement; Azure-native vs
  stack-agnostic.
- **vs `agent-auth-security`**: that repo implements *authentication
  mechanisms* (JWT, sessions, DPoP, OAuth 2.1, delegation) — how agents prove
  who they are. This repo assumes authenticated agents and governs what
  they're *allowed to do*: per-action authorization at the bridge,
  autonomy-level policies, JIT elevation, and compromise impact analysis.
  AuthN vs runtime authZ.

## Guardrails

- Destructive actions always require human approval (fail-closed).
- Suspended/revoked agents are denied at the bridge (BRIDGE-01).
- Read gateway: SELECT-only, two independent layers (text check + strict
  SQLite authorizer); regression tests prove the authorizer holds with
  the text check bypassed.
- PII scrubbed from free-text feedback before storage; ISO dates kept.
- Every bridge decision, shadow finding, and impact analysis is
  hash-chained in the audit log.

## Limitations

- The tool backend, vault, and JIT store are **simulations** — no real
  privileged operations are performed.
- Shadow detection needs activity logs; it cannot see agents that never
  act.
- The privilege graph is only as complete as the registered grants.
- Out of scope: real secret storage, session recording, endpoint
  controls, prompt-injection resistance of the agents themselves.

## How to run

```bash
python3 -m pytest tests/ -q        # 52 regression checks
python3 scripts/count_tests.py     # prints the real total
```

## Docs

- [knowledge/domain-notes.md](knowledge/domain-notes.md) · [knowledge/architecture.md](knowledge/architecture.md)
- [docs/implementation-guide.md](docs/implementation-guide.md) ·
  [docs/interview-points.md](docs/interview-points.md) ·
  [docs/threat-model.md](docs/threat-model.md) ·
  [docs/adr/0001-sqlite-authorizer-backstop.md](docs/adr/0001-sqlite-authorizer-backstop.md)

## Built / Written-not-run / Planned

| Item | Status |
|---|---|
| Registry, shadow detection, privilege graph, impact analysis | Built |
| Governed bridge with JIT elevation | Built |
| ZSP posture scorer | Built |
| Strict authorizer + bypassed-text-check regressions | Built |
| Streamlit demo | Written, not run here (needs streamlit) |
| Real vault / IdP integration | Planned (out of scope for synthetic demo) |

## Disclaimer

All data is synthetic and fictional. This is an independent demo project,
not affiliated with any vendor. Nothing here connects to real identity
providers or production systems.
