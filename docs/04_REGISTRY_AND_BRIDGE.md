# Registry, privilege graph and governed bridge

*Step 04 of the reading path.*

## What you'll learn

- How agents are registered and what autonomy levels mean
- How shadow agents and hidden privileges are found
- How the governed bridge decides every tool call

## Registry and autonomy

Every agent is registered with granted tools, data scopes, autonomy level (L0-L3), owner and status
(`registry.py`). Unregistered callers are shadow agents.

## Shadow agents, privilege graph and effective privilege

- `shadow.py` reads activity logs and flags callers not in the registry (SHADOW-01), recommends block for
  destructive use (SHADOW-02), and flags suspended or revoked agents still acting (SHADOW-03).
- `graph.py` and `impact.py` build agents → tools → scopes and answer "what is exposed if this agent is
  compromised?".
- `effective.py` resolves nested groups (EFF-01), wildcards (EFF-02) and dormant grants (EFF-03). In the demo
  `agt-router` looks read-only but holds `rotate_secret` through a dormant break-glass grant.

## Governed bridge

Agents never call tools directly. `Bridge.execute` checks registration (BRIDGE-01), grant (BRIDGE-02),
autonomy (BRIDGE-03) and human approval for destructive tools (BRIDGE-04). Approvals are issued by a named
human, are single-use, scoped and expire (BRIDGE-05); approvers cannot be agents (BRIDGE-06). A tool missing
from the catalog is treated as destructive.

Real output (fixed clock, rendered in CI):

<!-- run: python scripts/show_differentiator.py -->
```text
shadow ghost-helper   SHADOW-01 -> onboard (score 1)
shadow rogue-cleaner  SHADOW-01 -> block (score 9)
bridge agt-router    read_tickets    allowed
bridge agt-router    write_invoice   denied  BRIDGE-02
bridge rogue-cleaner purge_cache     denied  BRIDGE-01
bridge agt-jit-demo  write_invoice   denied  BRIDGE-03
bridge agt-jit-demo  write_invoice   allowed
bridge agt-biller    write_invoice   allowed
bridge agt-deployer  deploy_service  allowed
bridge agt-cache     purge_cache     denied  BRIDGE-04
bridge agt-cache     purge_cache     allowed  by r.osei (security on-call)
bridge agt-cache     purge_cache     denied  BRIDGE-05
denials in v_bridge_denials: 5, shadow callers in v_shadow_findings: 2
blast radius of agt-deployer: 6 nodes, 4 escalation paths, 6 exposed on compromise
zsp improvements: [(1, 'standing write access'), (2, 'shadow agents'), (3, 'JIT adoption'), (4, 'credential rotation')]
zsp score: 44.0; audit entries 15, chain valid: True
```
<!-- /run -->

Guardrails v2 (step 06) adds checks *in front of* the bridge; it does not replace any bridge rule.

## Next

[05_SHADOW_AI_AND_BROWSER.md](05_SHADOW_AI_AND_BROWSER.md)
