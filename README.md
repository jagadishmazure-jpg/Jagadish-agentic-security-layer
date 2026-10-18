# Agentic Security Layer

**Recruiter summary.** AI agents wield privileges across tools and data with
no governance. This repo is the cross-cutting control plane: it discovers
unregistered ("shadow") agents from activity logs, maps every agent's blast
radius on a privilege graph, and forces all tool calls through a governed
bridge that checks registration, grant, and autonomy policy per action.
Deterministic; the output and test count below are rendered from a real run
and checked in CI.

## What it does

1. **Agent registry** — every AI agent registered with granted tools, data
   scopes, autonomy level (L0-L3), and owner.
2. **Shadow-AI detection** — callers in activity logs but not in the
   registry are scored by privilege exercised and get an onboard-or-block
   recommendation (SHADOW-01/02). Suspended or revoked agents that still
   act are flagged for blocking (SHADOW-03). Findings are persisted and
   readable through `v_shadow_findings`.
3. **Privilege graph** — agents -> tools -> data scopes. `blast_radius`
   returns everything a compromised agent can reach; `escalation_paths`
   finds paths to high-sensitivity nodes.
4. **Effective privilege** — direct-grant review misses indirect paths.
   `effective_privilege` resolves nested group membership (EFF-01),
   wildcard grants (EFF-02), and dormant grants (EFF-03) into the full
   tool/scope set with every path cited. `hidden_escalations` finds
   privileges reachable ONLY indirectly. Demo: `agt-router` looks like a
   read-only L1 agent on direct review but effectively holds
   `rotate_secret` (sensitivity 5) via a dormant break-glass grant.
   Compromise analysis over effective privilege revokes indirect-only
   access first, since it survives naive cleanup.
5. **Compromised-agent impact** — exposure ranked by sensitivity with
   prioritized containment actions (suspend, revoke, rotate, review).
6. **Governed tool bridge (centerpiece)** — agents never call tools
   directly; the bridge verifies registration (BRIDGE-01), grant
   (BRIDGE-02), autonomy level (BRIDGE-03), and human approval for
   destructive actions (BRIDGE-04, fail-closed). The agent cannot assert
   approval itself: a named human issues it through `Bridge.approve`, and
   it is single-use, scoped to one agent and tool, and expires
   (BRIDGE-05). Approvers must be people, not agents (BRIDGE-06). JIT
   elevation unlocks writes for L1 agents, needs a named approver, and
   expires (at most 8h). A tool missing from the catalog is treated as
   destructive. Denials are persisted to `v_bridge_denials`.
6. **Zero-standing-privilege posture** — environment score 0-100 with a
   prioritized improvement list.

## Real run output (rendered from a fresh run in CI)

Demo scenario (`agelayer/demo_helpers.py::run_scenario`, fixed clock):

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

The three `agt-cache` lines are the approval flow: the agent's own claim of
approval is denied, a human-issued approval is accepted once, and replaying
it is denied.

## How this differs from machine-identity-security

The sibling `Jagadish-machine-identity-security` repo governs the
**identities** themselves: lifecycle scoring, vaulting, compromise signals,
revocation. This repo governs what AI agents **do** with identities:
discovery of unregistered agents, blast-radius analysis, per-action
governance through the bridge, and posture measurement. Identities vs
actions — the two halves of non-human identity security.

## How this differs from agent-identity-security and agent-auth-security

Checked against the code of each repo, not only its README:

- **vs `agent-identity-security`**: that repo is a posture *scanner* over
  an exported cloud identity inventory: detection rules (over-privileged
  agents, standing admin roles, unowned identities) plus privilege-path
  and blast-radius analysis to crown-jewel resources. **Overlap, stated
  honestly:** its blast-radius path analysis and this repo's privilege
  graph (`graph.py`, `impact.py`) answer the same question, and its
  standing-privilege rules resemble the ZSP scorer. What its code does not
  have, and this repo does: a runtime bridge that every action passes
  through, human approvals the agent cannot forge, expiring JIT elevation,
  and shadow-agent detection from activity logs. Assessment vs
  enforcement.
- **vs `agent-auth-security`**: that repo implements *authentication
  mechanisms* (JWT, sessions, DPoP, OAuth flows, delegation, refresh-token
  reuse detection) — how agents prove who they are. No code overlap. This
  repo assumes authenticated agents and governs what they're *allowed to
  do*. AuthN vs runtime authZ.

## Guardrails, each proven by a test

| Claim (all tests in `tests/test_agelayer.py` unless noted) | Test |
|---|---|
| Unregistered, suspended and revoked agents are denied at the bridge | `test_bridge_denies_unregistered_agent`, `test_bridge_denies_suspended_agent`, `test_revoked_agent_denied_and_its_activity_flagged` |
| Ungranted tools and L0 execution are denied | `test_bridge_denies_ungranted_tool`, `test_bridge_denies_l0_execution` |
| Destructive actions need L2 plus a human approval (fail-closed) | `test_bridge_destructive_needs_human_approval`, `test_destructive_still_needs_l2_even_with_approval` |
| The agent cannot approve its own action | `test_agent_cannot_approve_its_own_destructive_action` |
| Approvals are single-use, scoped and expire | `test_approval_is_single_use_scoped_and_expires` |
| JIT elevation is scoped and expires | `test_bridge_elevation_wrong_tool_denied`, `test_jit_elevation_expires` |
| Tools missing from the catalog are treated as destructive | `test_tool_missing_from_catalog_is_treated_as_destructive` |
| Shadow agents are detected and get onboard/block | `test_shadow_detects_unknown_caller`, `test_shadow_block_for_destructive` |
| Every bridge decision is hash-chained; tampering is detected | `test_every_bridge_decision_is_hash_chained`, `test_audit_tamper_detected` |
| Denials and shadow callers are readable through the views | `test_denials_and_shadow_callers_reach_the_read_views` |
| Indirect privilege resolves through nested groups, wildcards and dormant grants (EFF-01/02/03) | `tests/test_effective.py` (`test_nested_group_two_levels_resolves`, `test_wildcard_grant_expands_to_all_tools`, `test_dormant_grant_included_in_effective`) |
| Hidden escalations (indirect-only privilege) are found and rule-cited; direct-grant review would miss them | `tests/test_effective.py` (`test_hidden_escalations_finds_indirect_only_privilege`, `test_direct_grant_review_misses_hidden_escalation`) |
| Compromise analysis over effective privilege revokes indirect-only access first | `tests/test_effective.py` (`test_impact_effective_prioritizes_hidden_revocation`) |
| Gateway denies base tables, schema, writes and `load_extension` with the text check off | `tests/test_authorizer_strict.py` |
| PII scrubbed from free-text feedback; ISO dates kept | `test_feedback_scrubs_ssn_and_email`, `test_feedback_keeps_dates` |

Residual: a column-free `count(*)` on a table behind a view can return a
row count (no values); the text check blocks the plain form.

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
python3 -m pytest tests/ -q
python3 scripts/count_tests.py     # prints the real total
```

<!-- run: python scripts/count_tests.py -->
```text
98 tests collected
```
<!-- /run -->

## Standardization review (2026-10-18)

Bugs found in review and fixed, each with a regression test (section
"review fixes" in `tests/test_agelayer.py`):

| ID | Bug | Fix |
|---|---|---|
| BRIDGE-05 | An agent could set `human_approved=True` on its own request and run a destructive tool | The flag is ignored; only a human-issued, single-use, scoped, expiring approval counts |
| BRIDGE-06 | Approvals and elevations had no approver; an agent could approve itself | A named approver who is not a registered agent |
| BRIDGE-JIT-01 | JIT elevation never expired and could be unbounded | Expiry is checked on every call; cap 8h |
| BRIDGE-CAT-01 | A tool missing from the catalog was treated as a plain write | Treated as destructive (fail-closed), here and in graph, impact and shadow scoring |
| AUDIT-BRIDGE-01 | Bridge decisions went to a plain list, not the hash chain | Every decision is chained |
| VIEW-EMPTY-01 | `v_bridge_denials` and `v_shadow_findings` read tables nothing wrote to | Denials and shadow findings are persisted |
| SHADOW-03 | Suspended or revoked agents still acting were not flagged | Flagged for block |
| VIEW-COUNT-01 | `tool_count` counted an empty grant list as 1 | Exact `json_array_length` |
| ZSP-INPUT-01 | Negative or inconsistent inputs produced scores outside 0-100 | Validated; unknown tools count as standing write |
| AUDIT-COPY-01 | The audit kept a live reference to the caller's payload | Stores a copy |

The ZSP demo score moved from 45.5 to 44.0 because the unknown-tool rule
now counts as standing write access. The README also named a cloud
vendor's products in the boundary section; it is now vendor-neutral.

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
| Governed bridge with human-issued approvals and expiring JIT elevation | Built |
| Effective-privilege layer (nested groups, wildcards, dormant grants, hidden escalations) | Built |
| ZSP posture scorer | Built |
| Strict authorizer + bypassed-text-check regressions | Built |
| Streamlit demo | Written, not run here (needs streamlit) |
| Real vault / IdP integration | Planned (out of scope for synthetic demo) |

## Disclaimer

All data is synthetic and fictional. This is an independent demo project,
not affiliated with any company or vendor. Nothing here connects to real identity
providers or production systems.
