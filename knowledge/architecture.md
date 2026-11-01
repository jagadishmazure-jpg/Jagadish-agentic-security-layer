# Architecture

```mermaid
flowchart TB
    subgraph REG["Agent registry"]
        R[(agents table)]
    end
    subgraph OBS["Observed activity"]
        A[(activity logs)]
    end
    A --> SH[shadow.py<br/>unregistered caller detection]
    R --> SH
    SH --> REC[onboard / block<br/>SHADOW-01/02]

    R --> G[graph.py<br/>agents -> tools -> scopes]
    G --> BR[blast_radius<br/>transitive closure]
    G --> EP[escalation_paths<br/>to sensitive nodes]
    R --> EFF[effective.py<br/>direct + indirect privilege]
    EFF --> HE[hidden_escalations<br/>EFF-01/02/03]
    EFF --> IMP[impact.py<br/>compromise analysis]
    BR --> IMP

    R --> BDG[bridge.py<br/>governed tool bridge]
    BDG --> POL{registration?<br/>grant? autonomy?}
    POL -->|allow| FAKE[fake tool backend]
    POL -->|deny| DENY[BRIDGE-01..04]
    BDG --> AUD[audit.py<br/>hash-chained log]

    R --> ZSP[zsp.py<br/>posture 0-100]

    subgraph GW["Read gateway"]
        V[(v_agent_posture<br/>v_shadow_findings<br/>v_bridge_denials)]
        V --> TX[text check]
        TX --> AZ[strict authorizer<br/>source-arg rule]
    end
    R --> V
```

## Module responsibilities

| Module | Owns |
|---|---|
| `registry.py` | Agent inventory, autonomy levels L0-L3, status |
| `shadow.py` | Unregistered-caller detection + onboard/block scoring |
| `graph.py` | Privilege graph, blast radius, escalation paths |
| `effective.py` | Effective privilege: nested groups (EFF-01), wildcards (EFF-02), dormant grants (EFF-03); `hidden_escalations` finds indirect-only privilege |
| `impact.py` | Compromise exposure ranking + containment actions |
| `bridge.py` | Per-action governance (centerpiece) |
| `zsp.py` | Zero-standing-privilege posture score |
| `views.py` | Read-only views + SELECT-only gateway |
| `authz.py` | SQLite authorizer backstop (strict, view-aware) |
| `audit.py` | Hash-chained decision log |
| `feedback.py` | PII scrubbing before storage |
| `shadow_ai.py`, `browser_policy.py`, `extensions.py`, `coding_sessions.py` | workforce AI discovery and browser-level controls (docs step 05) |
| `intent.py`, `budget.py`, `guarded.py`, `risk_card.py` | runtime guardrails v2 (docs step 06) |
| `mcp/` | MCP registry, pinning, poisoning, shadowing, tokens, discovery, gateway (docs step 07) |
| `leadership.py`, `scenarios.py` | KPI catalog and report writers (docs step 08) |

The full reading path, with the v2 architecture diagram, is in `docs/00_START_HERE.md` and
`docs/03_ARCHITECTURE.md`.

See also `docs/adr/0001-sqlite-authorizer-backstop.md` for the gateway
backstop decision.
