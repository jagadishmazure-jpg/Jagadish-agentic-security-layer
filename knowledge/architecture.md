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
    BR --> IMP[impact.py<br/>compromise analysis]

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
| `impact.py` | Compromise exposure ranking + containment actions |
| `bridge.py` | Per-action governance (centerpiece) |
| `zsp.py` | Zero-standing-privilege posture score |
| `views.py` | Read-only views + SELECT-only gateway |
| `authz.py` | SQLite authorizer backstop (strict, view-aware) |
| `audit.py` | Hash-chained decision log |
| `feedback.py` | PII scrubbing before storage |

See also `docs/adr/0001-sqlite-authorizer-backstop.md` for the gateway
backstop decision.
