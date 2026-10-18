# Implementation guide

## Running locally

```bash
python3 -m pytest tests/ -q        # 52 regression checks
python3 scripts/count_tests.py     # prints the real total
```

Optional demo UI (needs streamlit, not required):

```bash
pip install streamlit
python3 -m streamlit run demo/app.py
```

## Adopting the pattern

1. **Register every agent** (`registry.register_agent`) with its granted
   tools, data scopes, autonomy level, and owner before it acts.
2. **Route all tool calls through `Bridge.execute`** — never let agents
   call tools directly. Denials carry policy IDs (BRIDGE-01..04).
3. **Feed activity logs to `shadow.detect`** on a schedule; onboard or
   block what it finds (SHADOW-01/02).
4. **Run `blast_radius` + `escalation_paths`** whenever grants change;
   treat new escalation paths as findings.
5. **Track `zsp.score`** over time; the improvements list is the roadmap.

## Autonomy levels

- L0 propose-only (no execution) · L1 read-only · L2 reads+writes ·
  L3 full within grant. Destructive tools always need human approval,
  regardless of level (fail-closed, BRIDGE-04).
