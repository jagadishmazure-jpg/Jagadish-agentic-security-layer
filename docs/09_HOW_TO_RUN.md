# How to run

*Step 09 of the reading path.*

## What you'll learn

- How to install, test and run every script

Python 3.10 or newer, standard library only. Tests need `pytest`.

```bash
python -m venv .venv && . .venv/bin/activate
pip install pytest==9.1.1 ruff==0.17.1
python -m pytest -q
ruff check .
python scripts/show_differentiator.py     # registry, shadow agents, bridge (step 04)
python scripts/show_shadow_ai.py          # inventory, browser policy, extensions, coding guard (step 05)
python scripts/show_guardrails_v2.py      # intent, budgets, kill switch, risk cards (step 06)
python scripts/show_mcp.py                # MCP gateway, drift, poisoning, tokens, evals (step 07)
python scripts/leadership_report.py       # reports/leadership_{daily,weekly}.{md,csv,html} (step 08)
python scripts/render_docs.py --check     # documented output still matches a fresh run
python scripts/check_brands.py            # no real brand names in tracked files
```

<!-- run: python scripts/count_tests.py -->
```text
326 tests collected
```
<!-- /run -->

## Next

[USE_CASES.md](USE_CASES.md)
