# Evaluation

*Step 11 of the reading path.*

## What you'll learn

- The two labelled sets in this repo and their measured scores
- Which cases are known misses, kept on purpose

Both sets are small and self-written. They are regression checks, not quality claims.

| Set | File | Cases |
|---|---|---|
| Intent scope | `data/intent_eval.json` | 30 (request, tool call, in or out of intent) |
| MCP tool poisoning | `data/mcp_tool_descriptions.json` | 24 (12 clean, 12 poisoned) |

Measured (rendered from a fresh run; last two lines of the MCP script):

<!-- run: python scripts/show_mcp.py | tail -n 2 -->
```text
poison eval: 24 cases, precision 1.0, recall 0.833, misses [{'id': 'p11', 'kind': 'missed'}, {'id': 'p12', 'kind': 'missed'}]
intent eval: 30 cases, precision 0.941, recall 0.941, misses [('false_flag', 'Wipe the cache on the pricing page'), ('missed', 'Show the order ORD-5 and its customer')]
```
<!-- /run -->

Known misses (each kept as a test):

- Intent: the synonym "wipe" is not in the verb list, so "Wipe the cache" is flagged (false flag); a
  `customer_id` argument is not a tracked resource, so a different customer is not caught (miss).
- Poisoning: a paraphrased instruction without trigger words (`p11`) and a Spanish instruction (`p12`).

## Next

[12_GUARDRAILS.md](12_GUARDRAILS.md)
