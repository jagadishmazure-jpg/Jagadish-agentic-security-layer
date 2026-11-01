# Limitations

*Step 13 of the reading path.*

## What you'll learn

What this repo does not do, stated before anyone asks.

- **Synthetic only.** Every log, app, extension, approval and price is synthetic. No real proxy, browser,
  IDE or MCP server is contacted.
- **Intent parser is keywords.** Synonyms and paraphrase are missed (see step 11). In production it would be
  a classifier with this parser kept as a fail-closed floor.
- **Poisoning scan is patterns.** Paraphrased and non-English instructions are missed (`p11`, `p12`).
- **Tokens are a teaching model** of short-lived audience-bound tokens, not an OAuth server.
- **Budgets count what they are told.** Token counts come from the caller; a lying caller is out of scope.
- **Browser policy sees metadata,** plus a sensitive flag from a DLP step. It does not inspect content
  itself (that is `Jagadish-pii-guard`).
- **Extension scoring** uses manifest permissions; it does not analyse extension code.
- **Leadership KPIs** owned by other repos are labelled samples here. Device posture and session KPIs are
  not covered.
- Carried over: the tool backend, vault and JIT store are simulations; shadow detection needs activity logs;
  a column-free `count(*)` behind a view can return a row count.

## Next

[14_THREAT_MODEL.md](14_THREAT_MODEL.md)
