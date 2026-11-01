# Shadow AI, browser policy, extensions and coding-agent guard

*Step 05 of the reading path.*

## What you'll learn

- How the AI and SaaS inventory is built from synthetic logs
- How each browser event gets allow, warn, redact or block
- How extensions are scored and how coding-assistant sessions are checked

## 1. Shadow AI and SaaS inventory (`shadow_ai.py`)

Input: synthetic proxy, CASB, extension, IDE, MCP and browser records (60 users, 7 days, fixed seed).
Each record names a user, business unit, host, path, upload bytes, source and account type (SSO or
personal). The catalog has 13 fictional apps on `.example` hosts: chat apps, coding assistants, a finance
copilot, MCP tools, a desktop agent and two plain SaaS apps.

| Rule | Fires when |
|---|---|
| SAI-01 | an unsanctioned app is used |
| SAI-02 | traffic to an unknown host looks like an AI API (chat-completion style paths); fail-closed to `restrict` |
| SAI-03 | a sanctioned app is used with a personal login (enforce SSO) |
| SAI-04 | more than 5 MB uploaded to a non-sanctioned app |

Risk score 0-100 uses app type, training on customer data, retention, SSO, upload volume and sanction.
Recommendations are `keep`, `review-to-sanction`, `restrict`, `block`. Nothing is applied automatically; a
person works the decision queue.

## 2. Browser AI usage policy (`browser_policy.py`)

Decision per event: state default (BPOL-01), group override (BPOL-02: finance and HR block unsanctioned,
personal and unclassified), sensitive-content step (BPOL-03: redact on approved or monitored, block
elsewhere), personal-account marker (BPOL-04). Stricter always wins. Changing an app's state is a proposal
that a named human other than the proposer approves (BPOL-05). The engine reads metadata only (host, group,
login domain, a sensitive flag from the DLP step); it never stores page content.

## 3. Extension risk (`extensions.py`)

Permissions are weighted (all-sites access, clipboard read, cookies, native messaging and request
interception are high-risk, EXT-01). Sideloaded or stale extensions (EXT-02) and AI extensions that send page
content to a remote service (EXT-03) add risk. Any high-risk permission gets at least `allow-with-review`. A
block needs a named owner sign-off (EXT-04).

## 4. Coding-agent session prompt guard (`coding_sessions.py`)

Checks what a coding assistant would send to its model: secrets in prompts or context (CSG-01), secret files
such as `.env` or key files (CSG-02), restricted source paths sent to an assistant not approved for them
(CSG-03), unregistered agent ids (CSG-04) and unsanctioned assistants (CSG-05). Findings carry type and turn
number only. Test secrets are built at runtime so no secret-shaped literal is stored.

## Real output (synthetic data, rendered in CI)

<!-- run: python scripts/show_shadow_ai.py -->
```text
app                                      state         users risk  recommendation
app-deskgenie                            unsanctioned     11   75  block
app-draftbird                            unsanctioned     12   75  block
app-parrotly                             unsanctioned     17   75  block
app-scrape-mcp                           unsanctioned      5   65  block
saas-boxdrop                             unsanctioned     11   50  restrict
unclassified:summarize-anything.example  unclassified      8   50  restrict
app-gitmuse                              unsanctioned      7   45  restrict
app-mcp-desktop                          unsanctioned      3   35  restrict
app-notetaker                            monitored        23   25  keep
saas-tasklane                            approved         39   25  keep
app-files-mcp                            approved         31   15  keep
app-quillwise                            approved         59   15  keep
app-stackwise                            approved         28   10  keep
app-ledgerlens                           approved         42    5  keep
coverage 91.7% (11/12), shadow users 25/60, personal-account users 9
findings: 14 (SAI-01, SAI-02, SAI-03, SAI-04)
browser policy: allow 133, warn 149, redact 17, block 101 of 400 events
by state: approved 147, monitored 26, personal 6, unclassified 26, unsanctioned 195
ext ext-coupon        score  70 block             EXT-01
ext ext-draftbird     score  66 block             EXT-01,EXT-03
ext ext-devtool       score  60 block             EXT-01,EXT-02
ext ext-summarize     score  32 allow-with-review EXT-03
ext ext-pdfquick      score  27 allow             EXT-02
ext ext-nativebridge  score  21 allow-with-review EXT-01
ext ext-pwmgr         score   6 allow             -
ext ext-tabsort       score   6 allow             -
ext ext-sso-helper    score   3 force-install     -
coding cs-001 blocked turns [] -> clean
coding cs-002 blocked turns [0, 1] -> CSG-01, CSG-02
coding cs-003 blocked turns [0, 1] -> CSG-01, CSG-03, CSG-04, CSG-05
```
<!-- /run -->

## Next

[06_RUNTIME_GUARDRAILS_V2.md](06_RUNTIME_GUARDRAILS_V2.md)
