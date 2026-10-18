# Domain notes: agentic security layer

AI agents wield privileges across tools and data stores. The security
problem is not the model — it is what the agent is *allowed to do*.
Four questions every enterprise should be able to answer:

1. **What agents exist?** Unknown agents ("shadow AI") operate outside
   governance: personal assistants wired to company data, automation
   scripts someone wrapped in a chat interface, evaluation harnesses left
   running. Discovery must come from observed activity, not from a
   registry nobody maintains.
2. **What could each agent reach?** A privilege graph (agents -> tools ->
   data) makes escalation paths visible. The question "if this agent is
   compromised, what is exposed?" should have a deterministic answer, not
   a meeting.
3. **Who checks each action?** Agents should never call privileged tools
   directly. A governed bridge verifies registration, grant, and autonomy
   policy per action — the same pattern as an API gateway, applied to
   agent tool calls.
4. **How close to zero standing privilege?** Standing credentials are the
   attack surface. The posture score measures the gap: no standing write
   access, privileged actions via just-in-time elevation, fresh rotations,
   no shadow agents.

This repo governs what agents *do*. The sibling machine-identity repo
governs the *identities* themselves (lifecycle, vaulting, compromise
signals). Together they cover both halves of non-human identity security.
