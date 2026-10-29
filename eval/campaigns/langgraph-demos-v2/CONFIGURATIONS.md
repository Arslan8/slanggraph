# Configurations

`Baseline` is the adapted upstream application without Argus. `Argus` uses an
authenticated `alice` principal, closed admission, principal authorization,
sealed mandatory policy, a Linux Landlock/seccomp worker for every tool body,
typed resource mediation, runtime contract validation, and in-memory security
audit.  The model and trusted orchestration nodes are identical between modes.

| Demo | Protected resources | Worker route | Trusted orchestration |
|---|---|---|---|
| D1 SQL agent | read-only SQLite metadata and `SELECT` | fresh Linux worker + SQL broker | query-generation/checking graph nodes |
| D2 Agentic RAG | frozen TF-IDF index | fresh Linux worker + retrieval broker | model, grading, rewrite, answer nodes |
| D3 Plan/execute | frozen query-dependent search corpus | fresh Linux worker + search broker | planner, executor model, replanner |
| D4 Multi-agent | frozen GDP search plus persistent Python session | fresh search worker; persistent Landlock/seccomp Python child behind broker | researcher/chart model and handoff nodes |
| D5 Customer support | principal-bound travel SQLite, policy index, empty frozen web search | fresh Linux workers + three brokers | assistant and deterministic user-info formatting |

D4's Python session is not trusted application code.  The parent-owned adapter
starts a separate process, loads the plotting runtime, applies Landlock and
seccomp, and only then accepts generated code.  Its namespace persists across
authorized calls, while the GDP fixture and host filesystem remain outside its
authority.

D5 preserves the conditional interrupt and approval/denial path.  The travel
adapter maps the authenticated logical principal to the frozen tutorial
passenger and performs ownership and lead-time checks at the database boundary.
