# LangGraph tool security

LangGraph's optional tool-security layer adds complete mediation, author DAC,
operator policy modules, durable approvals, tamper-evident auditing, and
redacted observability to `ToolNode`. It is opt-in: omitting `security` preserves
the existing execution path.

Start with the [10-line HOWTO](HOWTO.md), then use the
[API and behavior reference](reference.md). Existing applications should follow
the [migration guide](migration.md). The design rationale is recorded in the
[`adr/`](adr/) directory.

## Security boundary

The decisive check runs inside each physical sync or async tool execution,
after wrapper dispatch and immediately before argument injection and
`BaseTool` invocation. A wrapper retry or argument rewrite therefore receives a
new call index and a new decision. Direct tools can use `guarded_tool`, while
child graphs can use `delegate` to receive an explicitly reduced principal.

Security configuration is code, not model-controlled state. Bind principals in
`RunnableConfig`; never place credentials, approvals, policy blobs, or audit
records in graph state or messages.
