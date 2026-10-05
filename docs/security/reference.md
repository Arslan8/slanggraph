# Security API and behavior reference

The public API lives in `langgraph.prebuilt.security`. No security dependency is
added to LangGraph core; `StateGraph.compile(security=...)` uses a small
configuration protocol implemented by `SecurityConfig`.

## Tool declarations

Use `@effects(...)` to declare side effects, resource-bearing arguments,
sensitivity, and reversibility. Effects are `READ`, `WRITE`, `NETWORK`, `EXEC`,
`DELEGATE`, and `SEND`. A `ResourceArg` may normalize a path, domain, email
domain, SQL statement kind, or shell executable before policy sees it.

Use `@dac(...)` to declare the author's owner, execute grants, required scopes,
and optional grants for normalized argument values. Operator-provided
`DacOverrides` replace author DAC at configuration time and generate a compile
audit record. Undeclared tools are inferred as critical, irreversible execution
and default deny.

## Principals and configuration

`Principal` carries `user_id`, immutable roles and scopes, a session ID, an
optional delegator, and private module blobs. Bind it with `with_principal`; the
reserved value is stored in `RunnableConfig`, never graph state. Pass configured
modules to `with_principal` so their credential-preparation hooks run.

`SecurityConfig` accepts ordered modules, DAC overrides, an audit sink, an
observer, a positive policy timeout, and `require_principal`. It can be supplied
to `ToolNode(..., security=config)` or `StateGraph.compile(security=config)`.
Modules that can escalate require a real checkpointer.

`security=None` is a compatibility promise: no principal is required, no policy
stack is allocated, and existing ToolNode behavior remains in place.

## Decision order

For each physical execution, the framework:

1. reads the principal from config and normalizes declared resources;
2. runs author/operator DAC before policy modules;
3. runs ordered prepare hooks and re-normalizes transformed arguments;
4. reruns DAC on the final arguments;
5. runs the mandatory capability module and ordered permission hooks;
6. invokes the tool only after an `ALLOW`; and
7. invokes post hooks for an attempted execution.

The four verdicts are `ALLOW`, `DENY`, `TRANSFORM`, and `ESCALATE`. Modules are
restrictive: they can narrow or object, but cannot turn an earlier denial into
an allow. Exceptions, malformed results, normalization failures, and timeouts
deny the call. Raw tool arguments are never placed in approval payloads,
telemetry, or LangSmith metadata.

## Policy modules

Subclass `SecurityModule`, give it a unique non-empty `name`, and override only
the hooks it needs:

- `tool_alloc_security` initializes the module's private tool slot.
- `cred_prepare` initializes its private principal slot.
- `cred_transfer` restricts child credentials.
- `tool_call_prepare` may return a non-expansive argument transform.
- `tool_call_permission` may deny or request approval.
- `tool_call_post` observes attempted execution.
- `resume_permission` treats a human response as additional policy input.

`cap` is framework-owned and always first. Policy hooks run under
`policy_timeout_s`; timeout, exception, or malformed output fails closed.

## Approval and resume

An `ESCALATE` decision contains an `EscalationRequest`. ToolNode passes only its
argument-free payload to `interrupt()`. On `Command(resume=...)`, LangGraph
restarts the node, so normalization, DAC, and module permission run again before
`resume_permission`. Approval does not bypass any prior check, and the mandatory
capability module treats rejection as denial.

## Direct tools and delegation

Use `@guarded_tool(security=config)` when a tool can be invoked outside
ToolNode, including direct executors and alternate agent integrations. Its sync
and async entry points use the same normalization, DAC, stack, timeout, audit,
and observability semantics.

Use `delegate(child_graph, scopes=[...], security=config)` to invoke a child
with an explicit scope set. Scope growth is denied. Roles are retained, module
blobs are independently copied, and every module can restrict credential
transfer. The child principal records `delegated_by`.

## Audit and observability

`MemoryAuditSink` and `SqliteAuditSink` append SHA-256 hash-chained records.
SQLite uses WAL and full synchronization. `verify()` returns integrity plus the
first invalid record index. Records contain an argument hash, never raw values.

`MemorySecurityObserver` collects events and counters.
`LoggingSecurityObserver` emits structured redacted records.
`OpenTelemetrySecurityObserver` accepts compatible tracer and counter objects
without adding a hard dependency. `langsmith_metadata(event)` produces safe run
metadata. Each invoked DAC or module hook records stage, module, verdict,
reason, latency, user, tool, and call index where applicable.

## Inventory

`introspect(graph)` returns a `ToolInventory` for statically reachable nested
ToolNodes and registered guarded tools. `complete` is false when middleware or a
dynamic guarded tool can add tools that static analysis cannot enumerate.

`analyze_source(*paths, exclude=...)` traces parameters of registered graph
callbacks through local assignments and helpers. It reports unrestricted node
boundaries, unresolved callbacks, graphs compiled without `security`, retained
tool aliases, direct runnable invocation, dangerous resource APIs, dynamic
dispatch, and tool behavior missing from `@effects` declarations. The command
`langgraph-security-taint src --json` exits nonzero for findings or parse
errors, making it suitable for CI.

Static analysis cannot establish process-wide MAC for dynamic Python. Runtime
reflection, native extensions, dynamically loaded code, callbacks hidden in
containers, background work, and dependencies without source may evade source
resolution. If graph-controlled code is untrusted, enforce filesystem, network,
process, and credential policy outside the Python process as well.
