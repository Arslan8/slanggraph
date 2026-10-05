# Security migration guide

Security is opt-in and can be introduced incrementally. An application that
does not pass `security` keeps its prior ToolNode behavior.

## 1. Inventory execution paths

Run `introspect(compiled_graph)` and review every entry. Locate direct
`BaseTool.invoke` calls, agent middleware that can retry or rewrite requests,
and child graphs. A partial inventory is a release blocker until dynamic tool
sources are understood.

Run `langgraph-security-taint src` over application source as well. Every
`unmediated_node`, `unknown_callback`, `unknown_call`, `dynamic_dispatch`,
`unprotected_compile`, `retained_capability`, and `undeclared_effect` finding
requires removal, confinement, or an explicit security review. The analyzer
treats unknown dynamic behavior as an escape; it is a review gate, not proof
that Python is sandboxed.

## 2. Declare tools

Add `@effects` and `@dac` to every tool. Treat inferred descriptors as migration
warnings: inference deliberately yields critical, irreversible, default-deny
behavior. Normalize every argument that names a protected resource.

## 3. Bind authenticated principals

Create a `Principal` at the trusted request boundary and use `with_principal` on
the invocation config. Do not derive identity or scopes from prompts, messages,
tool arguments, or graph state.

## 4. Enable enforcement

Start with `SecurityConfig(audit_sink=MemoryAuditSink())`, then pass it to
ToolNode or `StateGraph.compile`. Add policy modules in operator-selected order.
Use `DacOverrides` for deployment policy rather than modifying model-visible
data.

## 5. Cover alternate paths

Wrap directly callable tools with `guarded_tool`. Wrap child graphs with
`delegate` and the smallest required scope set. Retain the regression test where
a wrapper executes twice and rewrites the second request: each physical call
must be mediated independently.

## 6. Add durable approval only with checkpoints

Set `can_escalate = True` only on modules that can return `ESCALATE`, and compile
with a checkpointer. Approval payloads must remain argument-free. Treat approval
as restrictive input; it never overrides DAC, capabilities, or another module.

## 7. Operate and roll out

Persist audit records, verify their chain, export redacted counters/spans, and
alert on normalization errors, module failures, and policy timeouts. Test sync,
async, retries, subgraphs, concurrency, and resume behavior before enforcing in
production.
