# Escape analysis

## Result

The current security hooks do not form a process-wide mandatory access-control
boundary. They completely mediate a narrower event: a tool call that crosses a
configured `ToolNode` or `guarded_tool`. Python executed as an ordinary graph
node remains part of the trusted computing base.

The source analyzer makes that distinction enforceable in review. It starts
taint at graph callback parameters, follows local assignment and helper calls,
and reports any known or unresolved path that does not cross a mediated tool
boundary. It also checks whether tool bodies reach effects omitted from their
`@effects` declarations.

## Sources, boundaries, and sinks

The analysis treats graph state, messages, tool arguments, callback parameters,
model output, and values derived from them as tainted. `ToolNode` and
`guarded_tool` are recognized mediation boundaries. A declaration is metadata,
not a sanitizer: the analyzer still compares a tool body with its declared
effects.

Reported sinks include:

- direct `invoke`, `ainvoke`, `run`, or `arun` calls;
- filesystem reads, writes, renames, permissions, and deletion;
- process creation and shell execution;
- sockets, HTTP clients, mail, and other network clients;
- database execution;
- `eval`, `exec`, compilation, and dynamic imports;
- unsafe deserialization and native-code interfaces; and
- a callable selected from tainted state or an unresolved dependency call that
  receives tainted data.

An unresolved callback is itself a finding. The analyzer never converts "could
not inspect" into "safe."

## Confirmed framework escape points

The audit of LangGraph core and prebuilt identifies these architectural escape
surfaces:

1. `RunnableCallable` invokes arbitrary node functions in-process. Those
   functions receive graph-controlled state and can call any Python capability.
2. `StateGraph.add_node`, conditional edges, error handlers, pre-model hooks,
   and post-model hooks all accept arbitrary callables.
3. `create_react_agent` compiles its internal graph without forwarding a
   `SecurityConfig`; model and structured-output runnables are invoked directly.
4. A tool object placed in `ToolNode` can remain reachable through its original
   Python alias and be invoked outside that node.
5. `guarded_tool` protects the wrapper, not other aliases to the original tool.
6. After a tool is allowed, its implementation can perform effects or access
   resources omitted from its descriptor. Hooks do not interpose on syscalls.
7. Dynamic middleware, runtime-created tools, opaque runnables, and dynamically
   selected callbacks cannot always be enumerated before execution.
8. Subgraphs invoked without `delegate` can receive ambient configuration or be
   called directly through another retained reference.
9. Threads, tasks, callbacks, subprocesses, and work scheduled by an allowed
   call can continue after post hooks return.
10. Policy modules, normalizers, observers, audit sinks, model clients, and
    dependency code execute with the host process's authority and are trusted.

These are not all equivalent vulnerabilities. They are the points where the
claim changes from "the hook mediates this tool invocation" to "trusted Python
must behave." Every application must either remove, review, or confine each
reachable point.

## CI usage

Run the analyzer over application source and exclude only generated or vendored
trees:

```bash
langgraph-security-taint src --exclude src/generated
langgraph-security-taint src --json > taint-report.json
```

The command exits nonzero when it finds an escape or cannot parse an input. JSON
findings include a fingerprint based on path, function, kind, and symbol so a
review system can compare results without relying on line numbers.

Do not create a blanket baseline that silently accepts current findings. Record
an owner and rationale for each reviewed fingerprint, and fail CI when a new
fingerprint appears.

## What closes the boundary

Static analysis is a discovery and review control. It cannot make dynamic Python
non-bypassable. A deployment that requires actual MAC must also run untrusted
nodes and tools in a separate security domain with deny-by-default filesystem,
network, process, IPC, and credential access. The host should expose only a
small capability broker; the broker applies the same principal, descriptor,
resource normalization, and policy decision immediately before performing each
operation.

Until that confinement exists, the accurate guarantee is: configured tool
entry points are mediated, while arbitrary Python code is trusted.
