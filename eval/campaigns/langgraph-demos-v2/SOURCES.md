# Sources and adaptations

The source snapshot, source-cell map, task freeze, fixtures, hashes, and model
settings are inherited unchanged from `../langgraph-demos-v1/`.  In particular,
the upstream LangGraph revision remains
`23961cff61a42b52525f3b20b4094d8d2fba1744`.

New application adaptations are limited to replacing resource-owning tool
bodies with schema-compatible worker entry points and flattening the D3/D4
prebuilt ReAct helper into the equivalent explicit model/tool loop so closed
admission can inventory it.  The same flattened graph is used in Baseline and
Argus.  Prompts, graph roles, task inputs, recursion limits, interrupt behavior,
and validators remain frozen.

Resource monitor implementations live in
`eval/apps/demos/resource_monitors/`.  Core runtime code changed only for the D5
checkpoint continuation defect described in `RESULTS.md`.
