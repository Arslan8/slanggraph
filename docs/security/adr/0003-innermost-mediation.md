# 0003: Mediate at the innermost execution boundary

Status: Accepted

## Context

Tool wrappers may invoke their execution callback repeatedly and with rewritten
arguments. Agents and subgraphs may also contain separate ToolNode instances.

## Decision

Place the decisive check inside `_execute_tool_sync` and
`_execute_tool_async`, immediately before injection and BaseTool invocation.
Assign a new call index to every callback execution. Provide `guarded_tool` for
routes that do not use ToolNode.

## Consequences

Retries and rewrites cannot reuse an earlier decision. Every execution route
must use ToolNode or an explicit guard; outer middleware is not a security
boundary.
