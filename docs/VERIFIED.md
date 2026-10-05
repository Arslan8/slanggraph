# Verified upstream integration points

Verified on October 5, 2026. All line numbers refer to the pinned commits, not
moving branches.

| Repository | Version | Commit |
| --- | --- | --- |
| `langchain-ai/langgraph` | `1.2.12` (`langgraph-prebuilt` `1.1.0`) | `49cce0ca852be4cfb567a1cbe0e511ff325a1682` |
| `langchain-ai/langchain` | `langchain==1.4.3` | `be854a130153e51346d83d3b06f959b80f6cbca6` |

## `create_agent` uses the public `ToolNode`

Confirmed. LangChain imports `ToolNode` directly from
`langgraph.prebuilt.tool_node` at
`langchain:libs/langchain_v1/langchain/agents/factory.py:35`. It constructs that
class with the agent's available tools and composed sync/async wrappers at
`factory.py:1129-1148`. There is no private `ToolNode` copy on this path.

The middleware type layer likewise imports `ToolCallRequest` and
`ToolCallWrapper` from `langgraph.prebuilt.tool_node` at
`langchain:libs/langchain_v1/langchain/agents/middleware/types.py:29`.

## Execution-method signatures

At the pinned LangGraph tag, the signatures in
`libs/prebuilt/langgraph/prebuilt/tool_node.py` are:

```python
def _run_one(
    self,
    call: ToolCall,
    input_type: Literal["list", "dict", "tool_calls"],
    tool_runtime: ToolRuntime,
) -> ToolMessage | Command | list[Command | ToolMessage]:
```

This is at `tool_node.py:1014-1019`.

```python
def _execute_tool_sync(
    self,
    request: ToolCallRequest,
    input_type: Literal["list", "dict", "tool_calls"],
    config: RunnableConfig,
) -> ToolMessage | Command | list[Command | ToolMessage]:
```

This is at `tool_node.py:922-927`.

```python
async def _execute_tool_async(
    self,
    request: ToolCallRequest,
    input_type: Literal["list", "dict", "tool_calls"],
    config: RunnableConfig,
) -> ToolMessage | Command | list[Command | ToolMessage]:
```

This is at `tool_node.py:1069-1074`.

`ToolCallRequest` is declared at `tool_node.py:132-149`. Its current positional
field order is `tool_call`, `tool`, `state`, `runtime`; compatibility work must
only append defaulted fields. Its `.override()` method uses `dataclasses.replace`
at `tool_node.py:170-199`.

## Resume behavior of `interrupt()`

`Command.resume` accepts either an interrupt-ID mapping or a single resume value
at `libs/langgraph/langgraph/types.py:826-852`. On the first `interrupt()` call,
the function raises `GraphInterrupt`; after a client supplies
`Command(resume=...)`, LangGraph starts the node again from the beginning. The
contract and checkpointer requirement are explicit at `types.py:887-909`.

The implementation assigns each interrupt invocation an ordinal from the
task-local scratchpad. It returns an already-persisted value at the matching
ordinal, consumes and persists a new resume value when present, or raises
`GraphInterrupt` otherwise (`types.py:1002-1029`). The Pregel loop rejects
`Command(resume=...)` without a checkpointer and requires interrupt IDs when
multiple interrupts are pending
(`libs/langgraph/langgraph/pregel/_loop.py:902-931`). Scratchpad construction
restores task-specific ordered resume values and uses an atomic interrupt counter
(`libs/langgraph/langgraph/pregel/_algo.py:1280-1345`).

Security consequence: resume re-executes pre-interrupt node logic. An approval
cannot be treated as continuation past the check; the resume path must record the
approval and rerun `resume_permission`, DAC, and MAC before execution.

## What a tool-call wrapper can do with `execute`

Both sync and async wrappers may call `execute` multiple times and may pass a
modified request each time. LangGraph documents this on `ToolCallWrapper` at
`libs/prebuilt/langgraph/prebuilt/tool_node.py:202-217`, and LangChain documents
the same behavior on `AgentMiddleware.wrap_tool_call` at
`langchain:libs/langchain_v1/langchain/agents/middleware/types.py:674-698`.

The implementation confirms the contract. `_run_one` creates a callback that
enters `_execute_tool_sync` for every invocation (`tool_node.py:1044-1055`), and
the async path creates callbacks that enter `_execute_tool_async` or the sync
fallback for every invocation (`tool_node.py:1191-1210`). Therefore, mediation
outside these execute methods would be bypassable by a wrapper retry with
rewritten arguments.

Upstream's test named `test_retry_middleware_with_exception` currently returns
after its first successful `ToolMessage` and asserts one attempt
(`libs/prebuilt/tests/test_on_tool_call.py:791-840`). It validates the callback
shape but not two physical executions. slangGraph must retain its own regression
test in which the wrapper calls `execute` twice and rewrites the second request.
