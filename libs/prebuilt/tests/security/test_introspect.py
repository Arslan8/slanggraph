"""Tests for compiled-graph security inventory."""

from __future__ import annotations

from typing import Any

from langchain_core.runnables import RunnableConfig
from langchain_core.tools import tool
from langgraph.graph import END, START, MessagesState, StateGraph

from langgraph.prebuilt import ToolNode
from langgraph.prebuilt.security import Effect, effects, introspect
from langgraph.prebuilt.security.introspect import (
    ToolInventoryEntry,
    _register_guarded_tool,
    _unregister_guarded_tool,
)


@tool
@effects(Effect.READ)
def root_tool(value: str) -> str:
    """Return a root value."""
    return value


@tool
@effects(Effect.WRITE)
def child_tool(value: str) -> str:
    """Return a child value."""
    return value


@tool
@effects(Effect.SEND)
def leaf_tool(value: str) -> str:
    """Return a leaf value."""
    return value


def _graph_with_node(name: str, node: Any) -> Any:
    builder = StateGraph(MessagesState)
    builder.add_node(name, node)
    builder.add_edge(START, name)
    builder.add_edge(name, END)
    return builder.compile()


def test_introspect_recurses_through_three_graph_levels() -> None:
    """Direct ToolNodes in nested compiled subgraphs are all inventoried."""
    leaf = _graph_with_node("leaf_tools", ToolNode([leaf_tool]))
    child_builder = StateGraph(MessagesState)
    child_builder.add_node("child_tools", ToolNode([child_tool]))
    child_builder.add_node("leaf_graph", leaf)
    child_builder.add_edge(START, "child_tools")
    child_builder.add_edge("child_tools", "leaf_graph")
    child_builder.add_edge("leaf_graph", END)
    child = child_builder.compile()
    root_builder = StateGraph(MessagesState)
    root_builder.add_node("root_tools", ToolNode([root_tool]))
    root_builder.add_node("child_graph", child)
    root_builder.add_edge(START, "root_tools")
    root_builder.add_edge("root_tools", "child_graph")
    root_builder.add_edge("child_graph", END)

    inventory = introspect(root_builder.compile())

    assert {entry.name for entry in inventory.tools} == {
        "root_tool",
        "child_tool",
        "leaf_tool",
    }
    assert inventory.complete is True
    assert next(entry for entry in inventory.tools if entry.name == "leaf_tool").path


def test_introspect_finds_tool_node_captured_by_runnable_callable() -> None:
    """A wrapper closure cannot hide a statically captured ToolNode."""
    captured = ToolNode([root_tool])

    def wrapped(state: MessagesState, config: RunnableConfig) -> Any:
        return captured.invoke(state, config)

    inventory = introspect(_graph_with_node("wrapped", wrapped))

    assert [entry.name for entry in inventory.tools] == ["root_tool"]


def test_introspect_marks_middleware_tool_source_incomplete() -> None:
    """Middleware that can introduce unregistered tools is not statically complete."""

    def passthrough(request: Any, execute: Any) -> Any:
        return execute(request)

    graph = _graph_with_node(
        "dynamic_tools", ToolNode([root_tool], wrap_tool_call=passthrough)
    )

    assert introspect(graph).complete is False


def test_introspect_includes_guarded_tool_registry() -> None:
    """Tools mediated outside ToolNode share the same static inventory."""
    node = ToolNode([root_tool])
    entry = ToolInventoryEntry(
        name="guarded_read",
        descriptor=node.descriptors_by_name["root_tool"],
        dac=node.dacs_by_name["root_tool"],
        path=("guarded",),
        source="guarded_tool",
    )
    _register_guarded_tool(entry)
    try:
        inventory = introspect(_graph_with_node("tools", ToolNode([child_tool])))
    finally:
        _unregister_guarded_tool("guarded_read")

    guarded = next(item for item in inventory.tools if item.name == "guarded_read")
    assert guarded.source == "guarded_tool"
