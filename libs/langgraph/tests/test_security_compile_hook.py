"""Tests for StateGraph's dependency-neutral security compile hook."""

from __future__ import annotations

from typing_extensions import TypedDict

from langgraph.graph import START, StateGraph


class State(TypedDict):
    value: int


def test_compile_calls_security_configuration_protocol() -> None:
    """Core invokes a supplied security configuration without importing prebuilt."""
    calls: list[tuple[object, object]] = []

    class Security:
        def configure_graph(self, graph: object, *, checkpointer: object) -> None:
            calls.append((graph, checkpointer))

    builder = StateGraph(State)
    builder.add_node("increment", lambda state: {"value": state["value"] + 1})
    builder.add_edge(START, "increment")

    builder.compile(checkpointer=False, security=Security())

    assert calls == [(builder, False)]
