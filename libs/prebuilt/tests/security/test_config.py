"""Tests for public security configuration entry points."""

from __future__ import annotations

import pytest
from langchain_core.tools import tool
from langgraph.checkpoint.memory import InMemorySaver
from langgraph.graph import START, MessagesState, StateGraph

from langgraph.prebuilt import ToolNode
from langgraph.prebuilt.security import (
    DacOverrides,
    MemoryAuditSink,
    SecurityConfig,
    SecurityModule,
    ToolDac,
    dac,
)


@tool
@dac(owner="author", grants={"author": "x"})
def configured_tool(value: str) -> str:
    """Return a value."""
    return value


def test_tool_node_constructor_applies_modules_and_operator_override() -> None:
    """The public constructor allocates labels and replaces the author DAC."""

    class LabelModule(SecurityModule):
        name = "label"

        def tool_alloc_security(self, tool, slot) -> None:
            slot["classification"] = "internal"

    override = ToolDac(owner="operator", grants={"operator": "x"})
    audit = MemoryAuditSink()
    node = ToolNode(
        [configured_tool],
        security=SecurityConfig(
            modules=[LabelModule()],
            dac_overrides=DacOverrides({"configured_tool": override}),
            audit_sink=audit,
        ),
    )

    assert node.dacs_by_name["configured_tool"] is override
    security_tool = node._security_tools_by_name["configured_tool"]
    assert security_tool.security["label"]["classification"] == "internal"
    assert audit.records()[0].stage == "compile"


def test_state_graph_compile_configures_reachable_tool_nodes() -> None:
    """StateGraph exposes a dependency-neutral security configuration hook."""
    node = ToolNode([configured_tool])
    builder = StateGraph(MessagesState)
    builder.add_node("tools", node)
    builder.add_edge(START, "tools")

    builder.compile(security=SecurityConfig())

    assert node._security_stack is not None


def test_escalating_module_requires_checkpointer() -> None:
    """Human approval cannot be enabled without durable graph state."""

    class EscalatingModule(SecurityModule):
        name = "approval"
        can_escalate = True

    builder = StateGraph(MessagesState)
    builder.add_node("tools", ToolNode([configured_tool]))
    builder.add_edge(START, "tools")
    security = SecurityConfig(modules=[EscalatingModule()])

    with pytest.raises(ValueError, match="require a checkpointer"):
        builder.compile(security=security)

    builder.compile(checkpointer=InMemorySaver(), security=security)


def test_invalid_security_protocol_is_rejected() -> None:
    """A mistaken compile argument fails clearly instead of being ignored."""
    builder = StateGraph(MessagesState)
    with pytest.raises(TypeError, match="configure_graph"):
        builder.compile(security=object())


def test_unknown_constructor_override_is_rejected() -> None:
    """Operator override typos fail closed."""
    override = ToolDac(owner="operator", grants={"operator": "x"})
    with pytest.raises(ValueError, match="unknown tools"):
        ToolNode(
            [configured_tool],
            security=SecurityConfig(
                dac_overrides=DacOverrides({"misspelled": override})
            ),
        )
