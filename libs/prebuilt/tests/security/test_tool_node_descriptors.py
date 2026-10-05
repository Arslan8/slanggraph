"""Tests for descriptor and DAC attachment at `ToolNode` construction."""

from unittest.mock import Mock

from langchain_core.messages import AIMessage
from langchain_core.tools import tool

from langgraph.prebuilt import ToolNode
from langgraph.prebuilt.security import Effect, ToolDac, dac, effects


@tool
@dac(owner="reader", grants={"reader": "x", "*": "-"})
@effects(Effect.READ)
def declared_tool(value: str) -> str:
    """Return a declared value."""
    return value


@tool
def undeclared_tool(value: str) -> str:
    """Return an undeclared value."""
    return value


def test_tool_node_materializes_declared_and_inferred_metadata() -> None:
    """Every registered tool has a descriptor and DAC at construction time."""
    node = ToolNode([declared_tool, undeclared_tool])

    assert node.descriptors_by_name["declared_tool"].effects == {Effect.READ}
    assert node.dacs_by_name["declared_tool"] == ToolDac(
        owner="reader", grants={"reader": "x", "*": "-"}
    )
    assert node.descriptors_by_name["undeclared_tool"].extra["inferred"] is True
    assert node.dacs_by_name["undeclared_tool"].grants == {"*": "-"}


def test_metadata_attachment_does_not_change_execution() -> None:
    """Attaching metadata alone preserves the upstream invocation path."""
    node = ToolNode([undeclared_tool])
    runtime = Mock(store=None, context=None, stream_writer=lambda _: None)
    request = {
        "messages": [
            AIMessage(
                content="",
                tool_calls=[
                    {
                        "name": "undeclared_tool",
                        "args": {"value": "unchanged"},
                        "id": "call-1",
                    }
                ],
            )
        ]
    }

    result = node.invoke(
        request, config={"configurable": {"__pregel_runtime": runtime}}
    )

    assert result["messages"][0].content == "unchanged"
