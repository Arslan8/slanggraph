"""Week-one `ToolNode` performance baseline."""

from unittest.mock import Mock

from langchain_core.messages import AIMessage, ToolMessage
from langchain_core.runnables import RunnableConfig
from langchain_core.tools import tool
from pytest_benchmark.fixture import BenchmarkFixture

from langgraph.prebuilt import ToolNode


@tool
def baseline_noop(value: int) -> int:
    """Return the supplied value unchanged."""
    return value


def _config() -> RunnableConfig:
    """Build the minimal runtime configuration required by `ToolNode`."""
    runtime = Mock()
    runtime.store = None
    runtime.context = None
    runtime.stream_writer = lambda _: None
    return {"configurable": {"__pregel_runtime": runtime}}


def test_tool_node_invoke_baseline(benchmark: BenchmarkFixture) -> None:
    """Measure one complete synchronous no-op tool invocation."""
    node = ToolNode([baseline_noop])
    request = {
        "messages": [
            AIMessage(
                content="",
                tool_calls=[
                    {
                        "name": "baseline_noop",
                        "args": {"value": 1},
                        "id": "benchmark-call",
                    }
                ],
            )
        ]
    }

    result = benchmark(node.invoke, request, config=_config())

    message = result["messages"][0]
    assert isinstance(message, ToolMessage)
    assert message.content == "1"
