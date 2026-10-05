"""Security mediation overhead benchmarks."""

from __future__ import annotations

from unittest.mock import Mock

from langchain_core.messages import AIMessage
from langchain_core.runnables import RunnableConfig
from langchain_core.tools import tool
from pytest_benchmark.fixture import BenchmarkFixture

from langgraph.prebuilt import ToolNode
from langgraph.prebuilt.security import (
    Decision,
    Effect,
    Principal,
    SecurityConfig,
    SecurityModule,
    Verdict,
    dac,
    effects,
    with_principal,
)


@tool
@dac(owner="benchmark", grants={"benchmark": "x"})
@effects(Effect.READ)
def secured_noop(value: int) -> int:
    """Return the supplied value unchanged."""
    return value


class _AllowModule(SecurityModule):
    def __init__(self, index: int) -> None:
        self.name = f"allow_{index}"

    def tool_call_permission(self, principal, call):
        return Decision(Verdict.ALLOW, f"{self.name}:allow")


def _config(modules: tuple[SecurityModule, ...]) -> RunnableConfig:
    runtime = Mock(store=None, context=None, stream_writer=lambda _: None)
    principal = Principal("benchmark", frozenset({"benchmark"}), frozenset(), "session")
    return with_principal(
        {"configurable": {"__pregel_runtime": runtime}},
        principal,
        modules=modules,
    )


def _request() -> dict:
    return {
        "messages": [
            AIMessage(
                content="",
                tool_calls=[
                    {
                        "name": "secured_noop",
                        "args": {"value": 1},
                        "id": "benchmark-call",
                    }
                ],
            )
        ]
    }


def test_security_cap_overhead(benchmark: BenchmarkFixture) -> None:
    """Measure mandatory DAC and capability mediation for one physical call."""
    security = SecurityConfig()
    node = ToolNode([secured_noop], security=security)
    try:
        result = benchmark(node.invoke, _request(), config=_config(()))
        assert result["messages"][0].content == "1"
    finally:
        assert node._security_stack is not None
        node._security_stack.close()


def test_security_five_module_overhead(benchmark: BenchmarkFixture) -> None:
    """Measure the bounded incremental cost of five permission modules."""
    modules = tuple(_AllowModule(index) for index in range(5))
    security = SecurityConfig(modules=modules)
    node = ToolNode([secured_noop], security=security)
    try:
        result = benchmark(node.invoke, _request(), config=_config(modules))
        assert result["messages"][0].content == "1"
    finally:
        assert node._security_stack is not None
        node._security_stack.close()
