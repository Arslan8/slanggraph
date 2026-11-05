"""Run ordinary frozen LangGraph tool-calling examples under Baseline or Argus."""

from __future__ import annotations

import argparse
import dataclasses
import enum
import json
import time
import uuid
from pathlib import Path

from langchain_core.messages import AIMessage
from langchain_core.tools import tool
from langchain_openai import ChatOpenAI
from langgraph.graph import END, START, MessagesState, StateGraph
from langgraph.prebuilt import ToolNode
from langgraph.prebuilt.security import (
    MemoryAuditSink,
    Principal,
    cedar_security_many,
    install_mac_policy,
    with_principal,
)
from timing import ModelTiming

MODEL_DIGEST = "500a1f067a9f782620b40bee6f7b0c89e17ae61f686b92c24933e4ca4b2b8b41"
PRINCIPAL_POLICY = 'permit(principal == slangGraph::User::"alice", action, resource);'
OPERATOR_POLICY = 'forbid(principal == slangGraph::User::"blocked", action, resource);'


@tool
def multiply(a: int, b: int) -> int:
    """Multiply two numbers."""
    return a * b


@tool
def add(a: int, b: int) -> int:
    """Add two numbers."""
    return a + b


@tool("add", return_direct=True)
def add_direct(a: int, b: int) -> int:
    """Add two numbers."""
    return a + b


@tool
def get_weather(location: str) -> str:
    """Call to get the current weather."""
    if location == "San Francisco":
        return "It's 60 degrees and foggy."
    return "It's 90 degrees and sunny."


@tool
def get_coolest_cities() -> str:
    """Get a list of coolest cities."""
    return "nyc, sf"


@tool(return_direct=True)
def greet(user_name: str) -> str:
    """Greet user."""
    return f"Hello {user_name}!"


TOOLS = {item.name: item for item in (multiply, add, get_weather, get_coolest_cities, greet)}


def serial(value):
    if dataclasses.is_dataclass(value):
        return {
            field.name: serial(getattr(value, field.name)) for field in dataclasses.fields(value)
        }
    if isinstance(value, enum.Enum):
        return value.value
    if isinstance(value, dict):
        return {str(key): serial(item) for key, item in value.items()}
    if isinstance(value, tuple | list | set | frozenset):
        return [serial(item) for item in value]
    if value is None or isinstance(value, str | bool | int | float):
        return value
    return str(value)


def model() -> ChatOpenAI:
    return ChatOpenAI(
        model="qwen3:8b",
        base_url="http://127.0.0.1:11434/v1",
        api_key="ollama",
        temperature=0,
        seed=20261005,
        timeout=600,
        max_retries=0,
        reasoning_effort="none",
    )


def security(
    tools,
    *,
    trusted_nodes: frozenset[str] = frozenset(),
    trusted_branches: frozenset[str] = frozenset(),
    record_audit: bool = False,
):
    audit = MemoryAuditSink() if record_audit else None
    config = dataclasses.replace(
        cedar_security_many(tools, policy=PRINCIPAL_POLICY),
        audit_sink=audit,
        closed_admission=True,
        trusted_application_nodes=trusted_nodes,
        trusted_application_branches=trusted_branches,
    )
    return config, None, audit


def custom_weather_graph(selected, model_timing: ModelTiming):
    chosen = [get_weather]
    bound = model().bind_tools(chosen)
    builder = StateGraph(MessagesState)

    def call_model(state: MessagesState):
        return {"messages": [model_timing.invoke(bound, state["messages"])]}

    def should_continue(state: MessagesState):
        return "tools" if state["messages"][-1].tool_calls else END

    builder.add_node("call_model", call_model)
    builder.add_node("tools", ToolNode(chosen, security=selected))
    builder.add_edge(START, "call_model")
    builder.add_conditional_edges("call_model", should_continue, ["tools", END])
    builder.add_edge("tools", "call_model")
    return builder.compile(security=selected)


def build(
    demo: str,
    mode: str,
    worker_route: Path | None,
    model_timing: ModelTiming,
    *,
    record_audit: bool = False,
):
    definitions = {
        "prebuilt-multiply": (
            ("multiply",),
            frozenset({"call_model"}),
            frozenset({"call_model:branch:should_continue"}),
        ),
        "custom-weather": (
            ("get_weather",),
            frozenset({"call_model"}),
            frozenset({"call_model:branch:should_continue"}),
        ),
        "fixed-weather": (("get_weather",), frozenset(), frozenset()),
        "parallel-weather": (
            ("get_weather", "get_coolest_cities"),
            frozenset(),
            frozenset(),
        ),
        "return-direct": (
            ("add",),
            frozenset({"call_model"}),
            frozenset(
                {
                    "call_model:branch:should_continue",
                    "tools:branch:after_tools",
                }
            ),
        ),
        "forced-tool": (
            ("greet",),
            frozenset({"call_model"}),
            frozenset(
                {
                    "call_model:branch:should_continue",
                    "tools:branch:after_tools",
                }
            ),
        ),
        "serial-tools": (
            ("add", "multiply"),
            frozenset({"call_model"}),
            frozenset({"call_model:branch:should_continue"}),
        ),
    }
    names, trusted_nodes, trusted_branches = definitions[demo]
    chosen = [TOOLS[name] for name in names]
    if demo == "return-direct":
        chosen = [add_direct]
    selected = dispatcher = audit = None
    if mode == "Argus":
        selected, dispatcher, audit = security(
            chosen,
            trusted_nodes=trusted_nodes,
            trusted_branches=trusted_branches,
            record_audit=record_audit,
        )
    if demo == "custom-weather":
        graph = custom_weather_graph(selected, model_timing)
        prompt = "What's the weather in San Francisco?"
    elif demo in {"fixed-weather", "parallel-weather"}:
        builder = StateGraph(MessagesState)
        builder.add_node("tools", ToolNode(chosen, security=selected))
        builder.add_edge(START, "tools")
        graph = builder.compile(security=selected)
        prompt = "Execute the tutorial's fixed ToolNode calls."
    else:
        selected_model = model().bind_tools(chosen)
        if demo == "forced-tool":
            selected_model = selected_model.bind_tools(
                chosen, tool_choice={"type": "tool", "name": "greet"}
            )
            prompt = "Hi, I am Bob"
        elif demo == "serial-tools":
            selected_model = selected_model.bind_tools(chosen, parallel_tool_calls=False)
            prompt = "What's 3 + 5 and 4 * 7? Use the tools for both calculations."
        elif demo == "return-direct":
            prompt = "What's 3 + 5? Use the add tool."
        else:
            prompt = "What's 42 x 7? Use the multiply tool."
        builder = StateGraph(MessagesState)

        def call_model(state: MessagesState):
            return {"messages": [model_timing.invoke(selected_model, state["messages"])]}

        def should_continue(state: MessagesState):
            return "tools" if state["messages"][-1].tool_calls else END

        def after_tools(_state: MessagesState):
            return END if demo in {"return-direct", "forced-tool"} else "call_model"

        builder.add_node("call_model", call_model)
        builder.add_node("tools", ToolNode(chosen, security=selected))
        builder.add_edge(START, "call_model")
        builder.add_conditional_edges("call_model", should_continue, ["tools", END])
        if demo in {"return-direct", "forced-tool"}:
            builder.add_conditional_edges("tools", after_tools, ["call_model", END])
        else:
            builder.add_edge("tools", "call_model")
        graph = builder.compile(security=selected)
    return graph, prompt, selected, dispatcher, audit


def main() -> None:
    parser = argparse.ArgumentParser()
    parser.add_argument(
        "--demo",
        choices=(
            "prebuilt-multiply",
            "custom-weather",
            "fixed-weather",
            "parallel-weather",
            "return-direct",
            "forced-tool",
            "serial-tools",
        ),
        required=True,
    )
    parser.add_argument("--mode", choices=("Baseline", "Argus"), required=True)
    parser.add_argument("--worker-route", type=Path)
    parser.add_argument("--output", type=Path, required=True)
    parser.add_argument("--audit", action="store_true")
    args = parser.parse_args()
    if args.audit and args.mode != "Argus":
        parser.error("--audit is only valid with --mode Argus")
    if args.mode == "Argus":
        install_mac_policy(OPERATOR_POLICY)
    preparation_started = time.perf_counter()
    model_timing = ModelTiming()
    graph, prompt, selected, dispatcher, audit = build(
        args.demo,
        args.mode,
        args.worker_route,
        model_timing,
        record_audit=args.audit,
    )
    principal = Principal("alice", frozenset(), frozenset(), f"{args.demo}-{uuid.uuid4().hex}")
    config = {"recursion_limit": 20}
    if selected is not None:
        config = with_principal(config, principal, modules=selected.modules)
    preparation_ms = (time.perf_counter() - preparation_started) * 1000
    if args.demo == "fixed-weather":
        graph_input = {
            "messages": [
                AIMessage(
                    content="",
                    tool_calls=[
                        {
                            "name": "get_weather",
                            "args": {"location": "San Francisco"},
                            "id": "fixed-weather",
                            "type": "tool_call",
                        }
                    ],
                )
            ]
        }
    elif args.demo == "parallel-weather":
        graph_input = {
            "messages": [
                AIMessage(
                    content="",
                    tool_calls=[
                        {
                            "name": "get_weather",
                            "args": {"location": "San Francisco"},
                            "id": "parallel-weather",
                            "type": "tool_call",
                        },
                        {
                            "name": "get_coolest_cities",
                            "args": {},
                            "id": "parallel-cities",
                            "type": "tool_call",
                        },
                    ],
                )
            ]
        }
    else:
        graph_input = {"messages": [("user", prompt)]}
    invocation_started = time.perf_counter()
    result = graph.invoke(graph_input, config=config)
    invocation_ms = (time.perf_counter() - invocation_started) * 1000
    messages = result["messages"]
    tool_messages = [message for message in messages if message.type == "tool"]
    args.output.write_text(
        json.dumps(
            {
                "demo": args.demo,
                "mode": args.mode,
                "isolation_route": "language" if selected else "baseline",
                "prompt": prompt,
                "wall_ms": invocation_ms,
                "invocation_ms": invocation_ms,
                "preparation_ms": preparation_ms,
                "model_time_ms": model_timing.wall_ms,
                "model_calls": model_timing.calls,
                "answer": str(messages[-1].content),
                "messages": [message.model_dump() for message in messages],
                "executed_tools": [message.name for message in tool_messages],
                "model_digest": MODEL_DIGEST,
                "authorization_decisions": [serial(item) for item in audit.records()]
                if audit
                else [],
                "authorization_grants": [
                    serial(item) for item in selected.host_executor.authorization_grants()
                ]
                if selected
                else [],
                "activation_receipts": [serial(item) for item in dispatcher.activation_receipts()]
                if dispatcher
                else [],
                "lowered_restrictions": [serial(item) for item in dispatcher.lowering_records()]
                if dispatcher
                else [],
            },
            indent=2,
        )
        + "\n"
    )


if __name__ == "__main__":
    main()
