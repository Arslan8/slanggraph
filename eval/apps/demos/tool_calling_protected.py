"""Run ordinary frozen LangGraph tool-calling examples under Baseline or Argus."""

from __future__ import annotations

import argparse
import dataclasses
import enum
import hashlib
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
    CedarObjectAuthorizer,
    CedarPolicySet,
    DacOverrides,
    EnforcementKind,
    LinuxObjectDispatcher,
    LinuxToolSpec,
    MemoryAuditSink,
    ObjectPolicyHostExecutor,
    Principal,
    SecurityConfig,
    ToolDac,
    install_mac_policy,
    parse_security_manifest,
    with_principal,
)
from langgraph.prebuilt.security.lean_lifecycle import LeanLifecycleChecker
from langgraph.prebuilt.security.object_policy import _language_sandbox_owner_policy
from timing import ModelTiming
from tool_calling_worker import add as worker_add
from tool_calling_worker import get_coolest_cities as worker_get_coolest_cities
from tool_calling_worker import get_weather as worker_get_weather
from tool_calling_worker import greet as worker_greet
from tool_calling_worker import multiply as worker_multiply

HERE = Path(__file__).resolve().parent
WORKER = HERE / "tool_calling_worker.py"
WORKER_DIGEST = hashlib.sha256(WORKER.read_bytes()).hexdigest()
MODEL_DIGEST = "500a1f067a9f782620b40bee6f7b0c89e17ae61f686b92c24933e4ca4b2b8b41"
LEAN_RUNTIME = (
    "/home/faculty/abk6349/.elan/toolchains/leanprover--lean4---v4.34.1/lib/lean/libleanshared.so"
)
LEAN_RUNTIME_SHA256 = "6b30cc963d065fc9d2f87f7e9cbe0682b23000ae5425bccd769c5d477fa74f13"
PRINCIPAL_POLICY = 'permit(principal == slangGraph::User::"alice", action, resource);'
OPERATOR_POLICY = 'forbid(principal == slangGraph::User::"blocked", action, resource);'


@tool
def multiply(a: int, b: int) -> int:
    """Multiply two numbers."""
    return worker_multiply(a, b)


@tool
def add(a: int, b: int) -> int:
    """Add two numbers."""
    return worker_add(a, b)


@tool("add", return_direct=True)
def add_direct(a: int, b: int) -> int:
    """Add two numbers."""
    return worker_add(a, b)


@tool
def get_weather(location: str) -> str:
    """Call to get the current weather."""
    return worker_get_weather(location)


@tool
def get_coolest_cities() -> str:
    """Get a list of coolest cities."""
    return worker_get_coolest_cities()


@tool(return_direct=True)
def greet(user_name: str) -> str:
    """Greet user."""
    return worker_greet(user_name)


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
    tool_names: tuple[str, ...],
    worker_route: Path,
    *,
    trusted_nodes: frozenset[str] = frozenset(),
    trusted_branches: frozenset[str] = frozenset(),
):
    worker_route = worker_route.resolve()
    audit = MemoryAuditSink()
    checker = LeanLifecycleChecker(
        binary_path=str(worker_route),
        binary_sha256=hashlib.sha256(worker_route.read_bytes()).hexdigest(),
        runtime_path=LEAN_RUNTIME,
        runtime_sha256=LEAN_RUNTIME_SHA256,
    )
    dispatcher = LinuxObjectDispatcher(
        {
            name: LinuxToolSpec(f"tool_calling_worker:{name}", WORKER, WORKER_DIGEST)
            for name in tool_names
        },
        runtime_roots=(HERE,),
        lifecycle_checker=checker,
        integrity_recheck="preflight-only",
    )
    manifest = "\n".join(f"tool {name} {{\nruns linux\nreturns normal\n}}" for name in tool_names)
    parsed = parse_security_manifest(
        manifest,
        enforcers={EnforcementKind.KERNEL: dispatcher},
    )
    policies = CedarPolicySet(
        {name: _language_sandbox_owner_policy(parsed.tools[name]) for name in tool_names},
        PRINCIPAL_POLICY,
    )
    executor = ObjectPolicyHostExecutor(
        CedarObjectAuthorizer(parsed, policies),
        dispatcher,
        tool_owners={name: "application" for name in tool_names},
    )
    config = SecurityConfig(
        host_executor=executor,
        dac_overrides=DacOverrides({name: ToolDac("__cedar__", {"*": "x"}) for name in tool_names}),
        audit_sink=audit,
        closed_admission=True,
        trusted_application_nodes=trusted_nodes,
        trusted_application_branches=trusted_branches,
    )
    executor.validate_tools(tool_names)
    return config, dispatcher, audit


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


def build(demo: str, mode: str, worker_route: Path | None, model_timing: ModelTiming):
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
    selected = dispatcher = audit = None
    if mode == "Argus":
        if worker_route is None:
            raise ValueError("Argus requires the pinned Lean worker route")
        selected, dispatcher, audit = security(
            names,
            worker_route,
            trusted_nodes=trusted_nodes,
            trusted_branches=trusted_branches,
        )
    chosen = [TOOLS[name] for name in names]
    if demo == "return-direct":
        chosen = [add_direct]
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
    args = parser.parse_args()
    if args.mode == "Argus":
        install_mac_policy(OPERATOR_POLICY)
    started = time.perf_counter()
    model_timing = ModelTiming()
    graph, prompt, selected, dispatcher, audit = build(
        args.demo, args.mode, args.worker_route, model_timing
    )
    principal = Principal("alice", frozenset(), frozenset(), f"{args.demo}-{uuid.uuid4().hex}")
    config = {"recursion_limit": 20}
    if selected is not None:
        config = with_principal(config, principal, modules=selected.modules)
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
    result = graph.invoke(graph_input, config=config)
    wall_ms = (time.perf_counter() - started) * 1000
    messages = result["messages"]
    tool_messages = [message for message in messages if message.type == "tool"]
    args.output.write_text(
        json.dumps(
            {
                "demo": args.demo,
                "mode": args.mode,
                "prompt": prompt,
                "wall_ms": wall_ms,
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
