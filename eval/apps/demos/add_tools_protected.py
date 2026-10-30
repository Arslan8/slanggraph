"""Run the upstream add-tools prebuilt ToolNode demo with or without Argus."""

from __future__ import annotations

import argparse
import dataclasses
import enum
import hashlib
import json
import time
import uuid
from pathlib import Path
from typing import Annotated

from frozen_search_worker import search
from langchain_core.tools import tool
from langchain_openai import ChatOpenAI
from langgraph.graph import END, START, StateGraph
from langgraph.graph.message import add_messages
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
from typing_extensions import TypedDict

HERE = Path(__file__).resolve().parent
WORKER = HERE / "frozen_search_worker.py"
WORKER_DIGEST = hashlib.sha256(WORKER.read_bytes()).hexdigest()
MODEL_DIGEST = "500a1f067a9f782620b40bee6f7b0c89e17ae61f686b92c24933e4ca4b2b8b41"
PRINCIPAL_POLICY = 'permit(principal == slangGraph::User::"alice", action, resource);'
OPERATOR_POLICY = """
forbid(
    principal == slangGraph::User::\"blocked\",
    action,
    resource
);
"""


class State(TypedDict):
    messages: Annotated[list, add_messages]


@tool("tavily_search")
def search_tool(query: str) -> list[dict[str, str]]:
    """Search and return up to two relevant results from the frozen web corpus."""
    return search(query)


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


def security(worker_route: Path):
    worker_route = worker_route.resolve()
    audit = MemoryAuditSink()
    checker = LeanLifecycleChecker(
        binary_path=str(worker_route),
        binary_sha256=hashlib.sha256(worker_route.read_bytes()).hexdigest(),
    )
    dispatcher = LinuxObjectDispatcher(
        {"tavily_search": LinuxToolSpec("frozen_search_worker:search", WORKER, WORKER_DIGEST)},
        runtime_roots=(HERE,),
        lifecycle_checker=checker,
        integrity_recheck="preflight-only",
    )
    parsed = parse_security_manifest(
        "tool tavily_search {\nruns linux\nreturns normal\n}",
        enforcers={EnforcementKind.KERNEL: dispatcher},
    )
    policies = CedarPolicySet(
        {"tavily_search": _language_sandbox_owner_policy(parsed.tools["tavily_search"])},
        PRINCIPAL_POLICY,
    )
    executor = ObjectPolicyHostExecutor(
        CedarObjectAuthorizer(parsed, policies),
        dispatcher,
        tool_owners={"tavily_search": "application"},
    )
    config = SecurityConfig(
        host_executor=executor,
        dac_overrides=DacOverrides({"tavily_search": ToolDac("__cedar__", {"*": "x"})}),
        audit_sink=audit,
        closed_admission=True,
        trusted_application_nodes=frozenset({"chatbot"}),
        trusted_application_branches=frozenset({"chatbot:branch:route_tools"}),
    )
    executor.validate_tools(("tavily_search",))
    return config, dispatcher, audit


def build(mode: str, worker_route: Path | None, model_timing: ModelTiming):
    model = ChatOpenAI(
        model="qwen3:8b",
        base_url="http://127.0.0.1:11434/v1",
        api_key="ollama",
        temperature=0,
        seed=20261005,
        timeout=600,
        max_retries=0,
        reasoning_effort="none",
    )
    model_with_tools = model.bind_tools([search_tool])
    selected = dispatcher = audit = None
    if mode == "Argus":
        if worker_route is None:
            raise ValueError("Argus requires the pinned Lean worker route")
        selected, dispatcher, audit = security(worker_route)
    builder = StateGraph(State)

    def chatbot(state: State):
        return {"messages": [model_timing.invoke(model_with_tools, state["messages"])]}

    def route_tools(state: State):
        return "tools" if state["messages"][-1].tool_calls else END

    builder.add_node("chatbot", chatbot)
    builder.add_node("tools", ToolNode(tools=[search_tool], security=selected))
    builder.add_conditional_edges("chatbot", route_tools, ["tools", END])
    builder.add_edge("tools", "chatbot")
    builder.add_edge(START, "chatbot")
    return builder.compile(security=selected), selected, dispatcher, audit


def main() -> None:
    parser = argparse.ArgumentParser()
    parser.add_argument("--mode", choices=("Baseline", "Argus"), required=True)
    parser.add_argument("--prompt", required=True)
    parser.add_argument("--output", type=Path, required=True)
    parser.add_argument("--worker-route", type=Path)
    args = parser.parse_args()
    if args.mode == "Argus":
        install_mac_policy(OPERATOR_POLICY)
    started = time.perf_counter()
    model_timing = ModelTiming()
    graph, selected, dispatcher, audit = build(args.mode, args.worker_route, model_timing)
    principal = Principal("alice", frozenset(), frozenset(), f"add-tools-{uuid.uuid4().hex}")
    config = {"recursion_limit": 20}
    if selected is not None:
        config = with_principal(config, principal, modules=selected.modules)
    result = graph.invoke({"messages": [("user", args.prompt)]}, config=config)
    elapsed = (time.perf_counter() - started) * 1000
    tool_messages = [message for message in result["messages"] if message.type == "tool"]
    args.output.write_text(
        json.dumps(
            {
                "mode": args.mode,
                "model": {
                    "name": "qwen3:8b",
                    "digest": MODEL_DIGEST,
                    "temperature": 0,
                    "seed": 20261005,
                    "reasoning_effort": "none",
                },
                "wall_ms": elapsed,
                "model_time_ms": model_timing.wall_ms,
                "model_calls": model_timing.calls,
                "answer": str(result["messages"][-1].content),
                "messages": [message.model_dump() for message in result["messages"]],
                "executed_tools": [message.name for message in tool_messages],
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
                "protections": {
                    "closed_admission": selected is not None,
                    "principal_authorization": selected is not None,
                    "sealed_operator_policy": selected is not None,
                    "linux_isolation": selected is not None,
                    "audit": selected is not None,
                    "lean_per_call": selected is not None,
                },
            },
            default=str,
            indent=2,
        )
        + "\n"
    )


if __name__ == "__main__":
    main()
