# ruff: noqa: E501
"""Run the frozen add-memory and time-travel tutorials with optional Argus."""

from __future__ import annotations

import argparse
import dataclasses
import enum
import json
import time
import uuid
from pathlib import Path
from typing import Annotated

from add_tools_protected import (
    MODEL_DIGEST,
    OPERATOR_POLICY,
    search_tool,
    security,
)
from langchain_openai import ChatOpenAI
from langgraph.checkpoint.memory import InMemorySaver
from langgraph.graph import END, START, StateGraph
from langgraph.graph.message import add_messages
from langgraph.prebuilt import ToolNode
from langgraph.prebuilt.security import Principal, install_mac_policy, with_principal
from timing import ModelTiming
from typing_extensions import TypedDict


class State(TypedDict):
    messages: Annotated[list, add_messages]


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


def build(mode: str, worker_route: Path | None, model_timing: ModelTiming):
    selected = dispatcher = audit = None
    if mode == "Argus":
        if worker_route is None:
            raise ValueError("Argus requires the pinned Lean worker route")
        selected, dispatcher, audit = security(worker_route)
    llm = ChatOpenAI(
        model="qwen3:8b",
        base_url="http://127.0.0.1:11434/v1",
        api_key="ollama",
        temperature=0,
        seed=20261005,
        timeout=600,
        max_retries=0,
        reasoning_effort="none",
    ).bind_tools([search_tool])
    builder = StateGraph(State)

    def chatbot(state: State):
        return {"messages": [model_timing.invoke(llm, state["messages"])]}

    def route_tools(state: State):
        return "tools" if state["messages"][-1].tool_calls else END

    builder.add_node("chatbot", chatbot)
    builder.add_node("tools", ToolNode([search_tool], security=selected))
    builder.add_conditional_edges("chatbot", route_tools, ["tools", END])
    builder.add_edge("tools", "chatbot")
    builder.add_edge(START, "chatbot")
    graph = builder.compile(checkpointer=InMemorySaver(), security=selected)
    return graph, selected, dispatcher, audit


def main() -> None:
    parser = argparse.ArgumentParser()
    parser.add_argument("--demo", choices=("add-memory", "time-travel"), required=True)
    parser.add_argument("--mode", choices=("Baseline", "Argus"), required=True)
    parser.add_argument("--worker-route", type=Path)
    parser.add_argument("--output", type=Path, required=True)
    args = parser.parse_args()
    if args.mode == "Argus":
        install_mac_policy(OPERATOR_POLICY)
    started = time.perf_counter()
    model_timing = ModelTiming()
    graph, selected, dispatcher, audit = build(args.mode, args.worker_route, model_timing)
    thread_id = uuid.uuid4().hex
    principal = Principal("alice", frozenset(), frozenset(), f"{args.demo}-{uuid.uuid4().hex}")
    config = {
        "configurable": {"thread_id": thread_id},
        "recursion_limit": 20,
    }
    if selected is not None:
        config = with_principal(config, principal, modules=selected.modules)
    first = graph.invoke(
        {
            "messages": [
                (
                    "user",
                    "You must use the search tool. Which city and country hosted the 2012 Summer Olympics?",
                )
            ]
        },
        config=config,
    )
    replayed = False
    history_size = 0
    if args.demo == "add-memory":
        final = graph.invoke(
            {
                "messages": [
                    (
                        "user",
                        "What currency did that country use at the time? Use the search tool.",
                    )
                ]
            },
            config=config,
        )
    else:
        history = list(graph.get_state_history(config))
        history_size = len(history)
        checkpoint = next(
            state
            for state in history
            if state.next == ("tools",) and state.values["messages"][-1].tool_calls
        )
        replay_config = dict(checkpoint.config)
        replay_config["recursion_limit"] = 20
        if selected is not None:
            replay_config = with_principal(replay_config, principal, modules=selected.modules)
        final = graph.invoke(None, config=replay_config)
        replayed = True
    wall_ms = (time.perf_counter() - started) * 1000
    all_messages = final["messages"]
    tool_messages = [message for message in all_messages if message.type == "tool"]
    args.output.write_text(
        json.dumps(
            {
                "demo": args.demo,
                "mode": args.mode,
                "wall_ms": wall_ms,
                "model_time_ms": model_timing.wall_ms,
                "model_calls": model_timing.calls,
                "first_answer": str(first["messages"][-1].content),
                "answer": str(all_messages[-1].content),
                "messages": [message.model_dump() for message in all_messages],
                "executed_tools": [message.name for message in tool_messages],
                "thread_id": thread_id,
                "history_size": history_size,
                "replayed": replayed,
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
