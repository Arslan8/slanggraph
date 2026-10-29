# ruff: noqa: E501
"""Executable extraction of D5, customer-support Part 3 conditional interrupt."""

from __future__ import annotations

import argparse
import dataclasses
import enum
import hashlib
import json
import re
import shutil
import sqlite3
import sys
import time
import uuid
from pathlib import Path
from typing import Annotated

import pandas as pd
from langchain_core.messages import AIMessage, ToolMessage
from langchain_core.prompts import ChatPromptTemplate
from langchain_core.runnables import Runnable, RunnableConfig, RunnableLambda
from langchain_core.tools import tool
from langchain_openai import ChatOpenAI
from langgraph.checkpoint.memory import InMemorySaver
from langgraph.graph import END, START, StateGraph
from langgraph.graph.message import AnyMessage, add_messages
from langgraph.prebuilt import ToolNode, tools_condition
from langgraph.prebuilt.security import (
    LinuxToolSpec,
    ObjectBrokerDispatcher,
    Principal,
    install_mac_policy,
    with_principal,
)
from resource_monitors.api import POLICY, SEARCH, TRAVEL
from resource_monitors.backends import (
    EmptySearchBackend,
    ExactBrokerMediator,
    TFIDFRetrieverBackend,
    TravelSQLiteBackend,
)
from resource_monitors.policy_worker import lookup_policy as broker_lookup_policy
from resource_monitors.search_worker import frozen_search as broker_search
from resource_monitors.security import monitored_security
from resource_monitors.travel_worker import (
    cancel_ticket as broker_cancel,
)
from resource_monitors.travel_worker import (
    fetch_user_flight_information as broker_fetch,
)
from resource_monitors.travel_worker import (
    search_flights as broker_flight_search,
)
from resource_monitors.travel_worker import (
    update_ticket_to_new_flight as broker_update,
)
from sklearn.feature_extraction.text import TfidfVectorizer
from timing import ModelTiming
from typing_extensions import TypedDict

FROZEN_NOW = pd.Timestamp("2026-11-15T12:05:03.561731-04:00")
PASSENGER = "3442 587242"
TICKET = "7240005432906569"
ALTERNATIVE_FLIGHT = 1472


def prepare_database(source: Path, destination: Path) -> None:
    shutil.copy2(source, destination)
    connection = sqlite3.connect(destination)
    tables = pd.read_sql(
        "SELECT name FROM sqlite_master WHERE type='table';", connection
    ).name.tolist()
    frames = {name: pd.read_sql(f"SELECT * from {name}", connection) for name in tables}
    example_time = pd.to_datetime(
        frames["flights"]["actual_departure"].replace("\\N", pd.NaT)
    ).max()
    delta = FROZEN_NOW - example_time
    frames["bookings"]["book_date"] = (
        pd.to_datetime(frames["bookings"]["book_date"].replace("\\N", pd.NaT), utc=True) + delta
    )
    for column in (
        "scheduled_departure",
        "scheduled_arrival",
        "actual_departure",
        "actual_arrival",
    ):
        frames["flights"][column] = (
            pd.to_datetime(frames["flights"][column].replace("\\N", pd.NaT)) + delta
        )
    for name, frame in frames.items():
        frame.to_sql(name, connection, if_exists="replace", index=False)
    connection.commit()
    connection.close()


def snapshot(database: Path) -> dict:
    connection = sqlite3.connect(database)
    flights = connection.execute(
        "SELECT flight_id FROM ticket_flights WHERE ticket_no = ? ORDER BY flight_id",
        (TICKET,),
    ).fetchall()
    owned = connection.execute(
        "SELECT passenger_id FROM tickets WHERE ticket_no = ?", (TICKET,)
    ).fetchone()
    connection.close()
    return {"ticket": TICKET, "flight_ids": [row[0] for row in flights], "owner": owned[0]}


class State(TypedDict):
    messages: Annotated[list[AnyMessage], add_messages]
    user_info: str


_MODEL_TIMING: ModelTiming | None = None


class Assistant:
    def __init__(self, runnable: Runnable):
        self.runnable = runnable

    def __call__(self, state: State, config: RunnableConfig):
        while True:
            result = (
                _MODEL_TIMING.invoke(self.runnable, state)
                if _MODEL_TIMING is not None
                else self.runnable.invoke(state)
            )
            if not result.tool_calls and (
                not result.content
                or (isinstance(result.content, list) and not result.content[0].get("text"))
            ):
                state = {
                    **state,
                    "messages": state["messages"] + [("user", "Respond with a real output.")],
                }
            else:
                return {"messages": result}


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


def build(
    database: Path,
    notebook: Path,
    faq_path: Path,
    mode: str,
):
    namespace = dict(globals())
    namespace.update({"db": str(database), "tool": tool})
    cells = json.loads(notebook.read_text())["cells"]
    for index in (9, 11, 13, 15, 17):
        source = "".join(cells[index]["source"])
        source = source.replace(
            "current_time = datetime.now(tz=timezone)",
            "current_time = FROZEN_NOW.to_pydatetime().astimezone(timezone)",
        )
        exec(compile(source, f"customer-support.ipynb:cell-{index}", "exec"), namespace)

    faq_sections = [
        part.strip() for part in re.split(r"(?=\n##)", faq_path.read_text()) if part.strip()
    ]
    vectorizer = TfidfVectorizer(stop_words="english").fit(faq_sections)
    matrix = vectorizer.transform(faq_sections)

    @tool
    def baseline_lookup_policy(query: str) -> str:
        """Consult the company policies to check whether certain options are permitted."""
        scores = (matrix @ vectorizer.transform([query]).T).toarray().ravel()
        return "\n\n".join(faq_sections[index] for index in scores.argsort()[-2:][::-1])

    @tool("tavily_search_results_json")
    def baseline_frozen_search(query: str) -> list[dict]:
        """Search the frozen travel corpus with the tutorial's search schema."""
        del query
        return []

    dispatcher = security = audit = None
    if mode == "Baseline":
        fetch = namespace["fetch_user_flight_information"]
        search = namespace["search_flights"]
        update = namespace["update_ticket_to_new_flight"]
        cancel = namespace["cancel_ticket"]
        lookup_policy = baseline_lookup_policy
        frozen_search = baseline_frozen_search
    else:
        travel_resource = TRAVEL.bind(
            implementation=TravelSQLiteBackend(database, PASSENGER, FROZEN_NOW.to_pydatetime()),
            mediator=ExactBrokerMediator(
                "principal-bound travel reads and ticket mutations",
                "eval/tests/test_demo_resource_monitors.py",
                (database,),
            ),
        )
        policy_resource = POLICY.bind(
            implementation=TFIDFRetrieverBackend(faq_sections, limit=2),
            mediator=ExactBrokerMediator(
                "query-only access to the frozen airline policy index",
                "eval/tests/test_demo_resource_monitors.py",
                (faq_path,),
            ),
        )
        search_resource = SEARCH.bind(
            implementation=EmptySearchBackend(),
            mediator=ExactBrokerMediator(
                "query-only access to the frozen empty travel search fixture",
                "eval/tests/test_demo_resource_monitors.py",
            ),
        )
        monitor_dir = Path(__file__).with_name("resource_monitors")
        travel_worker = monitor_dir / "travel_worker.py"
        policy_worker = monitor_dir / "policy_worker.py"
        search_worker = monitor_dir / "search_worker.py"
        specs = {
            name: LinuxToolSpec(
                f"resource_monitors.travel_worker:{entrypoint}",
                travel_worker,
                hashlib.sha256(travel_worker.read_bytes()).hexdigest(),
            )
            for name, entrypoint in {
                "fetch_user_flight_information": "fetch_user_flight_information",
                "search_flights": "search_flights",
                "update_ticket_to_new_flight": "update_ticket_to_new_flight",
                "cancel_ticket": "cancel_ticket",
            }.items()
        }
        specs["lookup_policy"] = LinuxToolSpec(
            "resource_monitors.policy_worker:lookup_policy",
            policy_worker,
            hashlib.sha256(policy_worker.read_bytes()).hexdigest(),
        )
        specs["tavily_search_results_json"] = LinuxToolSpec(
            "resource_monitors.search_worker:frozen_search",
            search_worker,
            hashlib.sha256(search_worker.read_bytes()).hexdigest(),
        )
        dispatcher = ObjectBrokerDispatcher(
            specs,
            runtime_roots=(
                Path(__file__).resolve().parent,
                Path(__file__).resolve().parents[3] / "libs/prebuilt",
                Path(__file__).resolve().parents[3] / "libs/langgraph",
                Path(__file__).resolve().parents[3] / "libs/checkpoint",
                Path(__file__).resolve().parents[3] / "libs/sdk-py",
                *(
                    Path(item).resolve()
                    for item in sys.path
                    if item and "site-packages" in item and Path(item).is_dir()
                ),
            ),
            resources=(travel_resource, policy_resource, search_resource),
        )
        fetch = tool(
            "fetch_user_flight_information",
            description="Fetch all tickets and flight details for the signed-in passenger.",
        )(broker_fetch)
        search = tool(
            "search_flights",
            description="Search flights by airports and optional departure-time range.",
        )(broker_flight_search)
        update = tool(
            "update_ticket_to_new_flight",
            description="Update the signed-in passenger's ticket to a valid new flight.",
        )(broker_update)
        cancel = tool(
            "cancel_ticket",
            description="Cancel a ticket owned by the signed-in passenger.",
        )(broker_cancel)
        lookup_policy = tool(
            "lookup_policy",
            description="Consult the frozen airline policy corpus.",
        )(broker_lookup_policy)
        frozen_search = tool(
            "tavily_search_results_json",
            description="Search the frozen travel web corpus.",
        )(broker_search)
        all_tools = (frozen_search, fetch, search, lookup_policy, update, cancel)
        security, audit = monitored_security(
            all_tools,
            dispatcher=dispatcher,
            resources=(travel_resource, policy_resource, search_resource),
            permissions={
                "fetch_user_flight_information": (travel_resource.permission("fetch_user"),),
                "search_flights": (travel_resource.permission("search_flights"),),
                "update_ticket_to_new_flight": (travel_resource.permission("update_ticket"),),
                "cancel_ticket": (travel_resource.permission("cancel_ticket"),),
                "lookup_policy": (policy_resource.permission("search"),),
                "tavily_search_results_json": (search_resource.permission("search"),),
            },
            trusted_nodes=("request_user_info", "format_user_info", "assistant"),
            trusted_branches=("assistant:branch:route_tools",),
        )
    safe_tools = [frozen_search, fetch, search, lookup_policy]
    sensitive_tools = [update, cancel]
    sensitive_names = {item.name for item in sensitive_tools}
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
    prompt = ChatPromptTemplate.from_messages(
        [
            (
                "system",
                "You are a helpful customer support assistant for Swiss Airlines. "
                "Use the provided tools to search for flights, company policies, and other "
                "information. When searching, be persistent and expand query bounds if needed."
                "\n\nCurrent user:\n<User>\n{user_info}\n</User>"
                "\nCurrent time: {time}.",
            ),
            ("placeholder", "{messages}"),
        ]
    ).partial(time=FROZEN_NOW.isoformat())
    assistant = prompt | model.bind_tools(safe_tools + sensitive_tools)
    builder = StateGraph(State)

    def assistant_node(state: State, config: RunnableConfig):
        return Assistant(assistant)(state, config)

    def request_user_info(state: State):
        del state
        return {
            "messages": [
                AIMessage(
                    content="",
                    tool_calls=[
                        {
                            "name": "fetch_user_flight_information",
                            "args": {},
                            "id": "initial-user-info",
                            "type": "tool_call",
                        }
                    ],
                )
            ]
        }

    def format_user_info(state: State):
        return {"user_info": str(state["messages"][-1].content)}

    def tool_node():
        tools = safe_tools + sensitive_tools
        if security:
            return ToolNode(tools, security=security)
        return ToolNode(tools).with_fallbacks(
            [RunnableLambda(namespace["handle_tool_error"])], exception_key="error"
        )

    def route_tools(state: State):
        next_node = tools_condition(state)
        if next_node == END:
            return END
        first = state["messages"][-1].tool_calls[0]
        return "sensitive_tools" if first["name"] in sensitive_names else "safe_tools"

    builder.add_node("request_user_info", request_user_info)
    builder.add_edge(START, "request_user_info")
    builder.add_node("fetch_user_info", tool_node())
    builder.add_node("format_user_info", format_user_info)
    builder.add_node("assistant", assistant_node)
    builder.add_node("safe_tools", tool_node())
    builder.add_node("sensitive_tools", tool_node())
    builder.add_edge("request_user_info", "fetch_user_info")
    builder.add_edge("fetch_user_info", "format_user_info")
    builder.add_edge("format_user_info", "assistant")
    builder.add_conditional_edges("assistant", route_tools, ["safe_tools", "sensitive_tools", END])
    builder.add_edge("safe_tools", "assistant")
    builder.add_edge("sensitive_tools", "assistant")
    return (
        builder.compile(
            checkpointer=InMemorySaver(),
            interrupt_before=["sensitive_tools"],
            security=security,
        ),
        security,
        dispatcher,
        audit,
    )


def drive(graph, task_id: int, security=None) -> dict:
    prompts = {
        1: ["Retrieve my existing flight details."],
        2: [
            "Search for an eligible alternative BSL to CDG flight after 2026-11-24 without changing my booking."
        ],
        3: [
            f"Change my ticket {TICKET} to flight {ALTERNATIVE_FLIGHT}.",
            "Retrieve my changed booking.",
        ],
        4: [
            f"Change my ticket {TICKET} to flight {ALTERNATIVE_FLIGHT}.",
            "Retrieve my unchanged booking.",
        ],
        5: [f"Cancel my owned ticket {TICKET}.", "Retrieve my current booking after cancellation."],
    }[task_id]
    approve = task_id in {3, 5}
    config = {
        "configurable": {"passenger_id": PASSENGER, "thread_id": str(uuid.uuid4())},
    }
    if security is not None:
        config = with_principal(
            config,
            Principal("alice", frozenset(), frozenset(), "D5-resource-monitor"),
            modules=security.modules,
        )
    interrupts = []
    final = None
    for prompt in prompts:
        final = graph.invoke({"messages": [("user", prompt)]}, config)
        while final["messages"][-1].tool_calls:
            call = final["messages"][-1].tool_calls[0]
            if call["name"] not in {"update_ticket_to_new_flight", "cancel_ticket"}:
                break
            interrupts.append({"tool_call": call, "approved": approve})
            if approve:
                final = graph.invoke(None, config)
            else:
                final = graph.invoke(
                    {
                        "messages": [
                            ToolMessage(
                                tool_call_id=call["id"],
                                content="API call denied by user. Continue without making the change.",
                            )
                        ]
                    },
                    config,
                )
    return {"state": final, "interrupts": interrupts}


def main() -> None:
    global _MODEL_TIMING
    parser = argparse.ArgumentParser()
    parser.add_argument("--source-database", type=Path, required=True)
    parser.add_argument("--database", type=Path, required=True)
    parser.add_argument("--notebook", type=Path, required=True)
    parser.add_argument("--faq", type=Path, required=True)
    parser.add_argument("--task-id", type=int, choices=range(1, 6), required=True)
    parser.add_argument("--output", type=Path, required=True)
    parser.add_argument("--mode", choices=("Baseline", "Argus"), required=True)
    args = parser.parse_args()
    prepare_database(args.source_database, args.database)
    before = snapshot(args.database)
    if args.mode == "Argus":
        install_mac_policy('forbid(principal == slangGraph::User::"blocked", action, resource);')
    started = time.perf_counter()
    model_timing = ModelTiming()
    _MODEL_TIMING = model_timing
    graph, security, dispatcher, audit = build(args.database, args.notebook, args.faq, args.mode)
    result = drive(graph, args.task_id, security)
    after = snapshot(args.database)
    state = result["state"] or {"messages": []}
    args.output.write_text(
        json.dumps(
            {
                "before": before,
                "after": after,
                "interrupts": result["interrupts"],
                "messages": [message.model_dump() for message in state.get("messages", [])],
                "wall_ms": (time.perf_counter() - started) * 1000,
                "model_time_ms": model_timing.wall_ms,
                "model_calls": model_timing.calls,
                "frozen_now": FROZEN_NOW.isoformat(),
                "authorization_decisions": [serial(item) for item in audit.records()]
                if audit
                else [],
                "authorization_grants": [
                    serial(item) for item in security.host_executor.authorization_grants()
                ]
                if security
                else [],
                "lowering_records": [serial(item) for item in dispatcher.lowering_records()]
                if dispatcher
                else [],
                "broker_audit": [serial(item) for item in dispatcher.audit_records()]
                if dispatcher
                else [],
            },
            default=str,
            indent=2,
        )
        + "\n"
    )


if __name__ == "__main__":
    main()
