"""Executable extraction of D1, SQL tutorial section 3 (custom graph)."""

from __future__ import annotations

import argparse
import dataclasses
import enum
import hashlib
import json
import sys
import time
from pathlib import Path
from typing import Literal

from langchain_community.agent_toolkits import SQLDatabaseToolkit
from langchain_community.utilities import SQLDatabase
from langchain_core.callbacks import BaseCallbackHandler
from langchain_core.messages import AIMessage
from langchain_core.tools import tool
from langchain_openai import ChatOpenAI
from langgraph.graph import END, START, MessagesState, StateGraph
from langgraph.prebuilt import ToolNode
from langgraph.prebuilt.security import (
    LinuxToolSpec,
    ObjectBrokerDispatcher,
    Principal,
    install_mac_policy,
    with_principal,
)
from resource_monitors.api import SQL_DATABASE
from resource_monitors.backends import ExactBrokerMediator, ReadOnlySQLBackend
from resource_monitors.security import monitored_security
from resource_monitors.sql_worker import list_tables as broker_list_tables
from resource_monitors.sql_worker import query as broker_query
from resource_monitors.sql_worker import schema as broker_schema
from timing import ModelTiming

MODEL = {
    "name": "qwen3:8b",
    "base_url": "http://127.0.0.1:11434/v1",
    "temperature": 0,
    "seed": 20261005,
    "digest": "500a1f067a9f782620b40bee6f7b0c89e17ae61f686b92c24933e4ca4b2b8b41",
    "timeout_seconds": 600,
    "max_retries": 0,
    "reasoning_effort": "none",
}


class Observer(BaseCallbackHandler):
    def __init__(self, events: Path):
        self.events = events

    def _write(self, value: dict) -> None:
        with self.events.open("a") as stream:
            stream.write(json.dumps(value, default=str) + "\n")

    def on_llm_start(self, serialized, prompts, **kwargs):
        self._write({"kind": "model_start", "monotonic": time.perf_counter(), "prompts": prompts})

    def on_llm_end(self, response, **kwargs):
        self._write(
            {
                "kind": "model_end",
                "monotonic": time.perf_counter(),
                "response": response.model_dump(),
            }
        )

    def on_tool_start(self, serialized, input_str, **kwargs):
        self._write(
            {
                "kind": "tool_start",
                "monotonic": time.perf_counter(),
                "name": serialized.get("name"),
                "input": input_str,
            }
        )

    def on_tool_end(self, output, **kwargs):
        self._write({"kind": "tool_end", "monotonic": time.perf_counter(), "output": str(output)})


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


def build(db_path: Path, events: Path, mode: str, model_timing: ModelTiming):
    llm = ChatOpenAI(
        model=MODEL["name"],
        base_url=MODEL["base_url"],
        api_key="ollama",
        temperature=MODEL["temperature"],
        seed=MODEL["seed"],
        timeout=MODEL["timeout_seconds"],
        max_retries=MODEL["max_retries"],
        reasoning_effort=MODEL["reasoning_effort"],
        callbacks=[Observer(events)],
    )
    db = SQLDatabase.from_uri(f"sqlite:///{db_path}")
    security = dispatcher = audit = None
    if mode == "Baseline":
        tools = SQLDatabaseToolkit(db=db, llm=llm).get_tools()
        list_tables_tool = next(item for item in tools if item.name == "sql_db_list_tables")
        get_schema_tool = next(item for item in tools if item.name == "sql_db_schema")
        run_query_tool = next(item for item in tools if item.name == "sql_db_query")
    else:
        resource = SQL_DATABASE.bind(
            implementation=ReadOnlySQLBackend(db_path),
            mediator=ExactBrokerMediator(
                "read-only SQL metadata and SELECT execution",
                "eval/tests/test_demo_resource_monitors.py",
                (db_path,),
            ),
        )
        worker = Path(__file__).with_name("resource_monitors") / "sql_worker.py"
        specs = {
            "sql_db_list_tables": LinuxToolSpec(
                "resource_monitors.sql_worker:list_tables",
                worker,
                hashlib.sha256(worker.read_bytes()).hexdigest(),
            ),
            "sql_db_schema": LinuxToolSpec(
                "resource_monitors.sql_worker:schema",
                worker,
                hashlib.sha256(worker.read_bytes()).hexdigest(),
            ),
            "sql_db_query": LinuxToolSpec(
                "resource_monitors.sql_worker:query",
                worker,
                hashlib.sha256(worker.read_bytes()).hexdigest(),
            ),
        }
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
            resources=(resource,),
        )
        list_tables_tool = tool("sql_db_list_tables")(broker_list_tables)
        get_schema_tool = tool("sql_db_schema")(broker_schema)
        run_query_tool = tool("sql_db_query")(broker_query)
        tool_set = (list_tables_tool, get_schema_tool, run_query_tool)
        security, audit = monitored_security(
            tool_set,
            dispatcher=dispatcher,
            resources=(resource,),
            permissions={
                "sql_db_list_tables": (resource.permission("list_tables"),),
                "sql_db_schema": (resource.permission("schema"),),
                "sql_db_query": (resource.permission("query"),),
            },
            trusted_nodes=(
                "request_list_tables",
                "format_list_tables",
                "call_get_schema",
                "generate_query",
                "check_query",
            ),
            trusted_branches=("generate_query:branch:should_continue",),
        )
    node_tools = (
        tool_set if mode == "Argus" else (list_tables_tool, get_schema_tool, run_query_tool)
    )
    get_schema_node = ToolNode(node_tools, name="get_schema", security=security)
    run_query_node = ToolNode(node_tools, name="run_query", security=security)

    def list_tables(state: MessagesState):
        del state
        tool_call = {
            "name": "sql_db_list_tables",
            "args": {},
            "id": "abc123",
            "type": "tool_call",
        }
        tool_call_message = AIMessage(content="", tool_calls=[tool_call])
        tool_message = list_tables_tool.invoke(tool_call)
        response = AIMessage(f"Available tables: {tool_message.content}")
        return {"messages": [tool_call_message, tool_message, response]}

    def call_get_schema(state: MessagesState):
        model = llm.bind_tools([get_schema_tool], tool_choice="any")
        return {"messages": [model_timing.invoke(model, state["messages"])]}

    generate_prompt = f"""
You are an agent designed to interact with a SQL database.
Given an input question, create a syntactically correct {db.dialect} query to run,
then look at the results of the query and return the answer. Unless the user
specifies a specific number of examples they wish to obtain, always limit your
query to at most 5 results.

You can order the results by a relevant column to return the most interesting
examples in the database. Never query for all the columns from a specific table,
only ask for the relevant columns given the question.

DO NOT make any DML statements (INSERT, UPDATE, DELETE, DROP etc.) to the database.
"""

    def generate_query(state: MessagesState):
        model = llm.bind_tools([run_query_tool])
        response = model_timing.invoke(
            model,
            [{"role": "system", "content": generate_prompt}] + state["messages"]
        )
        return {"messages": [response]}

    check_prompt = f"""
You are a SQL expert with a strong attention to detail.
Double check the {db.dialect} query for common mistakes, including:
- Using NOT IN with NULL values
- Using UNION when UNION ALL should have been used
- Using BETWEEN for exclusive ranges
- Data type mismatch in predicates
- Properly quoting identifiers
- Using the correct number of arguments for functions
- Casting to the correct data type
- Using the proper columns for joins

If there are any of the above mistakes, rewrite the query. If there are no mistakes,
just reproduce the original query.

You will call the appropriate tool to execute the query after running this check.
"""

    def check_query(state: MessagesState):
        tool_call = state["messages"][-1].tool_calls[0]
        user_message = {"role": "user", "content": tool_call["args"]["query"]}
        model = llm.bind_tools([run_query_tool], tool_choice="any")
        response = model_timing.invoke(
            model, [{"role": "system", "content": check_prompt}, user_message]
        )
        response.id = state["messages"][-1].id
        return {"messages": [response]}

    def should_continue(state: MessagesState) -> Literal[END, "check_query"]:
        return "check_query" if state["messages"][-1].tool_calls else END

    builder = StateGraph(MessagesState)
    if mode == "Baseline":
        builder.add_node(list_tables)
        list_tables_tail = "list_tables"
    else:

        def request_list_tables(state: MessagesState):
            del state
            return {
                "messages": [
                    AIMessage(
                        content="",
                        tool_calls=[
                            {
                                "name": "sql_db_list_tables",
                                "args": {},
                                "id": "list-tables",
                                "type": "tool_call",
                            }
                        ],
                    )
                ]
            }

        def format_list_tables(state: MessagesState):
            return {"messages": [AIMessage(f"Available tables: {state['messages'][-1].content}")]}

        builder.add_node("request_list_tables", request_list_tables)
        builder.add_node(
            "list_tables",
            ToolNode(node_tools, security=security),
        )
        builder.add_node("format_list_tables", format_list_tables)
        builder.add_edge(START, "request_list_tables")
        builder.add_edge("request_list_tables", "list_tables")
        builder.add_edge("list_tables", "format_list_tables")
        list_tables_tail = "format_list_tables"
    builder.add_node(call_get_schema)
    builder.add_node(get_schema_node, "get_schema")
    builder.add_node(generate_query)
    builder.add_node(check_query)
    builder.add_node(run_query_node, "run_query")
    if mode == "Baseline":
        builder.add_edge(START, "list_tables")
    builder.add_edge(list_tables_tail, "call_get_schema")
    builder.add_edge("call_get_schema", "get_schema")
    builder.add_edge("get_schema", "generate_query")
    builder.add_conditional_edges("generate_query", should_continue)
    builder.add_edge("check_query", "run_query")
    builder.add_edge("run_query", "generate_query")
    return builder.compile(security=security), security, dispatcher, audit


def main() -> None:
    parser = argparse.ArgumentParser()
    parser.add_argument("--database", required=True, type=Path)
    parser.add_argument("--prompt", required=True)
    parser.add_argument("--events", required=True, type=Path)
    parser.add_argument("--output", required=True, type=Path)
    parser.add_argument("--mode", choices=("Baseline", "Argus"), required=True)
    args = parser.parse_args()
    if args.mode == "Argus":
        install_mac_policy('forbid(principal == slangGraph::User::"blocked", action, resource);')
    started = time.perf_counter()
    model_timing = ModelTiming()
    graph, security, dispatcher, audit = build(
        args.database.resolve(), args.events, args.mode, model_timing
    )
    config = {"recursion_limit": 50}
    if security is not None:
        config = with_principal(
            config,
            Principal("alice", frozenset(), frozenset(), "D1-resource-monitor"),
            modules=security.modules,
        )
    result = graph.invoke({"messages": [("user", args.prompt)]}, config=config)
    args.output.write_text(
        json.dumps(
            {
                "messages": [message.model_dump() for message in result["messages"]],
                "answer": str(result["messages"][-1].content),
                "wall_ms": (time.perf_counter() - started) * 1000,
                "model_time_ms": model_timing.wall_ms,
                "model_calls": model_timing.calls,
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
