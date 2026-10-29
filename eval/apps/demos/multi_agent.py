# ruff: noqa: E501
"""Executable extraction of D4, the researcher/chart-generator network."""

from __future__ import annotations

import argparse
import dataclasses
import enum
import hashlib
import json
import sys
import time
from pathlib import Path
from typing import Annotated

import matplotlib

matplotlib.use("Agg")
import matplotlib.pyplot as plt
from langchain_core.messages import HumanMessage
from langchain_core.tools import tool
from langchain_experimental.utilities import PythonREPL
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
from resource_monitors.api import PYTHON_SESSION, SEARCH
from resource_monitors.backends import (
    ExactBrokerMediator,
    FrozenSearchBackend,
    PersistentPythonBackend,
)
from resource_monitors.python_worker import python_repl_tool as broker_python
from resource_monitors.search_worker import frozen_search as broker_search
from resource_monitors.security import monitored_security
from sklearn.feature_extraction.text import TfidfVectorizer
from timing import ModelTiming, assert_tool_parity


def llm() -> ChatOpenAI:
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


def make_system_prompt(suffix: str) -> str:
    return (
        "You are a helpful AI assistant, collaborating with other assistants."
        " Use the provided tools to progress towards answering the question."
        " If you are unable to fully answer, that's OK, another assistant with different tools "
        "will help where you left off. Execute what you can to make progress."
        " If you or any of the other assistants have the final answer or deliverable,"
        " prefix your response with FINAL ANSWER so the team knows to stop.\n" + suffix
    )


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
    gdp_path: Path,
    artifact: Path,
    observer: Path,
    mode: str,
    model_timing: ModelTiming,
):
    payload = json.loads(gdp_path.read_text())[1]
    documents = []
    for code in ("GBR", "FRA", "DEU", "JPN", "CAN"):
        rows = sorted(
            (row for row in payload if row["countryiso3code"] == code),
            key=lambda row: row["date"],
        )
        country = rows[0]["country"]["value"]
        values = ", ".join(f"{row['date']}: {row['value']}" for row in rows)
        documents.append(
            {
                "url": "https://api.worldbank.org/v2/indicator/NY.GDP.MKTP.CD",
                "content": f"{country} annual GDP current US dollars: {values}",
            }
        )
    vectorizer = TfidfVectorizer(stop_words="english").fit([item["content"] for item in documents])
    matrix = vectorizer.transform([item["content"] for item in documents])

    @tool("tavily_search")
    def baseline_tavily_tool(query: str) -> list[dict]:
        """Search the frozen public-data corpus and return up to five results."""
        scores = (matrix @ vectorizer.transform([query]).T).toarray().ravel()
        return [documents[index] for index in scores.argsort()[::-1]]

    repl = PythonREPL()

    @tool("python_repl_tool")
    def baseline_python_repl_tool(
        code: Annotated[str, "The python code to execute to generate your chart."],
    ):
        """Execute Python code to generate the chart; print values to expose them."""
        try:
            result = repl.run(code)
            figure = plt.gcf()
            lines = []
            for axis in figure.axes:
                for line in axis.lines:
                    lines.append(
                        {
                            "x": [str(value) for value in line.get_xdata().tolist()],
                            "y": [float(value) for value in line.get_ydata().tolist()],
                        }
                    )
            if lines:
                figure.savefig(artifact)
                observer.write_text(json.dumps({"lines": lines}, indent=2) + "\n")
        except BaseException as exc:
            return f"Failed to execute. Error: {exc!r}"
        return f"Successfully executed:\n```python\n{code}\n```\nStdout: {result}\n\nIf complete, respond with FINAL ANSWER."

    security = dispatcher = audit = python_backend = None
    if mode == "Baseline":
        tavily_tool = baseline_tavily_tool
        python_repl_tool = baseline_python_repl_tool
    else:
        search_resource = SEARCH.bind(
            implementation=FrozenSearchBackend(documents, limit=5),
            mediator=ExactBrokerMediator(
                "query-only access to the frozen GDP corpus",
                "eval/tests/test_demo_resource_monitors.py",
                (gdp_path,),
            ),
        )
        runtime_roots = (
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
        )
        python_backend = PersistentPythonBackend(
            artifact, observer, runtime_roots=tuple(runtime_roots)
        )
        python_resource = PYTHON_SESSION.bind(
            implementation=python_backend,
            mediator=ExactBrokerMediator(
                "persistent Landlock/seccomp Python chart session",
                "eval/tests/test_demo_resource_monitors.py",
                (gdp_path,),
            ),
        )
        monitor_dir = Path(__file__).with_name("resource_monitors")
        search_worker = monitor_dir / "search_worker.py"
        python_worker = monitor_dir / "python_worker.py"
        dispatcher = ObjectBrokerDispatcher(
            {
                "tavily_search": LinuxToolSpec(
                    "resource_monitors.search_worker:frozen_search",
                    search_worker,
                    hashlib.sha256(search_worker.read_bytes()).hexdigest(),
                ),
                "python_repl_tool": LinuxToolSpec(
                    "resource_monitors.python_worker:python_repl_tool",
                    python_worker,
                    hashlib.sha256(python_worker.read_bytes()).hexdigest(),
                ),
            },
            runtime_roots=runtime_roots,
            resources=(search_resource, python_resource),
        )
        tavily_tool = tool(
            "tavily_search",
            description=baseline_tavily_tool.description,
            args_schema=baseline_tavily_tool.args_schema,
        )(broker_search)
        python_repl_tool = tool(
            "python_repl_tool",
            description=baseline_python_repl_tool.description,
            args_schema=baseline_python_repl_tool.args_schema,
        )(broker_python)
        assert_tool_parity(baseline_tavily_tool, tavily_tool)
        assert_tool_parity(baseline_python_repl_tool, python_repl_tool)
        security, audit = monitored_security(
            (tavily_tool, python_repl_tool),
            dispatcher=dispatcher,
            resources=(search_resource, python_resource),
            permissions={
                "tavily_search": (search_resource.permission("search"),),
                "python_repl_tool": (python_resource.permission("execute"),),
            },
            trusted_nodes=("research_model", "research_handoff", "chart_model", "chart_handoff"),
            trusted_branches=(
                "research_model:branch:route_research",
                "research_handoff:branch:route_after_research",
                "chart_model:branch:route_chart",
                "chart_handoff:branch:route_after_chart",
            ),
        )

    research_model = llm().bind_tools([tavily_tool])
    chart_model = llm().bind_tools([python_repl_tool])

    def research_node(state: MessagesState):
        prompt = make_system_prompt(
            "You can only do research. You are working with a chart generator colleague."
        )
        return {
            "messages": [
                model_timing.invoke(research_model, [("system", prompt), *state["messages"]])
            ]
        }

    def chart_node(state: MessagesState):
        prompt = make_system_prompt(
            "You can only generate charts. You are working with a researcher colleague."
        )
        return {
            "messages": [
                model_timing.invoke(chart_model, [("system", prompt), *state["messages"]])
            ]
        }

    def route_research(state: MessagesState):
        return "research_tools" if state["messages"][-1].tool_calls else "research_handoff"

    def research_handoff(state: MessagesState):
        message = state["messages"][-1]
        return {"messages": [HumanMessage(content=message.content, name="researcher")]}

    def route_after_research(state: MessagesState):
        return END if "FINAL ANSWER" in str(state["messages"][-1].content) else "chart_model"

    def route_chart(state: MessagesState):
        return "chart_tools" if state["messages"][-1].tool_calls else "chart_handoff"

    def chart_handoff(state: MessagesState):
        message = state["messages"][-1]
        return {"messages": [HumanMessage(content=message.content, name="chart_generator")]}

    def route_after_chart(state: MessagesState):
        return END if "FINAL ANSWER" in str(state["messages"][-1].content) else "research_model"

    workflow = StateGraph(MessagesState)
    workflow.add_node("research_model", research_node)
    workflow.add_node(
        "research_tools",
        ToolNode((tavily_tool, python_repl_tool), security=security)
        if security
        else ToolNode([tavily_tool]),
    )
    workflow.add_node("research_handoff", research_handoff)
    workflow.add_node("chart_model", chart_node)
    workflow.add_node(
        "chart_tools",
        ToolNode((tavily_tool, python_repl_tool), security=security)
        if security
        else ToolNode([python_repl_tool]),
    )
    workflow.add_node("chart_handoff", chart_handoff)
    workflow.add_edge(START, "research_model")
    workflow.add_conditional_edges(
        "research_model", route_research, ["research_tools", "research_handoff"]
    )
    workflow.add_edge("research_tools", "research_model")
    workflow.add_conditional_edges("research_handoff", route_after_research, ["chart_model", END])
    workflow.add_conditional_edges("chart_model", route_chart, ["chart_tools", "chart_handoff"])
    workflow.add_edge("chart_tools", "chart_model")
    workflow.add_conditional_edges("chart_handoff", route_after_chart, ["research_model", END])
    return workflow.compile(security=security), security, dispatcher, audit, python_backend


def main() -> None:
    parser = argparse.ArgumentParser()
    parser.add_argument("--gdp", type=Path, required=True)
    parser.add_argument("--prompt", required=True)
    parser.add_argument("--artifact", type=Path, required=True)
    parser.add_argument("--observer", type=Path, required=True)
    parser.add_argument("--output", type=Path, required=True)
    parser.add_argument("--mode", choices=("Baseline", "Argus"), required=True)
    args = parser.parse_args()
    if args.mode == "Argus":
        install_mac_policy('forbid(principal == slangGraph::User::"blocked", action, resource);')
    started = time.perf_counter()
    model_timing = ModelTiming()
    graph, security, dispatcher, audit, python_backend = build(
        args.gdp, args.artifact, args.observer, args.mode, model_timing
    )
    config = {"recursion_limit": 150}
    if security is not None:
        config = with_principal(
            config,
            Principal("alice", frozenset(), frozenset(), "D4-resource-monitor"),
            modules=security.modules,
        )
    try:
        result = graph.invoke({"messages": [("user", args.prompt)]}, config)
    finally:
        if python_backend is not None:
            python_backend.close()
    args.output.write_text(
        json.dumps(
            {
                "answer": str(result["messages"][-1].content),
                "messages": [message.model_dump() for message in result["messages"]],
                "artifact": str(args.artifact),
                "observer": str(args.observer),
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
            indent=2,
        )
        + "\n"
    )


if __name__ == "__main__":
    main()
