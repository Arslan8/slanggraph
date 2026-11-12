"""Executable extraction of D3, the complete async planner/executor/replanner graph."""

from __future__ import annotations

import argparse
import asyncio
import dataclasses
import enum
import json
import operator
import time
from pathlib import Path
from typing import Annotated

from langchain_core.prompts import ChatPromptTemplate
from langchain_core.tools import tool
from langchain_openai import ChatOpenAI
from langgraph.graph import END, START, StateGraph
from langgraph.prebuilt import ToolNode
from langgraph.prebuilt.security import (
    Principal,
    install_mac_policy,
    sklearn_json_search_resource,
    with_principal,
)
from pydantic import BaseModel, Field
from resource_monitors.search_worker import frozen_search as broker_search
from resource_monitors.security import mediated_language_security
from runtime_protocol import wait_for_parent
from sklearn.feature_extraction.text import TfidfVectorizer
from timing import ModelTiming, assert_tool_parity
from typing_extensions import TypedDict


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


class PlanExecute(TypedDict):
    input: str
    plan: list[str]
    past_steps: Annotated[list[tuple], operator.add]
    response: str
    messages: list
    termination_reason: str


class Plan(BaseModel):
    steps: list[str] = Field(description="different steps to follow, should be in sorted order")


class Response(BaseModel):
    response: str


class Act(BaseModel):
    action: Response | Plan = Field(
        description="Respond when complete; otherwise provide only remaining plan steps."
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
    corpus_path: Path,
    mode: str,
    model_timing: ModelTiming,
    *,
    record_audit: bool = False,
):
    corpus = json.loads(corpus_path.read_text())
    texts = [f"{item['title']} {item['content']}" for item in corpus]
    vectorizer = TfidfVectorizer(stop_words="english").fit(texts)
    matrix = vectorizer.transform(texts)

    @tool("tavily_search_results_json")
    def baseline_frozen_search(query: str) -> list[dict]:
        """Search the frozen web corpus and return up to three relevant results."""
        scores = (matrix @ vectorizer.transform([query]).T).toarray().ravel()
        return [
            {"url": corpus[index]["url"], "content": corpus[index]["content"]}
            for index in scores.argsort()[-3:][::-1]
        ]

    security = dispatcher = audit = None
    if mode == "Baseline":
        frozen_search = baseline_frozen_search

    else:
        resource = sklearn_json_search_resource(corpus, top_k=3)
        frozen_search = tool(
            "tavily_search_results_json",
            description=baseline_frozen_search.description,
            args_schema=baseline_frozen_search.args_schema,
        )(broker_search)
        assert_tool_parity(baseline_frozen_search, frozen_search)
        security, audit = mediated_language_security(
            (frozen_search,),
            resources=(resource,),
            permissions={"tavily_search_results_json": (resource.permission("search"),)},
            trusted_nodes=(
                "planner",
                "prepare_agent",
                "agent_model",
                "capture_step",
                "replan",
            ),
            trusted_branches=(
                "agent_model:branch:route_agent",
                "replan:branch:should_end",
            ),
            record_audit=record_audit,
        )
    bound = llm().bind_tools([frozen_search])
    planner_prompt = ChatPromptTemplate.from_messages(
        [
            (
                "system",
                "For the given objective, come up with a simple step by step plan. "
                "This plan should involve individual tasks that yield the answer. Do not "
                "add superfluous steps. The final step should produce the final answer, "
                "and each step must contain all information needed.",
            ),
            ("placeholder", "{messages}"),
        ]
    )
    planner = planner_prompt | llm().with_structured_output(Plan)
    replanner_prompt = ChatPromptTemplate.from_template(
        """For the given objective, update the simple step by step plan.
Objective: {input}
Original plan: {plan}
Completed steps: {past_steps}
If no more steps are needed, respond to the user. Otherwise return only steps still needed."""
    )
    replanner = replanner_prompt | llm().with_structured_output(Act)

    def prepare_agent(state: PlanExecute):
        plan = state["plan"]
        plan_str = "\n".join(f"{i + 1}. {step}" for i, step in enumerate(plan))
        task = plan[0]
        task_formatted = f"For the following plan:\n{plan_str}\n\nExecute step 1: {task}"
        return {"messages": [("user", task_formatted)]}

    async def agent_model(state: PlanExecute):
        return {"messages": [await model_timing.ainvoke(bound, state["messages"])]}

    def route_agent(state: PlanExecute):
        return "agent_tools" if state["messages"][-1].tool_calls else "capture_step"

    def capture_step(state: PlanExecute):
        return {"past_steps": [(state["plan"][0], state["messages"][-1].content)]}

    async def plan_step(state: PlanExecute):
        plan = await model_timing.ainvoke(planner, {"messages": [("user", state["input"])]})
        steps = [step.strip() for step in plan.steps if step.strip()]
        if not steps:
            steps = [
                "Use the frozen search tool to find the facts needed for the objective, "
                "then answer the objective."
            ]
            return {"plan": steps, "termination_reason": "empty_plan_recovered"}
        return {"plan": steps}

    async def replan_step(state: PlanExecute):
        output = await model_timing.ainvoke(replanner, state)
        if isinstance(output.action, Response):
            response = output.action.response.strip()
            if response:
                return {"response": response, "termination_reason": "model_response"}
        else:
            steps = [step.strip() for step in output.action.steps if step.strip()]
            completed = {str(step).strip() for step, _ in state["past_steps"]}
            if steps and steps[0] not in completed and steps != state["plan"]:
                if len(state["past_steps"]) < 8:
                    return {"plan": steps}
        # A structured-output model can emit an empty/repeated plan forever.
        # Preserve its latest substantive answer as the application result so
        # this is scored as model accuracy, not a framework execution crash.
        response = str(state["past_steps"][-1][1]) if state["past_steps"] else ""
        return {"response": response, "termination_reason": "no_progress"}

    def should_end(state: PlanExecute):
        return END if state.get("response") else "prepare_agent"

    workflow = StateGraph(PlanExecute)
    workflow.add_node("planner", plan_step)
    workflow.add_node("prepare_agent", prepare_agent)
    workflow.add_node("agent_model", agent_model)
    if mode == "Argus":
        workflow.add_node("agent_tools", ToolNode([frozen_search], security=security))
    else:
        workflow.add_node("agent_tools", ToolNode([frozen_search]))
    workflow.add_node("capture_step", capture_step)
    workflow.add_node("replan", replan_step)
    workflow.add_edge(START, "planner")
    workflow.add_edge("planner", "prepare_agent")
    workflow.add_edge("prepare_agent", "agent_model")
    workflow.add_conditional_edges("agent_model", route_agent, ["agent_tools", "capture_step"])
    workflow.add_edge("agent_tools", "agent_model")
    workflow.add_edge("capture_step", "replan")
    workflow.add_conditional_edges("replan", should_end, ["prepare_agent", END])
    return workflow.compile(security=security), security, dispatcher, audit


async def run(args) -> None:
    if args.mode == "Argus":
        install_mac_policy('forbid(principal == slangGraph::User::"blocked", action, resource);')
    preparation_started = time.perf_counter()
    model_timing = ModelTiming()
    graph, security, dispatcher, audit = build(
        args.corpus,
        args.mode,
        model_timing,
        record_audit=args.audit,
    )
    config = {"recursion_limit": 50}
    if security is not None:
        config = with_principal(
            config,
            Principal("alice", frozenset(), frozenset(), "D3-resource-monitor"),
            modules=security.modules,
        )
    preparation_ms = (time.perf_counter() - preparation_started) * 1000
    status = "completed"
    error = None
    wait_for_parent()
    invocation_started = time.perf_counter()
    try:
        result = await graph.ainvoke(
            {
                "input": args.prompt,
                "plan": [],
                "past_steps": [],
                "response": "",
                "messages": [],
                "termination_reason": "",
            },
            config,
        )
    except BaseException as exc:
        status = "execution_error"
        error = f"{type(exc).__name__}: {exc}"
        result = {}
    invocation_ms = (time.perf_counter() - invocation_started) * 1000
    args.output.write_text(
        json.dumps(
            {
                "answer": result.get("response"),
                "isolation_route": "language" if security else "baseline",
                "state": result,
                "status": status,
                "error": error,
                "wall_ms": invocation_ms,
                "invocation_ms": invocation_ms,
                "preparation_ms": preparation_ms,
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
    parser = argparse.ArgumentParser()
    parser.add_argument("--corpus", type=Path, required=True)
    parser.add_argument("--prompt", required=True)
    parser.add_argument("--output", type=Path, required=True)
    parser.add_argument("--mode", choices=("Baseline", "Argus"), required=True)
    parser.add_argument("--audit", action="store_true")
    args = parser.parse_args()
    if args.audit and args.mode != "Argus":
        parser.error("--audit is only valid with --mode Argus")
    asyncio.run(run(args))
