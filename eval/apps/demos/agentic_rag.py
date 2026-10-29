# ruff: noqa: E501
"""Executable extraction of D2, the complete agentic-RAG graph."""

from __future__ import annotations

import argparse
import dataclasses
import enum
import hashlib
import html
import json
import sys
import time
from collections.abc import Sequence
from html.parser import HTMLParser
from pathlib import Path
from typing import Annotated, Literal, TypedDict

from langchain_core.messages import BaseMessage, HumanMessage
from langchain_core.prompts import PromptTemplate
from langchain_core.tools import tool
from langchain_openai import ChatOpenAI
from langgraph.graph import END, START, StateGraph
from langgraph.graph.message import add_messages
from langgraph.prebuilt import ToolNode
from langgraph.prebuilt.security import (
    LinuxToolSpec,
    ObjectBrokerDispatcher,
    Principal,
    install_mac_policy,
    with_principal,
)
from pydantic import BaseModel, Field
from resource_monitors.api import RETRIEVER
from resource_monitors.backends import ExactBrokerMediator, TFIDFRetrieverBackend
from resource_monitors.retriever_worker import retrieve_blog_posts as broker_retrieve
from resource_monitors.security import monitored_security
from sklearn.feature_extraction.text import TfidfVectorizer
from timing import ModelTiming, assert_tool_parity

MODEL = {
    "name": "qwen3:8b",
    "base_url": "http://127.0.0.1:11434/v1",
    "temperature": 0,
    "seed": 20261005,
    "reasoning_effort": "none",
}


class TextExtractor(HTMLParser):
    def __init__(self):
        super().__init__()
        self.parts: list[str] = []

    def handle_data(self, data: str) -> None:
        if data.strip():
            self.parts.append(data.strip())


class AgentState(TypedDict):
    messages: Annotated[Sequence[BaseMessage], add_messages]


def model() -> ChatOpenAI:
    return ChatOpenAI(
        model=MODEL["name"],
        base_url=MODEL["base_url"],
        api_key="ollama",
        temperature=MODEL["temperature"],
        seed=MODEL["seed"],
        timeout=600,
        max_retries=0,
        reasoning_effort=MODEL["reasoning_effort"],
    )


def chunks(paths: list[Path]) -> list[str]:
    result = []
    for path in paths:
        parser = TextExtractor()
        parser.feed(path.read_text(errors="replace"))
        words = html.unescape(" ".join(parser.parts)).split()
        for start in range(0, len(words), 60):
            result.append(" ".join(words[start : start + 100]))
    return result


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


def build(paths: list[Path], mode: str, model_timing: ModelTiming):
    documents = chunks(paths)
    vectorizer = TfidfVectorizer(stop_words="english").fit(documents)
    matrix = vectorizer.transform(documents)

    @tool("retrieve_blog_posts")
    def baseline_retrieve_blog_posts(query: str) -> str:
        """Search and return information about the frozen blog posts."""
        scores = (matrix @ vectorizer.transform([query]).T).toarray().ravel()
        indices = scores.argsort()[-5:][::-1]
        return "\n\n".join(documents[index] for index in indices)

    security = dispatcher = audit = None
    if mode == "Baseline":
        retrieve_blog_posts = baseline_retrieve_blog_posts

    else:
        resource = RETRIEVER.bind(
            implementation=TFIDFRetrieverBackend(documents),
            mediator=ExactBrokerMediator(
                "query-only access to the frozen TF-IDF index",
                "eval/tests/test_demo_resource_monitors.py",
                paths,
            ),
        )
        worker = Path(__file__).with_name("resource_monitors") / "retriever_worker.py"
        dispatcher = ObjectBrokerDispatcher(
            {
                "retrieve_blog_posts": LinuxToolSpec(
                    "resource_monitors.retriever_worker:retrieve_blog_posts",
                    worker,
                    hashlib.sha256(worker.read_bytes()).hexdigest(),
                )
            },
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
        retrieve_blog_posts = tool(
            "retrieve_blog_posts",
            description=baseline_retrieve_blog_posts.description,
            args_schema=baseline_retrieve_blog_posts.args_schema,
        )(broker_retrieve)
        assert_tool_parity(baseline_retrieve_blog_posts, retrieve_blog_posts)
        security, audit = monitored_security(
            (retrieve_blog_posts,),
            dispatcher=dispatcher,
            resources=(resource,),
            permissions={"retrieve_blog_posts": (resource.permission("search"),)},
            trusted_nodes=("agent", "rewrite", "generate"),
            trusted_branches=(
                "agent:branch:route_tools",
                "retrieve:branch:grade_documents",
            ),
        )

    tools = [retrieve_blog_posts]

    def grade_documents(state) -> Literal["generate", "rewrite"]:
        class Grade(BaseModel):
            binary_score: str = Field(description="Relevance score 'yes' or 'no'")

        prompt = PromptTemplate(
            template="""You are a grader assessing relevance of a retrieved document to a user question.
Here is the retrieved document:\n\n{context}\n\nHere is the user question: {question}
If the document contains keyword(s) or semantic meaning related to the user question, grade it as relevant.
Give a binary score 'yes' or 'no' score to indicate whether the document is relevant to the question.""",
            input_variables=["context", "question"],
        )
        chain = prompt | model().with_structured_output(Grade)
        messages = state["messages"]
        score = model_timing.invoke(
            chain,
            {"question": messages[0].content, "context": messages[-1].content}
        ).binary_score
        return "generate" if score == "yes" else "rewrite"

    def agent(state):
        response = model_timing.invoke(model().bind_tools(tools), state["messages"])
        return {"messages": [response]}

    def rewrite(state):
        question = state["messages"][0].content
        response = model_timing.invoke(
            model(),
            [
                HumanMessage(
                    content=f"""Look at the input and reason about the underlying semantic intent.
Here is the initial question:\n-------\n{question}\n-------\nFormulate an improved question:"""
                )
            ]
        )
        return {"messages": [response]}

    def generate(state):
        messages = state["messages"]
        prompt = PromptTemplate.from_template(
            """You are an assistant for question-answering tasks. Use the following pieces of retrieved context to answer the question. If you don't know the answer, say that you don't know. Use three sentences maximum and keep the answer concise.
Question: {question}
Context: {context}
Answer:"""
        )
        response = model_timing.invoke(
            prompt | model(),
            {"context": messages[-1].content, "question": messages[0].content}
        )
        return {"messages": [response]}

    workflow = StateGraph(AgentState)
    workflow.add_node("agent", agent)
    workflow.add_node("retrieve", ToolNode([retrieve_blog_posts], security=security))
    workflow.add_node("rewrite", rewrite)
    workflow.add_node("generate", generate)
    workflow.add_edge(START, "agent")

    def route_tools(state):
        return "tools" if state["messages"][-1].tool_calls else END

    workflow.add_conditional_edges("agent", route_tools, {"tools": "retrieve", END: END})
    workflow.add_conditional_edges("retrieve", grade_documents)
    workflow.add_edge("generate", END)
    workflow.add_edge("rewrite", "agent")
    return workflow.compile(security=security), security, dispatcher, audit


def main() -> None:
    parser = argparse.ArgumentParser()
    parser.add_argument("--documents", nargs=3, type=Path, required=True)
    parser.add_argument("--prompt", required=True)
    parser.add_argument("--output", type=Path, required=True)
    parser.add_argument("--mode", choices=("Baseline", "Argus"), required=True)
    args = parser.parse_args()
    if args.mode == "Argus":
        install_mac_policy('forbid(principal == slangGraph::User::"blocked", action, resource);')
    started = time.perf_counter()
    model_timing = ModelTiming()
    graph, security, dispatcher, audit = build(args.documents, args.mode, model_timing)
    config = {"recursion_limit": 50}
    if security is not None:
        config = with_principal(
            config,
            Principal("alice", frozenset(), frozenset(), "D2-resource-monitor"),
            modules=security.modules,
        )
    result = graph.invoke({"messages": [("user", args.prompt)]}, config)
    args.output.write_text(
        json.dumps(
            {
                "answer": str(result["messages"][-1].content),
                "messages": [message.model_dump() for message in result["messages"]],
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
