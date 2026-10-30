"""Common one-file-read workload for direct and language-sandbox routes."""

from __future__ import annotations

import argparse
import json
import os
import subprocess
import sys
import tempfile
import time
import uuid
from dataclasses import replace
from pathlib import Path

from langchain_core.messages import AIMessage
from langchain_core.tools import tool
from langgraph.graph import START, MessagesState, StateGraph
from langgraph.prebuilt import ToolNode
from langgraph.prebuilt.security import (
    Principal,
    SqliteAuditSink,
    cedar_security,
    install_mac_policy,
    with_principal,
)
from langgraph.prebuilt.security.inprocess import ManifestAdmission, read_text
from langgraph.prebuilt.security.object_policy import (
    ObjectPolicyHostExecutor,
    _LanguageSandboxDispatcher,
)

POLICY = 'permit(principal == slangGraph::User::"alice", action, resource);'
MANDATORY = 'forbid(principal == slangGraph::User::"bob", action, resource);'
MANIFEST = "runs inprocess\nfs read @{path} need"


@tool("common_read")
def common_read(path: str) -> str:
    """Return one exact granted text file."""
    return read_text(path)


def write(stream, value: dict) -> None:
    stream.write(json.dumps(value, sort_keys=True) + "\n")
    stream.flush()


def session(
    output: Path,
    number: int,
    warmups: int,
    measured: int,
    audit_durability: str,
) -> None:
    os.sched_setaffinity(0, {min(os.sched_getaffinity(0))})
    install_mac_policy(MANDATORY)
    with tempfile.TemporaryDirectory(prefix="slg-common-language-") as folder:
        root = Path(folder)
        allowed = root / "allowed.txt"
        allowed.write_text("COMMON_FILE_VALUE")
        sink = SqliteAuditSink(root / "audit.sqlite", durability=audit_durability)
        setup_start = time.perf_counter_ns()
        security = replace(
            cedar_security(common_read, manifest=MANIFEST, policy=POLICY),
            audit_sink=sink,
            closed_admission=True,
        )
        node = ToolNode([common_read], security=security)
        builder = StateGraph(MessagesState)
        builder.add_node("tools", node)
        builder.add_edge(START, "tools")
        graph = builder.compile(security=security)
        setup_ms = (time.perf_counter_ns() - setup_start) / 1e6
        principal = Principal("alice", frozenset(), frozenset(), f"session-{number}")
        config = with_principal({}, principal, modules=security.modules)
        spans = {
            "authorization_ms": 0.0,
            "host_executor_ms": 0.0,
            "dispatch_ms": 0.0,
            "execution_ms": 0.0,
            "audit_ms": 0.0,
        }
        originals = {
            "authorize": ObjectPolicyHostExecutor._authorize,
            "host_invoke": ObjectPolicyHostExecutor.invoke,
            "dispatch": _LanguageSandboxDispatcher.invoke,
            "execute": ManifestAdmission.invoke,
            "audit": sink.write,
        }

        def timed(name, function):
            def wrapper(*args, **kwargs):
                started = time.perf_counter_ns()
                try:
                    return function(*args, **kwargs)
                finally:
                    spans[name] += (time.perf_counter_ns() - started) / 1e6

            return wrapper

        ObjectPolicyHostExecutor._authorize = timed("authorization_ms", originals["authorize"])
        ObjectPolicyHostExecutor.invoke = timed("host_executor_ms", originals["host_invoke"])
        _LanguageSandboxDispatcher.invoke = timed("dispatch_ms", originals["dispatch"])
        ManifestAdmission.invoke = timed("execution_ms", originals["execute"])
        sink.write = timed("audit_ms", originals["audit"])
        try:
            with output.open("x") as stream:
                write(
                    stream,
                    {
                        "kind": "setup",
                        "route": "language",
                        "session": number,
                        "audit_durability": audit_durability,
                        "setup_ms": setup_ms,
                        "manifest": MANIFEST,
                        "policy": POLICY,
                        "mandatory_policy": MANDATORY,
                    },
                )
                for index in range(1 + warmups + measured):
                    phase = (
                        "first_use" if index == 0 else "warmup" if index <= warmups else "measured"
                    )
                    for key in spans:
                        spans[key] = 0.0
                    started = time.perf_counter_ns()
                    result = graph.invoke(
                        {
                            "messages": [
                                AIMessage(
                                    content="",
                                    tool_calls=[
                                        {
                                            "name": "common_read",
                                            "args": {"path": str(allowed)},
                                            "id": uuid.uuid4().hex,
                                        }
                                    ],
                                )
                            ]
                        },
                        config=config,
                    )
                    elapsed = (time.perf_counter_ns() - started) / 1e6
                    activation = max(0.0, spans["dispatch_ms"] - spans["execution_ms"])
                    accounted = (
                        spans["authorization_ms"]
                        + activation
                        + spans["execution_ms"]
                        + spans["audit_ms"]
                    )
                    host_bridge = (
                        spans["host_executor_ms"] - spans["authorization_ms"] - spans["dispatch_ms"]
                    )
                    graph_and_toolnode = elapsed - accounted - host_bridge
                    write(
                        stream,
                        {
                            "kind": "call",
                            "route": "language",
                            "session": number,
                            "round": index,
                            "phase": phase,
                            "elapsed_ms": elapsed,
                            "authorization_ms": spans["authorization_ms"],
                            "policy_lowering_ms": 0.0,
                            "activation_ms": activation,
                            "execution_ms": spans["execution_ms"],
                            "mediator_transport_ms": 0.0,
                            "lean_ms": 0.0,
                            "audit_ms": spans["audit_ms"],
                            "cleanup_ms": 0.0,
                            "framework_residual_ms": elapsed - accounted,
                            "host_bridge_ms": host_bridge,
                            "graph_and_toolnode_ms": graph_and_toolnode,
                            "residual_partition_error_ms": 0.0,
                            "valid": "COMMON_FILE_VALUE" in result["messages"][-1].content,
                        },
                    )
                    started = time.perf_counter_ns()
                    value = allowed.read_text()
                    direct = (time.perf_counter_ns() - started) / 1e6
                    write(
                        stream,
                        {
                            "kind": "call",
                            "route": "direct",
                            "session": number,
                            "round": index,
                            "phase": phase,
                            "elapsed_ms": direct,
                            "execution_ms": direct,
                            "valid": value == "COMMON_FILE_VALUE",
                        },
                    )
        finally:
            ObjectPolicyHostExecutor._authorize = originals["authorize"]
            ObjectPolicyHostExecutor.invoke = originals["host_invoke"]
            _LanguageSandboxDispatcher.invoke = originals["dispatch"]
            ManifestAdmission.invoke = originals["execute"]
            sink.write = originals["audit"]
            sink.close()


def run(
    output: Path,
    sessions: int,
    warmups: int,
    measured: int,
    audit_durability: str,
) -> None:
    output.mkdir(parents=True, exist_ok=False)
    for number in range(sessions):
        log = output / f"session-{number}.log"
        with log.open("x") as stream:
            subprocess.run(
                [
                    sys.executable,
                    __file__,
                    "--output",
                    str(output / f"session-{number}.jsonl"),
                    "--session",
                    str(number),
                    "--warmups",
                    str(warmups),
                    "--measured",
                    str(measured),
                    "--audit-durability",
                    audit_durability,
                ],
                stdout=stream,
                stderr=subprocess.STDOUT,
                timeout=600,
                check=True,
            )


if __name__ == "__main__":
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--output", required=True, type=Path)
    parser.add_argument("--sessions", default=5, type=int)
    parser.add_argument("--warmups", default=5, type=int)
    parser.add_argument("--measured", default=20, type=int)
    parser.add_argument("--session", type=int)
    parser.add_argument(
        "--audit-durability",
        choices=("synchronous", "trusted-async"),
        default="trusted-async",
    )
    arguments = parser.parse_args()
    if arguments.session is None:
        run(
            arguments.output,
            arguments.sessions,
            arguments.warmups,
            arguments.measured,
            arguments.audit_durability,
        )
    else:
        session(
            arguments.output,
            arguments.session,
            arguments.warmups,
            arguments.measured,
            arguments.audit_durability,
        )
