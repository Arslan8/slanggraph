"""Measure a fully protected current object-broker route in fresh sessions."""

from __future__ import annotations

import argparse
import hashlib
import json
import os
import sqlite3
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
    SQLITE_RECORD_SCHEMA,
    LinuxToolSpec,
    ObjectBrokerDispatcher,
    Principal,
    SqliteAuditSink,
    cedar_security,
    install_mac_policy,
    sqlite_record_mediator,
    with_principal,
)
from langgraph.prebuilt.security.landlock import LandlockSandboxExecutor
from langgraph.prebuilt.security.mediators.records import RECORDS
from langgraph.prebuilt.security.object_policy import ObjectPolicyHostExecutor

POLICY = (
    'permit(principal == slangGraph::User::"alice", '
    'action == slangGraph::Action::"db_record::read", resource) '
    'when { resource.selector == "notes/alice" };'
)
MANDATORY = 'forbid(principal == slangGraph::User::"bob", action, resource);'
MANIFEST = "runs linux\ndb_record read @{record} need\nreturns sensitive"
SOURCE = """from langgraph.prebuilt.security.mediators.records import records

def run(record):
    return records.read(record)
"""


@tool("broker_read")
def broker_read(record: str) -> dict:
    """Read one exact database record through the parent-owned broker."""
    raise AssertionError("unconfined callback executed")


def _write(stream, row: dict) -> None:
    stream.write(json.dumps(row, sort_keys=True) + "\n")
    stream.flush()


def run_session(output: Path, session: int, warmups: int, measured: int) -> None:
    """Run one independent process session."""
    output.parent.mkdir(parents=True, exist_ok=True)
    os.sched_setaffinity(0, {min(os.sched_getaffinity(0))})
    install_mac_policy(MANDATORY)
    with tempfile.TemporaryDirectory(prefix="slg-broker-cost-") as folder:
        root = Path(folder)
        source = root / "worker.py"
        database = root / "records.sqlite"
        source.write_text(SOURCE)
        with sqlite3.connect(database) as connection:
            connection.execute(SQLITE_RECORD_SCHEMA)
            connection.executemany(
                "INSERT INTO records VALUES (?, ?)",
                [("alice", "AUTHORIZED_RECORD"), ("bob", "BOB_PRIVATE")],
            )
        mediator_spans = {"operation_ms": 0.0}
        mediator = sqlite_record_mediator(database, database_id="notes")
        original_mediator_invoke = mediator.invoke

        def timed_mediator_invoke(*args, **kwargs):
            started = time.perf_counter_ns()
            try:
                return original_mediator_invoke(*args, **kwargs)
            finally:
                mediator_spans["operation_ms"] += (time.perf_counter_ns() - started) / 1e6

        mediator = replace(mediator, invoke=timed_mediator_invoke)
        setup_start = time.perf_counter_ns()
        dispatcher = ObjectBrokerDispatcher(
            {
                "broker_read": LinuxToolSpec(
                    "broker_worker:run",
                    source,
                    hashlib.sha256(source.read_bytes()).hexdigest(),
                )
            },
            mediators=(mediator,),
            runtime_roots=tuple(
                Path(item).resolve() for item in sys.path if item and Path(item).is_dir()
            ),
        )
        dispatcher_setup_ms = (time.perf_counter_ns() - setup_start) / 1e6
        sink = SqliteAuditSink(root / "audit.sqlite")
        admission_start = time.perf_counter_ns()
        security = cedar_security(
            broker_read,
            classes=RECORDS.class_declaration(),
            manifest=MANIFEST,
            policy=POLICY,
            dispatcher=dispatcher,
        )
        security = replace(security, audit_sink=sink, closed_admission=True)
        node = ToolNode([broker_read], security=security)
        builder = StateGraph(MessagesState)
        builder.add_node("tools", node)
        builder.add_edge(START, "tools")
        graph = builder.compile(security=security)
        admission_setup_ms = (time.perf_counter_ns() - admission_start) / 1e6
        principal = Principal("alice", frozenset(), frozenset(), f"session-{session}")
        config = with_principal({}, principal, modules=security.modules)
        spans = {"authorization_ms": 0.0, "audit_ms": 0.0, "cleanup_ms": 0.0}
        dispatch = {"start_wall": 0.0, "elapsed_ms": 0.0, "activated_at": 0.0}
        originals = {
            "authorize": ObjectPolicyHostExecutor._authorize,
            "dispatch": dispatcher.invoke,
            "cleanup": LandlockSandboxExecutor._cleanup_worker,
            "audit": sink.write,
        }

        def timed(name, function):
            def wrapper(*args, **kwargs):
                start = time.perf_counter_ns()
                try:
                    return function(*args, **kwargs)
                finally:
                    spans[name] += (time.perf_counter_ns() - start) / 1e6

            return wrapper

        ObjectPolicyHostExecutor._authorize = timed("authorization_ms", originals["authorize"])
        LandlockSandboxExecutor._cleanup_worker = timed("cleanup_ms", originals["cleanup"])
        sink.write = timed("audit_ms", originals["audit"])

        def timed_dispatch(*args, **kwargs):
            dispatch["start_wall"] = time.time()
            start = time.perf_counter_ns()
            result = originals["dispatch"](*args, **kwargs)
            dispatch["elapsed_ms"] = (time.perf_counter_ns() - start) / 1e6
            dispatch["activated_at"] = max(item.activated_at for item in result.receipt.evidence)
            return result

        dispatcher.invoke = timed_dispatch
        try:
            with output.open("x") as stream:
                _write(
                    stream,
                    {
                        "kind": "setup",
                        "session": session,
                        "cpu_affinity": sorted(os.sched_getaffinity(0)),
                        "dispatcher_setup_ms": dispatcher_setup_ms,
                        "admission_setup_ms": admission_setup_ms,
                        "closed_admission": True,
                        "mandatory_policy": MANDATORY,
                        "policy": POLICY,
                        "manifest": MANIFEST,
                    },
                )
                for index in range(1 + warmups + measured):
                    phase = (
                        "first_use" if index == 0 else "warmup" if index <= warmups else "measured"
                    )
                    spans.update(authorization_ms=0.0, audit_ms=0.0, cleanup_ms=0.0)
                    mediator_spans["operation_ms"] = 0.0
                    dispatch.update(start_wall=0.0, elapsed_ms=0.0, activated_at=0.0)
                    request = {
                        "messages": [
                            AIMessage(
                                content="",
                                tool_calls=[
                                    {
                                        "name": "broker_read",
                                        "args": {"record": "notes/alice"},
                                        "id": f"broker-{session}-{index}-{uuid.uuid4().hex}",
                                    }
                                ],
                            )
                        ]
                    }
                    start = time.perf_counter_ns()
                    result = graph.invoke(request, config=config)
                    elapsed_ms = (time.perf_counter_ns() - start) / 1e6
                    content = result["messages"][-1].content
                    activation_ms = max(
                        0.0, (dispatch["activated_at"] - dispatch["start_wall"]) * 1000
                    )
                    broker_after_activation_ms = max(
                        0.0,
                        dispatch["elapsed_ms"] - activation_ms - spans["cleanup_ms"],
                    )
                    mediator_transport_ms = max(
                        0.0,
                        broker_after_activation_ms - mediator_spans["operation_ms"],
                    )
                    accounted = (
                        spans["authorization_ms"]
                        + activation_ms
                        + mediator_transport_ms
                        + mediator_spans["operation_ms"]
                        + spans["audit_ms"]
                        + spans["cleanup_ms"]
                    )
                    _write(
                        stream,
                        {
                            "kind": "call",
                            "route": "broker",
                            "session": session,
                            "round": index,
                            "phase": phase,
                            "elapsed_ms": elapsed_ms,
                            "authorization_ms": spans["authorization_ms"],
                            "activation_ms": activation_ms,
                            "execution_ms": mediator_spans["operation_ms"],
                            "mediator_transport_ms": mediator_transport_ms,
                            "audit_ms": spans["audit_ms"],
                            "cleanup_ms": spans["cleanup_ms"],
                            "framework_residual_ms": elapsed_ms - accounted,
                            "valid": "AUTHORIZED_RECORD" in content,
                            "audit_records": len(sink.records()),
                            "broker_records": len(dispatcher.audit_records()),
                        },
                    )
                    start = time.perf_counter_ns()
                    with sqlite3.connect(database) as connection:
                        direct = connection.execute(
                            "SELECT value FROM records WHERE key='alice'"
                        ).fetchone()[0]
                    direct_ms = (time.perf_counter_ns() - start) / 1e6
                    _write(
                        stream,
                        {
                            "kind": "call",
                            "route": "direct-broker",
                            "session": session,
                            "round": index,
                            "phase": phase,
                            "elapsed_ms": direct_ms,
                            "valid": direct == "AUTHORIZED_RECORD",
                        },
                    )
        finally:
            ObjectPolicyHostExecutor._authorize = originals["authorize"]
            LandlockSandboxExecutor._cleanup_worker = originals["cleanup"]


def main() -> None:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--output", type=Path, required=True)
    parser.add_argument("--sessions", type=int, default=5)
    parser.add_argument("--warmups", type=int, default=10)
    parser.add_argument("--measured", type=int, default=20)
    parser.add_argument("--session", type=int)
    args = parser.parse_args()
    if args.session is not None:
        run_session(args.output, args.session, args.warmups, args.measured)
        return
    args.output.mkdir(parents=True, exist_ok=False)
    for session in range(args.sessions):
        command = [
            sys.executable,
            __file__,
            "--output",
            str(args.output / f"session-{session}.jsonl"),
            "--warmups",
            str(args.warmups),
            "--measured",
            str(args.measured),
            "--session",
            str(session),
        ]
        log = args.output / f"session-{session}.log"
        with log.open("x") as stream:
            subprocess.run(command, check=True, stdout=stream, stderr=subprocess.STDOUT)
        print(f"broker session {session} complete", flush=True)


if __name__ == "__main__":
    main()
