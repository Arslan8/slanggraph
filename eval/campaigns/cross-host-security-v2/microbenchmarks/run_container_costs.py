"""Measure the production Docker route in five independent process sessions."""

from __future__ import annotations

import argparse
import hashlib
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
    LinuxToolSpec,
    Principal,
    SqliteAuditSink,
    cedar_security,
    install_mac_policy,
    with_principal,
)
from langgraph.prebuilt.security.container import DockerObjectDispatcher
from langgraph.prebuilt.security.object_policy import ObjectPolicyHostExecutor

IMAGE = "sha256:3bcfa1622e24814afee022c71236dadd92e31a5fff41ad99a23925bc98311504"
IMAGE = os.environ.get("ARGUS_EVAL_DOCKER_IMAGE", IMAGE)
POLICY = 'permit(principal == slangGraph::User::"alice", action, resource);'
MANDATORY = 'forbid(principal == slangGraph::User::"bob", action, resource);'
SOURCE = """from pathlib import Path

def run(path):
    return Path(path).read_text()
"""


@tool("container_read")
def container_read(path: str) -> str:
    """Read one exact file through the native container route."""
    raise AssertionError("unconfined callback executed")


def _write(stream, row: dict) -> None:
    stream.write(json.dumps(row, sort_keys=True) + "\n")
    stream.flush()


def run_session(output: Path, session: int, warmups: int, measured: int) -> None:
    """Run one statistically independent process session."""
    output.parent.mkdir(parents=True, exist_ok=True)
    os.sched_setaffinity(0, {min(os.sched_getaffinity(0))})
    install_mac_policy(MANDATORY)
    with tempfile.TemporaryDirectory(prefix="slg-container-cost-") as folder:
        root = Path(folder)
        os.chmod(root, 0o700)
        source = root / "tool.py"
        allowed = root / "allowed.txt"
        source.write_text(SOURCE)
        allowed.write_text("AUTHORIZED_CURRENT_ROUTE")
        expected = allowed.read_text()
        digest = hashlib.sha256(source.read_bytes()).hexdigest()
        setup_start = time.perf_counter_ns()
        dispatcher = DockerObjectDispatcher(
            {"container_read": LinuxToolSpec("container_read:run", source, digest)},
            image=IMAGE,
            private_roots=(root,),
        )
        dispatcher_setup_ms = (time.perf_counter_ns() - setup_start) / 1e6
        sink = SqliteAuditSink(root / "audit.sqlite")

        admission_start = time.perf_counter_ns()
        security = cedar_security(
            container_read,
            manifest="runs linux\nfs read @{path} need",
            policy=POLICY,
            dispatcher=dispatcher,
        )
        security = replace(
            security,
            audit_sink=sink,
            closed_admission=True,
        )
        node = ToolNode([container_read], security=security)
        builder = StateGraph(MessagesState)
        builder.add_node("tools", node)
        builder.add_edge(START, "tools")
        graph = builder.compile(security=security)
        admission_setup_ms = (time.perf_counter_ns() - admission_start) / 1e6

        principal = Principal("alice", frozenset(), frozenset(), f"session-{session}")
        config = with_principal({}, principal, modules=security.modules)
        spans = {"authorization_ms": 0.0, "audit_ms": 0.0}
        dispatch = {"start_wall": 0.0, "elapsed_ms": 0.0}

        original_authorize = ObjectPolicyHostExecutor._authorize

        def timed_authorize(self, *args, **kwargs):
            start = time.perf_counter_ns()
            try:
                return original_authorize(self, *args, **kwargs)
            finally:
                spans["authorization_ms"] += (time.perf_counter_ns() - start) / 1e6

        ObjectPolicyHostExecutor._authorize = timed_authorize
        original_dispatch = dispatcher.invoke

        def timed_dispatch(*args, **kwargs):
            dispatch["start_wall"] = time.time()
            start = time.perf_counter_ns()
            try:
                return original_dispatch(*args, **kwargs)
            finally:
                dispatch["elapsed_ms"] = (time.perf_counter_ns() - start) / 1e6

        dispatcher.invoke = timed_dispatch
        original_audit = sink.write

        def timed_audit(*args, **kwargs):
            start = time.perf_counter_ns()
            try:
                return original_audit(*args, **kwargs)
            finally:
                spans["audit_ms"] += (time.perf_counter_ns() - start) / 1e6

        sink.write = timed_audit
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
                        "image": IMAGE,
                        "artifact_sha256": digest,
                    },
                )
                for index in range(1 + warmups + measured):
                    phase = (
                        "first_use" if index == 0 else "warmup" if index <= warmups else "measured"
                    )
                    spans.update(authorization_ms=0.0, audit_ms=0.0)
                    dispatch.update(start_wall=0.0, elapsed_ms=0.0)
                    call_id = f"container-{session}-{index}-{uuid.uuid4().hex}"
                    request = {
                        "messages": [
                            AIMessage(
                                content="",
                                tool_calls=[
                                    {
                                        "name": "container_read",
                                        "args": {"path": str(allowed)},
                                        "id": call_id,
                                    }
                                ],
                            )
                        ]
                    }
                    start = time.perf_counter_ns()
                    result = graph.invoke(request, config=config)
                    elapsed_ms = (time.perf_counter_ns() - start) / 1e6
                    content = result["messages"][-1].content
                    valid = expected in content
                    record = dispatcher.execution_records()[-1]
                    activation_ms = max(
                        0.0,
                        (record["activated_at"] - dispatch["start_wall"]) * 1000,
                    )
                    worker_ms = max(0.0, dispatch["elapsed_ms"] - activation_ms)
                    accounted_ms = (
                        spans["authorization_ms"] + activation_ms + worker_ms + spans["audit_ms"]
                    )
                    _write(
                        stream,
                        {
                            "kind": "call",
                            "route": "container",
                            "session": session,
                            "round": index,
                            "phase": phase,
                            "elapsed_ms": elapsed_ms,
                            "authorization_ms": spans["authorization_ms"],
                            "activation_ms": activation_ms,
                            "execution_ms": worker_ms,
                            "audit_ms": spans["audit_ms"],
                            "framework_residual_ms": elapsed_ms - accounted_ms,
                            "container_id": record["container_id"],
                            "reused": record["reused"],
                            "valid": valid,
                            "audit_records": len(sink.records()),
                        },
                    )
                    if not valid:
                        raise RuntimeError("container result mismatch")

                    start = time.perf_counter_ns()
                    direct = allowed.read_text()
                    direct_ms = (time.perf_counter_ns() - start) / 1e6
                    _write(
                        stream,
                        {
                            "kind": "call",
                            "route": "direct-container",
                            "session": session,
                            "round": index,
                            "phase": phase,
                            "elapsed_ms": direct_ms,
                            "valid": direct == expected,
                        },
                    )
                container_id = dispatcher.execution_records()[-1]["container_id"]
                cleanup_start = time.perf_counter_ns()
                dispatcher.close()
                cleanup_ms = (time.perf_counter_ns() - cleanup_start) / 1e6
                probe = subprocess.run(
                    [
                        "docker",
                        "ps",
                        "-a",
                        "--no-trunc",
                        "--filter",
                        f"id={container_id}",
                        "--format",
                        "{{.ID}}",
                    ],
                    check=True,
                    capture_output=True,
                    text=True,
                    timeout=10,
                )
                _write(
                    stream,
                    {
                        "kind": "cleanup",
                        "session": session,
                        "cleanup_ms": cleanup_ms,
                        "container_id": container_id,
                        "removal_confirmed": not probe.stdout.strip(),
                    },
                )
        finally:
            ObjectPolicyHostExecutor._authorize = original_authorize
            if not dispatcher._closed:
                dispatcher.close()


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
        print(f"container session {session} complete", flush=True)


if __name__ == "__main__":
    main()
