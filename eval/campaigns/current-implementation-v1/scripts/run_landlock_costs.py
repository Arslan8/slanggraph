"""Measure the current Lean-backed Linux/Landlock worker in fresh sessions."""

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
from pathlib import Path
from typing import Literal

from langchain_core.messages import AIMessage
from langchain_core.tools import tool
from langgraph.graph import START, MessagesState, StateGraph
from langgraph.prebuilt import ToolNode
from langgraph.prebuilt.security import (
    DacOverrides,
    Effect,
    LeanLifecycleChecker,
    LinuxSandboxExecutor,
    LinuxToolSpec,
    Principal,
    ResourceArg,
    SecurityConfig,
    SqliteAuditSink,
    dac,
    effects,
    parse_profiles,
    with_principal,
)
from langgraph.prebuilt.security.audit import SqliteAuditSink as AuditClass
from langgraph.prebuilt.security.cedar import CedarPolicyBackend
from langgraph.prebuilt.security.lean_lifecycle import (
    LeanLifecycleChecker as CheckerClass,
)
from langgraph.prebuilt.security.lean_lifecycle import (
    LeanLifecycleSession,
)

LEAN_BINARY = "/data/langgraph/proofs/worker-route/.lake/build/bin/workerRoute"
LEAN_SHA256 = "6097be9b7b84639959c7a0b9de31c79f23486e9f01bf1b6de575dfab25c7cb08"
SOURCE = """from pathlib import Path

def run(path):
    return Path(path).read_text()
"""


@tool("landlock_read")
@dac(owner="analyst", grants={"analyst": "x", "*": "-"})
@effects(Effect.READ, resources=[ResourceArg("path", "path", "realpath")])
def landlock_read(path: str) -> str:
    """Read an exact granted file in a fresh Linux worker."""
    raise AssertionError("unconfined callback executed")


def _write(stream, row: dict) -> None:
    stream.write(json.dumps(row, sort_keys=True) + "\n")
    stream.flush()


def run_session(
    output: Path,
    session: int,
    warmups: int,
    measured: int,
    optimization_level: Literal["no", "normal", "aggressive"],
) -> None:
    """Run one independent process session."""
    output.parent.mkdir(parents=True, exist_ok=True)
    os.sched_setaffinity(0, {min(os.sched_getaffinity(0))})
    with tempfile.TemporaryDirectory(prefix="slg-landlock-cost-") as folder:
        root = Path(folder)
        source = root / "tool.py"
        allowed = root / "allowed.txt"
        source.write_text(SOURCE)
        allowed.write_text("AUTHORIZED_LANDLOCK_ROUTE")
        expected = allowed.read_text()
        profile_text = f"""tool landlock_read {{
 owner analyst
 grant analyst: call
 runs linux
 syscalls @minimal
 fs read {allowed} need
}}
principal alice {{
 roles analyst
 fs read {allowed}
}}
"""
        profiles = parse_profiles(profile_text, source="landlock-cost.slp")
        checker_start = time.perf_counter_ns()
        checker = LeanLifecycleChecker(LEAN_BINARY, LEAN_SHA256)
        checker_setup_ms = (time.perf_counter_ns() - checker_start) / 1e6
        executor_start = time.perf_counter_ns()
        policy_backend = CedarPolicyBackend(optimization_level=optimization_level)
        executor = LinuxSandboxExecutor(
            profiles,
            {
                "landlock_read": LinuxToolSpec(
                    "landlock_tool:run",
                    source,
                    hashlib.sha256(source.read_bytes()).hexdigest(),
                )
            },
            runtime_roots=(root,),
            default_wall_timeout_s=10,
            lifecycle_checker=checker,
            policy_backend=policy_backend,
        )
        executor_setup_ms = (time.perf_counter_ns() - executor_start) / 1e6
        sink = SqliteAuditSink(root / "audit.sqlite")
        admission_start = time.perf_counter_ns()
        security = SecurityConfig(
            dac_overrides=DacOverrides(profiles=profiles.tools),
            host_executor=executor,
            audit_sink=sink,
            closed_admission=True,
        )
        node = ToolNode([landlock_read], security=security)
        builder = StateGraph(MessagesState)
        builder.add_node("tools", node)
        builder.add_edge(START, "tools")
        graph = builder.compile(security=security)
        admission_setup_ms = (time.perf_counter_ns() - admission_start) / 1e6
        principal = Principal("alice", frozenset({"analyst"}), frozenset(), f"session-{session}")
        config = with_principal({}, principal, modules=security.modules)
        spans = {
            "authorization_ms": 0.0,
            "lean_ms": 0.0,
            "cleanup_ms": 0.0,
            "audit_ms": 0.0,
            "worker_ms": 0.0,
            "prego_ms": 0.0,
            "lean_at_worker_start_ms": 0.0,
            "lean_at_go_ms": 0.0,
        }
        originals = {
            "authorize": CedarPolicyBackend.filter,
            "lean": CheckerClass._require,
            "cleanup": LinuxSandboxExecutor._cleanup_worker,
            "worker": LinuxSandboxExecutor._run_worker,
            "go": LeanLifecycleSession.permit_go,
            "audit": AuditClass.write,
        }

        def timed(name, function):
            def wrapper(*args, **kwargs):
                start = time.perf_counter_ns()
                try:
                    return function(*args, **kwargs)
                finally:
                    spans[name] += (time.perf_counter_ns() - start) / 1e6

            return wrapper

        CedarPolicyBackend.filter = timed("authorization_ms", originals["authorize"])
        CheckerClass._require = timed("lean_ms", originals["lean"])
        LinuxSandboxExecutor._cleanup_worker = timed("cleanup_ms", originals["cleanup"])
        AuditClass.write = timed("audit_ms", originals["audit"])

        def timed_worker(*args, **kwargs):
            spans["lean_at_worker_start_ms"] = spans["lean_ms"]
            spans["worker_started_ns"] = time.perf_counter_ns()
            try:
                return originals["worker"](*args, **kwargs)
            finally:
                spans["worker_ms"] += (time.perf_counter_ns() - spans["worker_started_ns"]) / 1e6

        def timed_go(*args, **kwargs):
            result = originals["go"](*args, **kwargs)
            spans["prego_ms"] = (time.perf_counter_ns() - spans["worker_started_ns"]) / 1e6
            spans["lean_at_go_ms"] = spans["lean_ms"]
            return result

        LinuxSandboxExecutor._run_worker = timed_worker
        LeanLifecycleSession.permit_go = timed_go
        try:
            with output.open("x") as stream:
                _write(
                    stream,
                    {
                        "kind": "setup",
                        "session": session,
                        "cpu_affinity": sorted(os.sched_getaffinity(0)),
                        "checker_setup_ms": checker_setup_ms,
                        "executor_setup_ms": executor_setup_ms,
                        "admission_setup_ms": admission_setup_ms,
                        "closed_admission": True,
                        "operator_runtime_mac": False,
                        "runtime_mac_limitation": "mac:tool_requires_object_authorization",
                        "profile": profile_text,
                        "lean_binary": LEAN_BINARY,
                        "lean_sha256": LEAN_SHA256,
                        "cedar_optimization_level": optimization_level,
                    },
                )
                for index in range(1 + warmups + measured):
                    phase = (
                        "first_use" if index == 0 else "warmup" if index <= warmups else "measured"
                    )
                    for name in spans:
                        spans[name] = 0.0
                    request = {
                        "messages": [
                            AIMessage(
                                content="",
                                tool_calls=[
                                    {
                                        "name": "landlock_read",
                                        "args": {"path": str(allowed)},
                                        "id": f"landlock-{session}-{index}-{uuid.uuid4().hex}",
                                    }
                                ],
                            )
                        ]
                    }
                    start = time.perf_counter_ns()
                    result = graph.invoke(request, config=config)
                    elapsed_ms = (time.perf_counter_ns() - start) / 1e6
                    content = result["messages"][-1].content
                    lean_in_prego = max(
                        0.0,
                        spans["lean_at_go_ms"] - spans["lean_at_worker_start_ms"],
                    )
                    activation_ms = max(0.0, spans["prego_ms"] - lean_in_prego)
                    lean_after_go = max(0.0, spans["lean_ms"] - spans["lean_at_go_ms"])
                    execution_ms = max(
                        0.0,
                        spans["worker_ms"]
                        - spans["prego_ms"]
                        - spans["cleanup_ms"]
                        - lean_after_go,
                    )
                    accounted = (
                        spans["authorization_ms"]
                        + spans["lean_ms"]
                        + activation_ms
                        + execution_ms
                        + spans["audit_ms"]
                        + spans["cleanup_ms"]
                    )
                    _write(
                        stream,
                        {
                            "kind": "call",
                            "route": "landlock",
                            "session": session,
                            "round": index,
                            "phase": phase,
                            "elapsed_ms": elapsed_ms,
                            "authorization_ms": spans["authorization_ms"],
                            "lean_ms": spans["lean_ms"],
                            "activation_ms": activation_ms,
                            "execution_ms": execution_ms,
                            "audit_ms": spans["audit_ms"],
                            "cleanup_ms": spans["cleanup_ms"],
                            "framework_residual_ms": elapsed_ms - accounted,
                            "valid": expected in content,
                            "audit_records": len(sink.records()),
                            "activation_receipts": len(executor.activation_receipts()),
                        },
                    )
                    start = time.perf_counter_ns()
                    direct = allowed.read_text()
                    direct_ms = (time.perf_counter_ns() - start) / 1e6
                    _write(
                        stream,
                        {
                            "kind": "call",
                            "route": "upstream",
                            "session": session,
                            "round": index,
                            "phase": phase,
                            "elapsed_ms": direct_ms,
                            "valid": direct == expected,
                        },
                    )
        finally:
            CedarPolicyBackend.filter = originals["authorize"]
            CheckerClass._require = originals["lean"]
            LinuxSandboxExecutor._cleanup_worker = originals["cleanup"]
            LinuxSandboxExecutor._run_worker = originals["worker"]
            LeanLifecycleSession.permit_go = originals["go"]
            AuditClass.write = originals["audit"]


def main() -> None:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--output", type=Path, required=True)
    parser.add_argument("--sessions", type=int, default=5)
    parser.add_argument("--warmups", type=int, default=10)
    parser.add_argument("--measured", type=int, default=20)
    parser.add_argument(
        "--optimization-level",
        choices=("no", "normal", "aggressive"),
        default="aggressive",
    )
    parser.add_argument("--session", type=int)
    args = parser.parse_args()
    if args.session is not None:
        run_session(
            args.output,
            args.session,
            args.warmups,
            args.measured,
            args.optimization_level,
        )
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
            "--optimization-level",
            args.optimization_level,
            "--session",
            str(session),
        ]
        log = args.output / f"session-{session}.log"
        with log.open("x") as stream:
            subprocess.run(command, check=True, stdout=stream, stderr=subprocess.STDOUT)
        print(f"landlock session {session} complete", flush=True)


if __name__ == "__main__":
    main()
