"""Common one-file-read workload on sealed Linux, with and without Lean."""

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
    IntegrityRecheckMode,
    LeanLifecycleChecker,
    LinuxObjectDispatcher,
    LinuxToolSpec,
    Principal,
    SqliteAuditSink,
    cedar_security,
    install_mac_policy,
    with_principal,
)
from langgraph.prebuilt.security import linux as linux_module
from langgraph.prebuilt.security.enforcement import EnforcementCoordinator
from langgraph.prebuilt.security.lean_lifecycle import LeanLifecycleSession
from langgraph.prebuilt.security.linux import LinuxSandboxExecutor
from langgraph.prebuilt.security.linux_object import LinuxObjectDispatcher as _Dispatcher
from langgraph.prebuilt.security.linux_object import _LinuxObjectWorker
from langgraph.prebuilt.security.object_policy import ObjectPolicyHostExecutor
from langgraph.prebuilt.security.types import Tool, ToolCall, ToolDac

POLICY = 'permit(principal == slangGraph::User::"alice", action, resource);'
MANDATORY = 'forbid(principal == slangGraph::User::"bob", action, resource);'
MANIFEST = "runs linux\nfs read @{path} need"
LEAN_BINARY = "/data/langgraph/proofs/worker-route/.lake/build/lib/libargus_worker_route.so"
LEAN_SHA256 = "6723590136270fcf1bbe6851d5df6b8c4ea9ecbc8f4a23b34b86f057ad099bc2"
LEAN_RUNTIME = (
    "/home/faculty/abk6349/.elan/toolchains/leanprover--lean4---v4.34.1/lib/lean/libleanshared.so"
)
LEAN_RUNTIME_SHA256 = "6b30cc963d065fc9d2f87f7e9cbe0682b23000ae5425bccd769c5d477fa74f13"
SOURCE = """from pathlib import Path

def run(path):
    return Path(path).read_text()
"""


@tool("common_read")
def common_read(path: str) -> str:
    """Read one exact file in the sealed Linux worker."""
    raise RuntimeError("unconfined fallback is forbidden")


def write(stream, value: dict) -> None:
    stream.write(json.dumps(value, sort_keys=True) + "\n")
    stream.flush()


def session(
    output: Path,
    number: int,
    warmups: int,
    measured: int,
    lean: bool,
    integrity_recheck: str,
) -> None:
    os.sched_setaffinity(0, {min(os.sched_getaffinity(0))})
    install_mac_policy(MANDATORY)
    with tempfile.TemporaryDirectory(prefix="slg-common-linux-") as folder:
        root = Path(folder)
        trusted = root / "trusted"
        data = root / "data"
        trusted.mkdir()
        data.mkdir()
        source = trusted / "common_worker.py"
        allowed = data / "allowed.txt"
        source.write_text(SOURCE)
        allowed.write_text("COMMON_FILE_VALUE")
        checker_started = time.perf_counter_ns()
        checker = (
            LeanLifecycleChecker(
                LEAN_BINARY,
                LEAN_SHA256,
                LEAN_RUNTIME,
                LEAN_RUNTIME_SHA256,
            )
            if lean
            else None
        )
        checker_setup_ms = (time.perf_counter_ns() - checker_started) / 1e6
        dispatcher_started = time.perf_counter_ns()
        dispatcher = LinuxObjectDispatcher(
            {
                "common_read": LinuxToolSpec(
                    "common_worker:run",
                    source,
                    hashlib.sha256(source.read_bytes()).hexdigest(),
                )
            },
            runtime_roots=(trusted,),
            lifecycle_checker=checker,
            worker_pool_capacity=1,
            integrity_recheck=integrity_recheck,
        )
        dispatcher_setup_ms = (time.perf_counter_ns() - dispatcher_started) / 1e6
        sink = SqliteAuditSink(root / "audit.sqlite")
        admission_started = time.perf_counter_ns()
        security = replace(
            cedar_security(
                common_read,
                manifest=MANIFEST,
                policy=POLICY,
                dispatcher=dispatcher,
            ),
            audit_sink=sink,
            closed_admission=True,
        )
        node = ToolNode([common_read], security=security)
        builder = StateGraph(MessagesState)
        builder.add_node("tools", node)
        builder.add_edge(START, "tools")
        graph = builder.compile(security=security)
        admission_setup_ms = (time.perf_counter_ns() - admission_started) / 1e6
        principal = Principal("alice", frozenset(), frozenset(), f"session-{number}")
        config = with_principal({}, principal, modules=security.modules)
        spans = {
            "authorization_ms": 0.0,
            "invocation_binding_ms": 0.0,
            "policy_lowering_ms": 0.0,
            "host_prepare_ms": 0.0,
            "host_attestation_ms": 0.0,
            "prepared_policy_match_ms": 0.0,
            "lean_ms": 0.0,
            "worker_ms": 0.0,
            "prego_ms": 0.0,
            "lean_worker_start_ms": 0.0,
            "lean_go_ms": 0.0,
            "cleanup_ms": 0.0,
            "audit_ms": 0.0,
            "dispatch_ms": 0.0,
            "ready_ms": 0.0,
            "coordinator_activation_ms": 0.0,
            "host_executor_ms": 0.0,
            "dispatcher_setup_ms": 0.0,
            "toolnode_ms": 0.0,
            "tool_call_ms": 0.0,
            "worker_function_body_ms": 0.0,
            "worker_module_execution_ms": 0.0,
            "worker_target_resolution_ms": 0.0,
            "worker_target_call_ms": 0.0,
            "worker_result_serialization_ms": 0.0,
        }
        originals = {
            "authorize": ObjectPolicyHostExecutor._authorize,
            "host_invoke": ObjectPolicyHostExecutor.invoke,
            "compile": _LinuxObjectWorker._compile_grant,
            "prepare": LinuxSandboxExecutor._prepare_execution,
            "attest": linux_module._LinuxBubblewrapAdapter.attest,
            "negotiate": EnforcementCoordinator.negotiate,
            "authority_key": linux_module._prepared_authority_key,
            "host_key": linux_module._host_configuration_digest,
            "new_worker": _Dispatcher._new_worker,
            "lean": LeanLifecycleChecker._require,
            "worker": LinuxSandboxExecutor._run_worker,
            "go": LeanLifecycleSession.permit_go,
            "cleanup": LinuxSandboxExecutor._cleanup_worker,
            "audit": sink.write,
            "dispatch": dispatcher.invoke,
            "readline": linux_module._readline_json,
            "activate": EnforcementCoordinator.activate,
            "toolnode": ToolNode._func,
            "tool_call": ToolNode._run_one_inner,
            "encode_request": linux_module._encode_worker_request,
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
        _LinuxObjectWorker._compile_grant = timed("invocation_binding_ms", originals["compile"])
        LinuxSandboxExecutor._prepare_execution = timed("host_prepare_ms", originals["prepare"])
        linux_module._LinuxBubblewrapAdapter.attest = timed(
            "host_attestation_ms", originals["attest"]
        )
        EnforcementCoordinator.negotiate = timed("policy_lowering_ms", originals["negotiate"])
        linux_module._prepared_authority_key = timed(
            "prepared_policy_match_ms", originals["authority_key"]
        )
        linux_module._host_configuration_digest = timed(
            "prepared_policy_match_ms", originals["host_key"]
        )
        _Dispatcher._new_worker = timed("dispatcher_setup_ms", originals["new_worker"])
        LeanLifecycleChecker._require = timed("lean_ms", originals["lean"])
        EnforcementCoordinator.activate = timed("coordinator_activation_ms", originals["activate"])
        LinuxSandboxExecutor._cleanup_worker = timed("cleanup_ms", originals["cleanup"])
        sink.write = timed("audit_ms", originals["audit"])
        ToolNode._func = timed("toolnode_ms", originals["toolnode"])
        ToolNode._run_one_inner = timed("tool_call_ms", originals["tool_call"])

        def worker_timed(*args, **kwargs):
            spans["lean_worker_start_ms"] = spans["lean_ms"]
            started = time.perf_counter_ns()
            spans["worker_started_ns"] = started
            try:
                return originals["worker"](*args, **kwargs)
            finally:
                spans["worker_ms"] += (time.perf_counter_ns() - started) / 1e6

        def go_timed(*args, **kwargs):
            result = originals["go"](*args, **kwargs)
            spans["prego_ms"] = (time.perf_counter_ns() - spans["worker_started_ns"]) / 1e6
            spans["lean_go_ms"] = spans["lean_ms"]
            return result

        def readline_timed(*args, **kwargs):
            result = originals["readline"](*args, **kwargs)
            if isinstance(result, dict) and result.get("status") == "ready":
                spans["ready_ms"] = (time.perf_counter_ns() - spans["worker_started_ns"]) / 1e6
            timing_ns = result.get("evaluation_timing_ns") if isinstance(result, dict) else None
            if isinstance(timing_ns, dict):
                for source, destination in (
                    ("function_body", "worker_function_body_ms"),
                    ("module_execution", "worker_module_execution_ms"),
                    ("target_resolution", "worker_target_resolution_ms"),
                    ("target_call", "worker_target_call_ms"),
                    ("result_serialization", "worker_result_serialization_ms"),
                ):
                    value = timing_ns.get(source)
                    if type(value) is int and value >= 0:
                        spans[destination] = value / 1e6
            return result

        def encode_request_timed(request):
            return originals["encode_request"]({**request, "evaluation_telemetry": True})

        def dispatch_timed(*args, **kwargs):
            started = time.perf_counter_ns()
            try:
                return originals["dispatch"](*args, **kwargs)
            finally:
                spans["dispatch_ms"] += (time.perf_counter_ns() - started) / 1e6

        LinuxSandboxExecutor._run_worker = worker_timed
        LeanLifecycleSession.permit_go = go_timed
        linux_module._readline_json = readline_timed
        linux_module._encode_worker_request = encode_request_timed
        dispatcher.invoke = dispatch_timed
        route = "linux-lean" if lean else "linux"
        try:
            with output.open("x") as stream:
                write(
                    stream,
                    {
                        "kind": "setup",
                        "route": route,
                        "session": number,
                        "checker_setup_ms": checker_setup_ms,
                        "dispatcher_setup_ms": dispatcher_setup_ms,
                        "admission_setup_ms": admission_setup_ms,
                        "manifest": MANIFEST,
                        "policy": POLICY,
                        "mandatory_policy": MANDATORY,
                        "integrity_recheck": integrity_recheck,
                    },
                )
                for index in range(1 + warmups + measured):
                    phase = (
                        "first_use" if index == 0 else "warmup" if index <= warmups else "measured"
                    )
                    for key in spans:
                        spans[key] = 0.0
                    call_id = uuid.uuid4().hex
                    prepared_call = ToolCall(
                        Tool("common_read", ToolDac("owner", {}), frozenset(), ()),
                        {"path": str(allowed)},
                        {},
                        call_id,
                        0,
                    )
                    preflight_started = time.perf_counter_ns()
                    security.host_executor.prewarm(principal, prepared_call, (), count=1)
                    worker_preflight_ms = (time.perf_counter_ns() - preflight_started) / 1e6
                    for key in spans:
                        spans[key] = 0.0
                    hits_before = dispatcher.worker_pool_stats()["hits"]
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
                                            "id": call_id,
                                        }
                                    ],
                                )
                            ]
                        },
                        config=config,
                    )
                    elapsed = (time.perf_counter_ns() - started) / 1e6
                    pool_stats = dispatcher.worker_pool_stats()
                    lean_prego = max(0.0, spans["lean_go_ms"] - spans["lean_worker_start_ms"])
                    activation = max(
                        0.0,
                        spans["prego_ms"] - lean_prego
                        if lean
                        else spans["ready_ms"] + spans["coordinator_activation_ms"],
                    )
                    lean_after_go = max(0.0, spans["lean_ms"] - spans["lean_go_ms"])
                    execution = max(
                        0.0,
                        spans["worker_ms"]
                        - (spans["prego_ms"] if lean else activation)
                        - spans["cleanup_ms"]
                        - lean_after_go,
                    )
                    worker_transport_and_parent = max(
                        0.0,
                        execution
                        - spans["worker_function_body_ms"]
                        - spans["worker_result_serialization_ms"],
                    )
                    accounted = (
                        spans["authorization_ms"]
                        + spans["invocation_binding_ms"]
                        + spans["policy_lowering_ms"]
                        + activation
                        + execution
                        + spans["lean_ms"]
                        + spans["audit_ms"]
                        + spans["cleanup_ms"]
                    )
                    graph_dispatch = elapsed - spans["toolnode_ms"]
                    toolnode_orchestration = spans["toolnode_ms"] - spans["tool_call_ms"]
                    tool_call_framework = (
                        spans["tool_call_ms"] - spans["host_executor_ms"] - spans["audit_ms"]
                    )
                    host_bridge = (
                        spans["host_executor_ms"] - spans["authorization_ms"] - spans["dispatch_ms"]
                    )
                    dispatcher_other = (
                        spans["dispatch_ms"]
                        - spans["dispatcher_setup_ms"]
                        - spans["host_prepare_ms"]
                        - spans["worker_ms"]
                    )
                    host_prepare_other = (
                        spans["host_prepare_ms"]
                        - spans["invocation_binding_ms"]
                        - spans["host_attestation_ms"]
                        - spans["prepared_policy_match_ms"]
                        - spans["policy_lowering_ms"]
                        - spans["lean_worker_start_ms"]
                    )
                    residual_partition = (
                        graph_dispatch
                        + toolnode_orchestration
                        + tool_call_framework
                        + host_bridge
                        + dispatcher_other
                        + spans["dispatcher_setup_ms"]
                        + host_prepare_other
                        + spans["host_attestation_ms"]
                        + spans["prepared_policy_match_ms"]
                    )
                    write(
                        stream,
                        {
                            "kind": "call",
                            "route": route,
                            "session": number,
                            "round": index,
                            "phase": phase,
                            "elapsed_ms": elapsed,
                            "worker_preflight_ms": worker_preflight_ms,
                            "authorization_ms": spans["authorization_ms"],
                            "invocation_binding_ms": spans["invocation_binding_ms"],
                            "policy_lowering_ms": spans["policy_lowering_ms"],
                            "host_prepare_ms": spans["host_prepare_ms"],
                            "host_attestation_ms": spans["host_attestation_ms"],
                            "prepared_policy_match_ms": spans["prepared_policy_match_ms"],
                            "host_executor_ms": spans["host_executor_ms"],
                            "dispatcher_setup_ms": spans["dispatcher_setup_ms"],
                            "toolnode_ms": spans["toolnode_ms"],
                            "tool_call_ms": spans["tool_call_ms"],
                            "graph_dispatch_ms": graph_dispatch,
                            "toolnode_orchestration_ms": toolnode_orchestration,
                            "tool_call_framework_ms": tool_call_framework,
                            "host_bridge_ms": host_bridge,
                            "dispatcher_other_ms": dispatcher_other,
                            "host_prepare_other_ms": host_prepare_other,
                            "residual_partition_error_ms": (
                                elapsed - accounted - residual_partition
                            ),
                            "activation_ms": activation,
                            "execution_ms": execution,
                            "worker_function_body_ms": spans["worker_function_body_ms"],
                            "worker_module_execution_ms": spans["worker_module_execution_ms"],
                            "worker_target_resolution_ms": spans["worker_target_resolution_ms"],
                            "worker_target_call_ms": spans["worker_target_call_ms"],
                            "worker_result_serialization_ms": spans[
                                "worker_result_serialization_ms"
                            ],
                            "worker_transport_and_parent_ms": worker_transport_and_parent,
                            "mediator_transport_ms": 0.0,
                            "lean_ms": spans["lean_ms"],
                            "audit_ms": spans["audit_ms"],
                            "cleanup_ms": spans["cleanup_ms"],
                            "framework_residual_ms": elapsed - accounted,
                            "worker_reused": pool_stats["hits"] > hits_before,
                            "worker_pool": dict(pool_stats),
                            "valid": "COMMON_FILE_VALUE" in result["messages"][-1].content,
                        },
                    )
        finally:
            ObjectPolicyHostExecutor._authorize = originals["authorize"]
            ObjectPolicyHostExecutor.invoke = originals["host_invoke"]
            _LinuxObjectWorker._compile_grant = originals["compile"]
            LinuxSandboxExecutor._prepare_execution = originals["prepare"]
            linux_module._LinuxBubblewrapAdapter.attest = originals["attest"]
            EnforcementCoordinator.negotiate = originals["negotiate"]
            linux_module._prepared_authority_key = originals["authority_key"]
            linux_module._host_configuration_digest = originals["host_key"]
            _Dispatcher._new_worker = originals["new_worker"]
            LeanLifecycleChecker._require = originals["lean"]
            EnforcementCoordinator.activate = originals["activate"]
            LinuxSandboxExecutor._run_worker = originals["worker"]
            LeanLifecycleSession.permit_go = originals["go"]
            linux_module._readline_json = originals["readline"]
            linux_module._encode_worker_request = originals["encode_request"]
            LinuxSandboxExecutor._cleanup_worker = originals["cleanup"]
            sink.write = originals["audit"]
            ToolNode._func = originals["toolnode"]
            ToolNode._run_one_inner = originals["tool_call"]
            dispatcher.close()


def run(
    output: Path,
    sessions: int,
    warmups: int,
    measured: int,
    integrity_recheck: str,
) -> None:
    output.mkdir(parents=True, exist_ok=False)
    for lean in (False, True):
        for number in range(sessions):
            route = "linux-lean" if lean else "linux"
            with (output / f"{route}-session-{number}.log").open("x") as log:
                subprocess.run(
                    [
                        sys.executable,
                        __file__,
                        "--output",
                        str(output / f"{route}-session-{number}.jsonl"),
                        "--session",
                        str(number),
                        "--warmups",
                        str(warmups),
                        "--measured",
                        str(measured),
                        "--integrity-recheck",
                        integrity_recheck,
                        *(["--lean"] if lean else []),
                    ],
                    stdout=log,
                    stderr=subprocess.STDOUT,
                    timeout=1200,
                    check=True,
                )


if __name__ == "__main__":
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--output", required=True, type=Path)
    parser.add_argument("--sessions", default=5, type=int)
    parser.add_argument("--warmups", default=5, type=int)
    parser.add_argument("--measured", default=20, type=int)
    parser.add_argument("--session", type=int)
    parser.add_argument("--lean", action="store_true")
    parser.add_argument(
        "--integrity-recheck",
        choices=[item.value for item in IntegrityRecheckMode],
        default=IntegrityRecheckMode.for_optimization("aggressive").value,
    )
    arguments = parser.parse_args()
    if arguments.session is None:
        run(
            arguments.output,
            arguments.sessions,
            arguments.warmups,
            arguments.measured,
            arguments.integrity_recheck,
        )
    else:
        session(
            arguments.output,
            arguments.session,
            arguments.warmups,
            arguments.measured,
            arguments.lean,
            arguments.integrity_recheck,
        )
