"""Measure matched LangGraph SQLite routes with and without Argus."""

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
from langgraph.prebuilt.security import landlock as landlock_module
from langgraph.prebuilt.security import linux as linux_module
from langgraph.prebuilt.security._object_landlock import _LandlockObjectAdapter
from langgraph.prebuilt.security.broker import BrokerSession
from langgraph.prebuilt.security.enforcement import EnforcementCoordinator
from langgraph.prebuilt.security.landlock import LandlockSandboxExecutor
from langgraph.prebuilt.security.lean_lifecycle import LeanLifecycleChecker
from langgraph.prebuilt.security.mediators.records import RECORDS
from langgraph.prebuilt.security.object_broker import _ObjectBroker, _ObjectWorker
from langgraph.prebuilt.security.object_policy import ObjectPolicyHostExecutor
from langgraph.prebuilt.security.policy import TypedPolicyBackend
from langgraph.prebuilt.security.types import Tool, ToolCall, ToolDac

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


def _initialize_database(database: Path) -> None:
    with sqlite3.connect(database) as connection:
        connection.execute(SQLITE_RECORD_SCHEMA)
        connection.executemany(
            "INSERT INTO records VALUES (?, ?)",
            [("alice", "AUTHORIZED_RECORD"), ("bob", "BOB_PRIVATE")],
        )


def run_baseline_session(output: Path, session: int, warmups: int, measured: int) -> None:
    """Run the same LangGraph workload without Argus in a clean interpreter."""
    output.parent.mkdir(parents=True, exist_ok=True)
    os.sched_setaffinity(0, {min(os.sched_getaffinity(0))})
    with tempfile.TemporaryDirectory(prefix="slg-broker-baseline-") as folder:
        database = Path(folder) / "records.sqlite"
        _initialize_database(database)

        @tool("broker_read")
        def baseline_read(record: str) -> dict:
            """Read the requested record directly from application SQLite."""
            database_id, separator, key = record.partition("/")
            if database_id != "notes" or separator != "/" or not key:
                raise ValueError("unsupported record")
            with sqlite3.connect(database) as connection:
                row = connection.execute(
                    "SELECT value FROM records WHERE key = ?", (key,)
                ).fetchone()
            return {"found": row is not None, "value": row[0] if row else None}

        setup_start = time.perf_counter_ns()
        builder = StateGraph(MessagesState)
        builder.add_node("tools", ToolNode([baseline_read]))
        builder.add_edge(START, "tools")
        graph = builder.compile()
        setup_ms = (time.perf_counter_ns() - setup_start) / 1e6
        with output.open("x") as stream:
            _write(
                stream,
                {
                    "kind": "baseline_setup",
                    "session": session,
                    "cpu_affinity": sorted(os.sched_getaffinity(0)),
                    "graph_setup_ms": setup_ms,
                },
            )
            for index in range(1 + warmups + measured):
                phase = "first_use" if index == 0 else "warmup" if index <= warmups else "measured"
                call_id = f"baseline-{session}-{index}-{uuid.uuid4().hex}"
                request = {
                    "messages": [
                        AIMessage(
                            content="",
                            tool_calls=[
                                {
                                    "name": "broker_read",
                                    "args": {"record": "notes/alice"},
                                    "id": call_id,
                                }
                            ],
                        )
                    ]
                }
                start = time.perf_counter_ns()
                result = graph.invoke(request)
                elapsed_ms = (time.perf_counter_ns() - start) / 1e6
                _write(
                    stream,
                    {
                        "kind": "call",
                        "route": "langgraph-baseline",
                        "session": session,
                        "round": index,
                        "phase": phase,
                        "elapsed_ms": elapsed_ms,
                        "valid": "AUTHORIZED_RECORD" in result["messages"][-1].content,
                    },
                )
                start = time.perf_counter_ns()
                with sqlite3.connect(database) as connection:
                    direct = connection.execute(
                        "SELECT value FROM records WHERE key='alice'"
                    ).fetchone()[0]
                _write(
                    stream,
                    {
                        "kind": "diagnostic",
                        "route": "direct-sqlite",
                        "session": session,
                        "round": index,
                        "phase": phase,
                        "elapsed_ms": (time.perf_counter_ns() - start) / 1e6,
                        "valid": direct == "AUTHORIZED_RECORD",
                    },
                )


def run_session(
    output: Path,
    session: int,
    warmups: int,
    measured: int,
    *,
    audit: bool,
) -> None:
    """Run one independent process session."""
    output.parent.mkdir(parents=True, exist_ok=True)
    os.sched_setaffinity(0, {min(os.sched_getaffinity(0))})
    checker_path = Path(os.environ["ARGUS_LIFECYCLE_CHECKER_LIBRARY"]).resolve(strict=True)
    runtime_path = Path(os.environ["ARGUS_LIFECYCLE_CHECKER_RUNTIME"]).resolve(strict=True)
    checker_start = time.perf_counter_ns()
    checker = LeanLifecycleChecker(
        str(checker_path),
        hashlib.sha256(checker_path.read_bytes()).hexdigest(),
        str(runtime_path),
        hashlib.sha256(runtime_path.read_bytes()).hexdigest(),
    )
    checker.require_inline()
    checker_setup_ms = (time.perf_counter_ns() - checker_start) / 1e6
    install_mac_policy(MANDATORY)
    with tempfile.TemporaryDirectory(prefix="slg-broker-cost-") as folder:
        root = Path(folder)
        source = root / "worker.py"
        database = root / "records.sqlite"
        source.write_text(SOURCE)
        _initialize_database(database)
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
            lifecycle_checker=checker,
            worker_pool_capacity=1,
        )
        dispatcher_setup_ms = (time.perf_counter_ns() - setup_start) / 1e6
        sink = SqliteAuditSink(root / "audit.sqlite") if audit else None
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
        spans = {
            "authorization_ms": 0.0,
            "audit_ms": 0.0,
            "cleanup_ms": 0.0,
            "lean_grant_ms": 0.0,
            "grant_capture_check_ms": 0.0,
            "lean_go_ms": 0.0,
            "lean_result_ms": 0.0,
            "lean_prepare_ms": 0.0,
            "prepared_worker_selection_ms": 0.0,
            "grant_construction_ms": 0.0,
            "invocation_policy_binding_ms": 0.0,
            "prepared_policy_binding_ms": 0.0,
            "channel_thread_setup_ms": 0.0,
            "certificate_construction_ms": 0.0,
            "receipt_validation_ms": 0.0,
            "request_encoding_ms": 0.0,
            "worker_ready_wait_ms": 0.0,
            "worker_result_wait_ms": 0.0,
            "host_attestation_ms": 0.0,
            "prepared_mediator_binding_ms": 0.0,
            "worker_context_binding_ms": 0.0,
            "coordinator_activation_ms": 0.0,
            "coordinator_receipt_check_ms": 0.0,
            "broker_frame_ms": 0.0,
            "broker_close_ms": 0.0,
        }
        dispatch = {"start_wall": 0.0, "elapsed_ms": 0.0, "activated_at": 0.0}
        originals = {
            "authorize": ObjectPolicyHostExecutor._authorize,
            "dispatch": dispatcher.invoke,
            "cleanup": LandlockSandboxExecutor._cleanup_worker,
            "audit": sink.write if sink is not None else None,
            "lean": LeanLifecycleChecker._require,
            "lean_typed_grant": LeanLifecycleChecker.require_prepared_grant,
            "lean_prepare": LeanLifecycleChecker._prepare_captured_route,
            "lean_prepare_binding": LeanLifecycleChecker._prepare_validated_binding,
            "lean_prepared": LeanLifecycleChecker._require_prepared_captured,
            "lean_transition": LeanLifecycleChecker._require_prepared_transition,
            "grant_capture_check": LandlockSandboxExecutor._check_lean_grant,
            "policy_filter": TypedPolicyBackend.filter,
            "landlock_lower": LandlockSandboxExecutor._lower,
            "limits": LandlockSandboxExecutor._limits,
            "pool_key": LandlockSandboxExecutor._pool_key,
            "new_worker": dispatcher._new_worker,
            "compile_grant": _ObjectWorker._compile_grant,
            "prepare_grant": _ObjectWorker._prepare_grant,
            "bind_policy": _ObjectWorker._bind_prepared_policy,
            "bind_session": _ObjectBroker.bind_prepared_session,
            "capture_certificate": landlock_module._capture_controller_receipt_certificate,
            "receipt": _ObjectWorker._receipt,
            "encode_worker_request": linux_module._encode_worker_request,
            "readline_json": linux_module._readline_json,
            "host_attest": _LandlockObjectAdapter.attest,
            "bind_mediators": _ObjectWorker._bind_prepared_mediators,
            "bind_worker": _LandlockObjectAdapter.bind_worker,
            "coordinator_activate": EnforcementCoordinator.activate,
            "coordinator_validate": EnforcementCoordinator.validate_receipt,
            "broker_frame": _ObjectBroker._handle_frame,
            "broker_close": BrokerSession.close_parent,
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
        if sink is not None:
            sink.write = timed("audit_ms", originals["audit"])

        def timed_lean(instance, payload, phase):
            name = {
                "grant_ready": "lean_grant_ms",
                "running": "lean_go_ms",
                "ready": "lean_result_ms",
            }[phase]
            start = time.perf_counter_ns()
            try:
                return originals["lean"](instance, payload, phase)
            finally:
                spans[name] += (time.perf_counter_ns() - start) / 1e6

        LeanLifecycleChecker._require = timed_lean
        LeanLifecycleChecker.require_prepared_grant = timed(
            "lean_grant_ms", originals["lean_typed_grant"]
        )

        def timed_lean_prepare(function):
            def wrapper(*args, **kwargs):
                start = time.perf_counter_ns()
                try:
                    return function(*args, **kwargs)
                finally:
                    elapsed = (time.perf_counter_ns() - start) / 1e6
                    spans["lean_prepare_ms"] += elapsed

            return wrapper

        def timed_lean_prepared(instance, prepared, events, phase):
            name = {"running": "lean_go_ms", "ready": "lean_result_ms"}[phase]
            start = time.perf_counter_ns()
            try:
                return originals["lean_prepared"](instance, prepared, events, phase)
            finally:
                spans[name] += (time.perf_counter_ns() - start) / 1e6

        LeanLifecycleChecker._prepare_captured_route = timed_lean_prepare(originals["lean_prepare"])
        LeanLifecycleChecker._prepare_validated_binding = timed_lean_prepare(
            originals["lean_prepare_binding"]
        )
        LeanLifecycleChecker._require_prepared_captured = timed_lean_prepared

        def timed_lean_transition(instance, prepared, observed, phase, **kwargs):
            name = {"running": "lean_go_ms", "ready": "lean_result_ms"}[phase]
            start = time.perf_counter_ns()
            try:
                return originals["lean_transition"](instance, prepared, observed, phase, **kwargs)
            finally:
                spans[name] += (time.perf_counter_ns() - start) / 1e6

        LeanLifecycleChecker._require_prepared_transition = timed_lean_transition
        LandlockSandboxExecutor._check_lean_grant = timed(
            "grant_capture_check_ms", originals["grant_capture_check"]
        )
        TypedPolicyBackend.filter = timed("policy_filter_ms", originals["policy_filter"])
        LandlockSandboxExecutor._lower = timed("landlock_lower_ms", originals["landlock_lower"])
        LandlockSandboxExecutor._limits = timed("limits_ms", originals["limits"])
        LandlockSandboxExecutor._pool_key = timed("pool_key_ms", originals["pool_key"])
        dispatcher._new_worker = timed("prepared_worker_selection_ms", originals["new_worker"])
        _ObjectWorker._compile_grant = timed("grant_construction_ms", originals["compile_grant"])
        _ObjectWorker._prepare_grant = timed(
            "invocation_policy_binding_ms", originals["prepare_grant"]
        )
        _ObjectWorker._bind_prepared_policy = timed(
            "prepared_policy_binding_ms", originals["bind_policy"]
        )
        _ObjectBroker.bind_prepared_session = timed(
            "channel_thread_setup_ms", originals["bind_session"]
        )
        landlock_module._capture_controller_receipt_certificate = timed(
            "certificate_construction_ms", originals["capture_certificate"]
        )
        _ObjectWorker._receipt = timed("receipt_validation_ms", originals["receipt"])
        linux_module._encode_worker_request = timed(
            "request_encoding_ms", originals["encode_worker_request"]
        )

        def timed_readline(*args, **kwargs):
            start = time.perf_counter_ns()
            result = originals["readline_json"](*args, **kwargs)
            elapsed = (time.perf_counter_ns() - start) / 1e6
            if result.get("status") == "ready":
                spans["worker_ready_wait_ms"] += elapsed
            else:
                spans["worker_result_wait_ms"] += elapsed
            return result

        linux_module._readline_json = timed_readline
        _LandlockObjectAdapter.attest = timed("host_attestation_ms", originals["host_attest"])
        _ObjectWorker._bind_prepared_mediators = timed(
            "prepared_mediator_binding_ms", originals["bind_mediators"]
        )
        _LandlockObjectAdapter.bind_worker = timed(
            "worker_context_binding_ms", originals["bind_worker"]
        )
        EnforcementCoordinator.activate = timed(
            "coordinator_activation_ms", originals["coordinator_activate"]
        )
        EnforcementCoordinator.validate_receipt = timed(
            "coordinator_receipt_check_ms", originals["coordinator_validate"]
        )
        _ObjectBroker._handle_frame = timed("broker_frame_ms", originals["broker_frame"])
        BrokerSession.close_parent = timed("broker_close_ms", originals["broker_close"])

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
                        "checker_setup_ms": checker_setup_ms,
                        "closed_admission": True,
                        "mandatory_policy": MANDATORY,
                        "policy": POLICY,
                        "manifest": MANIFEST,
                        "lifecycle_checker_sha256": checker.binary_sha256,
                        "lifecycle_checker_path": checker.binary_path,
                        "lifecycle_runtime_path": checker.runtime_path,
                        "lifecycle_runtime_sha256": checker.runtime_sha256,
                        "checker_inline": checker.inline,
                        "checker_loaded_during_preparation": checker.statistics()["loads"] == 1,
                        "audit_enabled": audit,
                    },
                )
                for index in range(1 + warmups + measured):
                    phase = (
                        "first_use" if index == 0 else "warmup" if index <= warmups else "measured"
                    )
                    spans.update(
                        authorization_ms=0.0,
                        audit_ms=0.0,
                        cleanup_ms=0.0,
                        lean_grant_ms=0.0,
                        grant_capture_check_ms=0.0,
                        policy_filter_ms=0.0,
                        landlock_lower_ms=0.0,
                        limits_ms=0.0,
                        pool_key_ms=0.0,
                        lean_go_ms=0.0,
                        lean_result_ms=0.0,
                        lean_prepare_ms=0.0,
                        prepared_worker_selection_ms=0.0,
                        grant_construction_ms=0.0,
                        invocation_policy_binding_ms=0.0,
                        prepared_policy_binding_ms=0.0,
                        channel_thread_setup_ms=0.0,
                        certificate_construction_ms=0.0,
                        receipt_validation_ms=0.0,
                        request_encoding_ms=0.0,
                        worker_ready_wait_ms=0.0,
                        worker_result_wait_ms=0.0,
                        host_attestation_ms=0.0,
                        prepared_mediator_binding_ms=0.0,
                        worker_context_binding_ms=0.0,
                        coordinator_activation_ms=0.0,
                        coordinator_receipt_check_ms=0.0,
                        broker_frame_ms=0.0,
                        broker_close_ms=0.0,
                    )
                    mediator_spans["operation_ms"] = 0.0
                    dispatch.update(start_wall=0.0, elapsed_ms=0.0, activated_at=0.0)
                    call_id = f"broker-{session}-{index}-{uuid.uuid4().hex}"
                    prepared_call = ToolCall(
                        Tool("broker_read", ToolDac("owner", {}), frozenset(), ()),
                        {"record": "notes/alice"},
                        {},
                        call_id,
                        0,
                    )
                    preparation_start = time.perf_counter_ns()
                    security.host_executor.prewarm(principal, prepared_call, (), count=1)
                    worker_preparation_ms = (time.perf_counter_ns() - preparation_start) / 1e6
                    spans.update(
                        authorization_ms=0.0,
                        audit_ms=0.0,
                        cleanup_ms=0.0,
                        lean_grant_ms=0.0,
                        grant_capture_check_ms=0.0,
                        policy_filter_ms=0.0,
                        landlock_lower_ms=0.0,
                        limits_ms=0.0,
                        pool_key_ms=0.0,
                        lean_go_ms=0.0,
                        lean_result_ms=0.0,
                        lean_prepare_ms=0.0,
                        prepared_worker_selection_ms=0.0,
                        grant_construction_ms=0.0,
                        invocation_policy_binding_ms=0.0,
                        prepared_policy_binding_ms=0.0,
                        channel_thread_setup_ms=0.0,
                        certificate_construction_ms=0.0,
                        receipt_validation_ms=0.0,
                        request_encoding_ms=0.0,
                        worker_ready_wait_ms=0.0,
                        worker_result_wait_ms=0.0,
                        host_attestation_ms=0.0,
                        prepared_mediator_binding_ms=0.0,
                        worker_context_binding_ms=0.0,
                        coordinator_activation_ms=0.0,
                        coordinator_receipt_check_ms=0.0,
                        broker_frame_ms=0.0,
                        broker_close_ms=0.0,
                    )
                    pool_before = dict(dispatcher.worker_pool_stats())
                    checker_before = checker.statistics()
                    request = {
                        "messages": [
                            AIMessage(
                                content="",
                                tool_calls=[
                                    {
                                        "name": "broker_read",
                                        "args": {"record": "notes/alice"},
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
                    pool_after = dict(dispatcher.worker_pool_stats())
                    checker_after = checker.statistics()
                    if (
                        pool_after["hits"] != pool_before["hits"] + 1
                        or pool_after["policy_lowerings"] != pool_before["policy_lowerings"]
                        or checker_after["subprocess_calls"] != checker_before["subprocess_calls"]
                    ):
                        raise RuntimeError("optimized broker path instrumentation mismatch")
                    activation_inclusive_ms = max(
                        0.0, (dispatch["activated_at"] - dispatch["start_wall"]) * 1000
                    )
                    activation_ms = max(0.0, activation_inclusive_ms - spans["lean_grant_ms"])
                    broker_after_activation_ms = max(
                        0.0,
                        dispatch["elapsed_ms"] - activation_inclusive_ms - spans["cleanup_ms"],
                    )
                    mediator_transport_ms = max(
                        0.0,
                        broker_after_activation_ms
                        - mediator_spans["operation_ms"]
                        - spans["lean_go_ms"]
                        - spans["lean_result_ms"],
                    )
                    lean_ms = spans["lean_grant_ms"] + spans["lean_go_ms"] + spans["lean_result_ms"]
                    accounted = (
                        spans["authorization_ms"]
                        + activation_ms
                        + lean_ms
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
                            "worker_preparation_ms": worker_preparation_ms,
                            "authorization_ms": spans["authorization_ms"],
                            "activation_ms": activation_ms,
                            "lean_grant_ms": spans["lean_grant_ms"],
                            "grant_capture_check_ms": spans["grant_capture_check_ms"],
                            "policy_filter_ms": spans["policy_filter_ms"],
                            "landlock_lower_ms": spans["landlock_lower_ms"],
                            "limits_ms": spans["limits_ms"],
                            "pool_key_ms": spans["pool_key_ms"],
                            "lean_go_ms": spans["lean_go_ms"],
                            "lean_result_ms": spans["lean_result_ms"],
                            "lean_prepare_ms": spans["lean_prepare_ms"],
                            "prepared_worker_selection_ms": spans["prepared_worker_selection_ms"],
                            "grant_construction_ms": spans["grant_construction_ms"],
                            "invocation_policy_binding_ms": spans["invocation_policy_binding_ms"],
                            "prepared_policy_binding_ms": spans["prepared_policy_binding_ms"],
                            "channel_thread_setup_ms": spans["channel_thread_setup_ms"],
                            "certificate_construction_ms": spans["certificate_construction_ms"],
                            "receipt_validation_ms": spans["receipt_validation_ms"],
                            "request_encoding_ms": spans["request_encoding_ms"],
                            "worker_ready_wait_ms": spans["worker_ready_wait_ms"],
                            "worker_result_wait_ms": spans["worker_result_wait_ms"],
                            "host_attestation_ms": spans["host_attestation_ms"],
                            "prepared_mediator_binding_ms": spans["prepared_mediator_binding_ms"],
                            "worker_context_binding_ms": spans["worker_context_binding_ms"],
                            "coordinator_activation_ms": spans["coordinator_activation_ms"],
                            "coordinator_receipt_check_ms": spans["coordinator_receipt_check_ms"],
                            "broker_frame_ms": spans["broker_frame_ms"],
                            "broker_close_ms": spans["broker_close_ms"],
                            "dispatcher_ms": dispatch["elapsed_ms"],
                            "execution_ms": mediator_spans["operation_ms"],
                            "mediator_transport_ms": mediator_transport_ms,
                            "audit_ms": spans["audit_ms"],
                            "cleanup_ms": spans["cleanup_ms"],
                            "framework_residual_ms": elapsed_ms - accounted,
                            "valid": "AUTHORIZED_RECORD" in content,
                            "audit_enabled": audit,
                            "audit_records": len(sink.records()) if sink is not None else 0,
                            "broker_records": len(dispatcher.audit_records()),
                            "checker": checker_after,
                            "pool": pool_after,
                            "prepared_lowering_repeated_online": False,
                        },
                    )
        finally:
            ObjectPolicyHostExecutor._authorize = originals["authorize"]
            LandlockSandboxExecutor._cleanup_worker = originals["cleanup"]
            LeanLifecycleChecker._require = originals["lean"]
            LeanLifecycleChecker.require_prepared_grant = originals["lean_typed_grant"]
            LeanLifecycleChecker._prepare_captured_route = originals["lean_prepare"]
            LeanLifecycleChecker._prepare_validated_binding = originals["lean_prepare_binding"]
            LeanLifecycleChecker._require_prepared_captured = originals["lean_prepared"]
            LeanLifecycleChecker._require_prepared_transition = originals["lean_transition"]
            LandlockSandboxExecutor._check_lean_grant = originals["grant_capture_check"]
            TypedPolicyBackend.filter = originals["policy_filter"]
            LandlockSandboxExecutor._lower = originals["landlock_lower"]
            LandlockSandboxExecutor._limits = originals["limits"]
            LandlockSandboxExecutor._pool_key = originals["pool_key"]
            dispatcher._new_worker = originals["new_worker"]
            _ObjectWorker._compile_grant = originals["compile_grant"]
            _ObjectWorker._prepare_grant = originals["prepare_grant"]
            _ObjectWorker._bind_prepared_policy = originals["bind_policy"]
            _ObjectBroker.bind_prepared_session = originals["bind_session"]
            landlock_module._capture_controller_receipt_certificate = originals[
                "capture_certificate"
            ]
            _ObjectWorker._receipt = originals["receipt"]
            linux_module._encode_worker_request = originals["encode_worker_request"]
            linux_module._readline_json = originals["readline_json"]
            _LandlockObjectAdapter.attest = originals["host_attest"]
            _ObjectWorker._bind_prepared_mediators = originals["bind_mediators"]
            _LandlockObjectAdapter.bind_worker = originals["bind_worker"]
            EnforcementCoordinator.activate = originals["coordinator_activate"]
            EnforcementCoordinator.validate_receipt = originals["coordinator_validate"]
            _ObjectBroker._handle_frame = originals["broker_frame"]
            BrokerSession.close_parent = originals["broker_close"]
            dispatcher.close()
            if sink is not None:
                sink.close()


def main() -> None:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--output", type=Path, required=True)
    parser.add_argument("--sessions", type=int, default=5)
    parser.add_argument("--warmups", type=int, default=10)
    parser.add_argument("--measured", type=int, default=20)
    parser.add_argument("--session", type=int)
    parser.add_argument("--route", choices=("baseline", "protected"), default="protected")
    parser.add_argument("--checker-library", type=Path)
    parser.add_argument("--checker-runtime", type=Path)
    parser.add_argument(
        "--audit",
        action="store_true",
        help="enable durable SQLite audit logging (disabled by default)",
    )
    args = parser.parse_args()
    if args.checker_library is not None:
        os.environ["ARGUS_LIFECYCLE_CHECKER_LIBRARY"] = str(
            args.checker_library.resolve(strict=True)
        )
    if args.checker_runtime is not None:
        os.environ["ARGUS_LIFECYCLE_CHECKER_RUNTIME"] = str(
            args.checker_runtime.resolve(strict=True)
        )
    if args.route == "protected" and not {
        "ARGUS_LIFECYCLE_CHECKER_LIBRARY",
        "ARGUS_LIFECYCLE_CHECKER_RUNTIME",
    }.issubset(os.environ):
        parser.error("--checker-library and --checker-runtime are required")
    if args.session is not None:
        if args.route == "baseline":
            run_baseline_session(args.output, args.session, args.warmups, args.measured)
        else:
            run_session(
                args.output,
                args.session,
                args.warmups,
                args.measured,
                audit=args.audit,
            )
        return
    args.output.mkdir(parents=True, exist_ok=False)
    for session in range(args.sessions):
        routes = ("baseline", "protected") if session % 2 == 0 else ("protected", "baseline")
        for route in routes:
            command = [
                sys.executable,
                __file__,
                "--output",
                str(args.output / f"session-{session}-{route}.jsonl"),
                "--warmups",
                str(args.warmups),
                "--measured",
                str(args.measured),
                "--session",
                str(session),
                "--route",
                route,
            ]
            if args.audit and route == "protected":
                command.append("--audit")
            log = args.output / f"session-{session}-{route}.log"
            with log.open("x") as stream:
                subprocess.run(command, check=True, stdout=stream, stderr=subprocess.STDOUT)
        print(f"broker session {session} complete", flush=True)


if __name__ == "__main__":
    main()
