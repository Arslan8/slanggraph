"""End-to-end SLP/Cedar enforcement, using real Linux workers and Cedar."""

import asyncio
import hashlib
import json
import shutil
import sys
from dataclasses import replace
from pathlib import Path
from threading import Event

import pytest
from langchain_core.messages import AIMessage
from langchain_core.tools import tool
from langgraph.graph import START, MessagesState, StateGraph

from langgraph.prebuilt import ToolNode
from langgraph.prebuilt.security import (
    EnforcementKind,
    HostExecutionDenied,
    HostExecutionError,
    LinuxToolSpec,
    ObjectBrokerDispatcher,
    ObjectGrant,
    ObjectGrantLine,
    Principal,
    Requirement,
    Tool,
    ToolCall,
    ToolDac,
    cedar_security,
    with_principal,
)
from langgraph.prebuilt.security.capabilities import probe_landlock_abi
from tests.security.mediator_fixtures import exact_mediator

pytestmark = pytest.mark.skipif(
    probe_landlock_abi() < 5, reason="Landlock ABI 5 required"
)

CLASSES = """
class record {
  operations read
  object item
  normalizer identity
  attrs
  enforced_by broker
}
"""
POLICY = 'permit(principal == slangGraph::User::"alice", action, resource);'


@pytest.fixture
def isolated(tmp_path):
    source = tmp_path / "worker.py"
    source.write_text("""
import os
import ctypes
from langgraph.prebuilt.security.object_broker import object_request

def run(path, other, operation="read", selector="record-1"):
    result = {"allowed": open(path).read()}
    try:
        result["other"] = open(other).read()
    except OSError:
        result["other"] = "blocked"
    libc = ctypes.CDLL(None, use_errno=True)
    fd = libc.open(other.encode(), os.O_RDONLY)
    result["native_blocked"] = fd < 0
    if fd >= 0:
        os.close(fd)
    try:
        result["broker"] = object_request("record", operation, selector)
    except PermissionError:
        result["broker"] = "denied"
    return result
""")
    allowed = tmp_path / "allowed"
    allowed.write_text("permitted")
    other = tmp_path / "secret"
    other.write_text("private")
    seen = []

    def handle(line, payload):
        seen.append((line.selector, dict(payload)))
        return "brokered"

    dispatcher = ObjectBrokerDispatcher(
        {
            "read_record": LinuxToolSpec(
                "worker:run", source, hashlib.sha256(source.read_bytes()).hexdigest()
            )
        },
        mediators=(exact_mediator({("record", "read"): handle}),),
        runtime_roots=tuple(Path(p) for p in sys.path if p and Path(p).is_dir()),
    )
    principal = Principal("alice", frozenset(), frozenset(), "session")
    call = ToolCall(
        Tool("read_record", ToolDac("owner", {"*": "x"}), frozenset(), ()),
        {"path": str(allowed), "other": str(other)},
        {},
        "call-1",
        0,
    )
    return dispatcher, principal, call, seen


def security_for(dispatcher, **kwargs):
    @tool
    def read_record(path: str, other: str) -> str:
        """Trusted schema only; body must never execute."""
        raise AssertionError("coordinator execution")

    return cedar_security(
        read_record,
        manifest="runs linux\nfs read @{path} need\nrecord read record-1 need",
        classes=CLASSES,
        policy=POLICY,
        dispatcher=dispatcher,
        **kwargs,
    )


@pytest.mark.skipif(shutil.which("cedar") is None, reason="Cedar CLI required")
def test_cedar_to_kernel_and_broker(isolated):
    dispatcher, principal, call, seen = isolated
    executor = security_for(dispatcher).host_executor
    result = executor.invoke(principal, call, ())
    assert result.value == {
        "allowed": "permitted",
        "other": "blocked",
        "native_blocked": True,
        "broker": "brokered",
    }
    assert seen == [("record-1", {})]
    assert result.receipt.grant_digest == executor.authorization_grants()[-1].digest
    assert len(result.receipt.rule_enforcement) == 2
    with pytest.raises(HostExecutionDenied, match="object_policy"):
        executor.invoke(replace(principal, user_id="mallory"), call, ())
    assert len(seen) == 1


@pytest.mark.skipif(shutil.which("cedar") is None, reason="Cedar CLI required")
def test_mac_denial_prevents_dispatch(isolated):
    dispatcher, principal, call, seen = isolated
    executor = security_for(
        dispatcher, mac_forbids="forbid(principal, action, resource);"
    ).host_executor
    with pytest.raises(HostExecutionDenied):
        executor.invoke(principal, call, ())
    assert not seen
    assert not dispatcher.audit_records()


@pytest.mark.skipif(shutil.which("cedar") is None, reason="Cedar CLI required")
def test_directory_is_not_widened_to_recursive_access(isolated, tmp_path):
    dispatcher, principal, call, seen = isolated
    executor = security_for(dispatcher).host_executor
    with pytest.raises(HostExecutionDenied, match="required_authority_removed"):
        executor.invoke(
            principal, replace(call, args={**call.args, "path": str(tmp_path)}), ()
        )
    assert not seen


@pytest.mark.skipif(shutil.which("cedar") is None, reason="Cedar CLI required")
def test_authorized_argument_normalization_reaches_worker(isolated):
    dispatcher, principal, call, seen = isolated
    executor = security_for(dispatcher).host_executor
    normalized = {"path": call.args["path"]}
    call = replace(
        call, args={**call.args, "path": "/untrusted/raw"}, normalized=normalized
    )
    assert executor.invoke(principal, call, ()).value["allowed"] == "permitted"


def test_helper_rejects_implicit_or_trusted_execution(isolated):
    dispatcher, *_ = isolated

    @tool
    def schema() -> str:
        """Schema only."""
        raise AssertionError

    with pytest.raises(ValueError, match="runs linux, macos or broker"):
        cedar_security(schema, policy=POLICY, dispatcher=dispatcher)
    with pytest.raises(ValueError, match="missing manifests"):
        cedar_security(
            schema, manifest="runs linux", policy=POLICY, dispatcher=dispatcher
        )
    with pytest.raises(ValueError, match="unsupported_class"):
        cedar_security(
            schema,
            manifest="runs linux\nrecord read x need",
            classes=CLASSES.replace(
                "enforced_by broker", "enforced_by language_sandbox"
            ),
            policy=POLICY,
            dispatcher=dispatcher,
        )


async def test_cancellation_waits_for_active_worker(isolated):
    dispatcher, principal, call, _ = isolated
    started, release = Event(), Event()

    def handler(line, payload):
        started.set()
        assert release.wait(10)
        return "finished"

    dispatcher = ObjectBrokerDispatcher(
        dispatcher.tools,
        mediators=(exact_mediator({("record", "read"): handler}),),
        runtime_roots=dispatcher.runtime_roots,
    )
    lines = (
        ObjectGrantLine(
            "fs",
            "fs",
            "read",
            call.args["path"],
            {},
            Requirement.NEED,
            EnforcementKind.KERNEL,
        ),
        ObjectGrantLine(
            "record",
            "record",
            "read",
            "record-1",
            {},
            Requirement.NEED,
            EnforcementKind.BROKER,
        ),
    )
    grant = ObjectGrant(
        principal.user_id, call.tool.name, call.call_id, "policy", lines
    )
    task = asyncio.create_task(dispatcher.ainvoke(principal, call, grant))
    try:
        assert await asyncio.to_thread(started.wait, 10)
        task.cancel()
        await asyncio.sleep(0.05)
        assert not task.done()
        task.cancel()
        await asyncio.sleep(0.05)
        assert not task.done()
    finally:
        release.set()
    with pytest.raises(asyncio.CancelledError):
        await task


@pytest.mark.skipif(shutil.which("cedar") is None, reason="Cedar CLI required")
def test_artifact_replacement_after_verification_uses_pinned_bytes(
    isolated, monkeypatch
):
    dispatcher, principal, call, seen = isolated
    executor = security_for(dispatcher).host_executor
    from_module = sys.modules["langgraph.prebuilt.security.object_broker"]
    compile_grant = from_module._ObjectWorker._compile_grant

    def replace_original(worker, *args):
        dispatcher.tools[call.tool.name].artifact_path.write_text(
            "raise RuntimeError('replaced')"
        )
        return compile_grant(worker, *args)

    monkeypatch.setattr(from_module._ObjectWorker, "_compile_grant", replace_original)
    assert executor.invoke(principal, call, ()).value["broker"] == "brokered"
    assert seen


@pytest.mark.skipif(shutil.which("cedar") is None, reason="Cedar CLI required")
def test_symlink_substitution_after_authorization_is_denied(isolated, monkeypatch):
    dispatcher, principal, call, seen = isolated
    executor = security_for(dispatcher).host_executor
    module = sys.modules["langgraph.prebuilt.security.object_broker"]
    compile_grant = module._ObjectWorker._compile_grant

    def swap_path(worker, *args):
        allowed = Path(call.args["path"])
        allowed.unlink()
        allowed.symlink_to(call.args["other"])
        return compile_grant(worker, *args)

    monkeypatch.setattr(module._ObjectWorker, "_compile_grant", swap_path)
    with pytest.raises(HostExecutionDenied):
        executor.invoke(principal, call, ())
    assert not seen


@pytest.mark.parametrize("operation", ["read", "write", "truncate"])
def test_kernel_file_operations_do_not_imply_each_other(isolated, operation):
    dispatcher, principal, call, _ = isolated
    source = dispatcher.tools[call.tool.name].artifact_path
    source.write_text("""
import os

def run(path, other):
    result = {}
    try:
        with open(path) as stream:
            stream.read()
        result["read"] = True
    except OSError:
        result["read"] = False
    try:
        fd = os.open(path, os.O_WRONLY)
        try:
            os.write(fd, b"updated")
        finally:
            os.close(fd)
        result["write"] = True
    except OSError:
        result["write"] = False
    try:
        os.truncate(path, 0)
        result["truncate"] = True
    except OSError:
        result["truncate"] = False
    return result
""")
    spec = LinuxToolSpec(
        "worker:run", source, hashlib.sha256(source.read_bytes()).hexdigest()
    )
    dispatcher = ObjectBrokerDispatcher(
        {call.tool.name: spec}, {}, runtime_roots=dispatcher.runtime_roots
    )
    line = ObjectGrantLine(
        "file",
        "fs",
        operation,
        call.args["path"],
        {},
        Requirement.NEED,
        EnforcementKind.KERNEL,
    )
    grant = ObjectGrant(
        principal.user_id, call.tool.name, call.call_id, "policy", (line,)
    )
    assert dispatcher.invoke(principal, call, grant).value == {
        name: name == operation for name in ("read", "write", "truncate")
    }


async def test_worker_exit_does_not_claim_broker_operation_terminated(isolated):
    dispatcher, principal, call, _ = isolated
    source = dispatcher.tools[call.tool.name].artifact_path
    source.write_text("""
import json
import os
import time

def run(path, other):
    request = {"service": '["record","record-1"]', "operation": "read", "payload": {}}
    os.write(int(os.environ["SLANGGRAPH_BROKER_FD"]), json.dumps(request).encode() + b"\\n")
    for _ in range(200):
        if open(path).read() == "handler-started":
            return "worker-finished"
        time.sleep(0.01)
    raise RuntimeError("handler did not start")
""")
    release, finished, lease_released = Event(), Event(), Event()

    def handler(line, payload):
        Path(call.args["path"]).write_text("handler-started")
        try:
            assert release.wait(10)
            return "handler-finished"
        finally:
            finished.set()

    spec = LinuxToolSpec(
        "worker:run", source, hashlib.sha256(source.read_bytes()).hexdigest()
    )
    dispatcher = ObjectBrokerDispatcher(
        {call.tool.name: spec},
        mediators=(
            replace(
                exact_mediator({("record", "read"): handler}),
                release=lambda context: lease_released.set(),
            ),
        ),
        runtime_roots=dispatcher.runtime_roots,
    )
    lines = (
        ObjectGrantLine(
            "file",
            "fs",
            "read",
            call.args["path"],
            {},
            Requirement.NEED,
            EnforcementKind.KERNEL,
        ),
        ObjectGrantLine(
            "record",
            "record",
            "read",
            "record-1",
            {},
            Requirement.NEED,
            EnforcementKind.BROKER,
        ),
    )
    grant = ObjectGrant(
        principal.user_id, call.tool.name, call.call_id, "policy", lines
    )
    try:
        with pytest.raises(
            HostExecutionError, match="broker_operation_still_running"
        ) as caught:
            await dispatcher.ainvoke(principal, call, grant)
        assert not caught.value.termination_confirmed
        assert caught.value.receipt.grant_digest == grant.digest
        assert not lease_released.is_set()
    finally:
        release.set()
        assert await asyncio.to_thread(finished.wait, 5)
        assert await asyncio.to_thread(lease_released.wait, 5)


@pytest.mark.skipif(shutil.which("cedar") is None, reason="Cedar CLI required")
@pytest.mark.parametrize("asynchronous", [False, True])
async def test_toolnode_uses_isolated_helper_without_executing_stub(
    isolated, asynchronous
):
    dispatcher, principal, call, seen = isolated

    @tool
    def read_record(path: str, other: str) -> str:
        """Schema only."""
        raise AssertionError("tool body ran in coordinator")

    security = cedar_security(
        read_record,
        manifest="runs linux\nfs read @{path} need\nrecord read record-1 need",
        classes=CLASSES,
        policy=POLICY,
        dispatcher=dispatcher,
    )
    builder = StateGraph(MessagesState)
    builder.add_node("tools", ToolNode([read_record]))
    builder.add_edge(START, "tools")
    node = builder.compile(security=security)
    config = with_principal({}, principal, modules=security.modules)
    inputs = {
        "messages": [
            AIMessage(
                content="",
                tool_calls=[
                    {
                        "name": call.tool.name,
                        "args": dict(call.args),
                        "id": call.call_id,
                    }
                ],
            )
        ]
    }
    result = (
        await node.ainvoke(inputs, config=config)
        if asynchronous
        else node.invoke(inputs, config=config)
    )
    message = result["messages"][-1]
    assert message.status == "success", message.content
    assert json.loads(message.content)["broker"] == "brokered"
    assert seen == [("record-1", {})]
