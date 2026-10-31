"""Real native object and broker routes, including the runtime Lean gates."""

from __future__ import annotations

import copy
import hashlib
import json
import platform
import shutil
import sys
from dataclasses import replace
from pathlib import Path

import pytest
from langchain_core.messages import AIMessage
from langchain_core.tools import tool
from langgraph._internal import _runtime_policy
from langgraph.graph import START, MessagesState, StateGraph

from langgraph.prebuilt import ToolNode
from langgraph.prebuilt.security import (
    MacOSNativeLauncher,
    MacOSObjectDispatcher,
    MacOSToolSpec,
    cedar_security,
    install_mac_policy,
    with_principal,
)
from langgraph.prebuilt.security.enforcement import SupportLevel
from langgraph.prebuilt.security.execution import HostExecutionDenied
from langgraph.prebuilt.security.lean_lifecycle import LeanLifecycleChecker
from langgraph.prebuilt.security.object_policy import (
    EnforcementKind,
    ObjectGrant,
    ObjectGrantLine,
)
from langgraph.prebuilt.security.profile import Requirement
from langgraph.prebuilt.security.resource_mediator import (
    ResourceMediatorAdapter,
    ResourceSupport,
)
from langgraph.prebuilt.security.types import Principal, Tool, ToolCall, ToolDac

pytestmark = pytest.mark.skipif(
    platform.system() != "Darwin", reason="native macOS required"
)


@pytest.fixture(scope="module")
def native(tmp_path_factory):
    root = Path(__file__).resolve().parents[4]
    path = root / "proofs/worker-route/.lake/build/lib/libargus_worker_route.dylib"
    manifest = path.with_suffix(".dylib.json")
    if not manifest.is_file():
        pytest.skip("build the pinned macOS Lean library first")
    data = json.loads(manifest.read_text())
    checker = LeanLifecycleChecker(
        str(path), data["sha256"], data["native_runtime"], data["native_runtime_sha256"]
    )
    launcher = MacOSNativeLauncher.build(
        tmp_path_factory.mktemp("object-native") / "launcher"
    )
    roots = tuple(
        root / "libs" / name
        for name in ("prebuilt", "langgraph", "checkpoint", "sdk-py")
    )
    roots += tuple(
        Path(value).resolve()
        for value in sys.path
        if value and "site-packages" in value and Path(value).is_dir()
    )
    roots += tuple(
        Path(value)
        for value in json.loads((launcher.path.parent / "manifest.json").read_text())[
            "dependency_roots"
        ]
    )
    aliases = json.loads((launcher.path.parent / "manifest.json").read_text()).get(
        "runtime_aliases", {}
    )
    images = json.loads((launcher.path.parent / "manifest.json").read_text()).get(
        "runtime_libraries", ()
    )
    return launcher, checker, roots, aliases, images


@pytest.fixture
def route(tmp_path, native):
    launcher, checker, roots, aliases, images = native
    code = tmp_path / "code"
    code.mkdir()
    secret = tmp_path / "protected.txt"
    secret.write_text("private")
    source = code / "worker.py"
    source.write_text("""
import os
import socket
from langgraph.prebuilt.security.object_broker import object_request

def run(operation="read", selector="one", path="", attack=""):
    if attack == "file":
        try:
            return open(path).read()
        except OSError:
            return "blocked"
    if attack == "network":
        try:
            socket.socket().connect(("127.0.0.1", 9))
        except OSError:
            return "blocked"
    if attack == "fork":
        try:
            child = os.fork()
        except OSError:
            return "blocked"
        if child == 0:
            os._exit(0)
        os.waitpid(child, 0)
        return "escaped"
    try:
        return object_request("record", operation, selector)
    except PermissionError:
        return "denied"
""")
    seen = []

    def assess(line, host):
        if line.class_name == "record" and line.operation == "read":
            return ResourceSupport(
                SupportLevel.EXACT,
                "one record",
                "macos-object-regression",
                protected_paths=(str(secret),),
                required_capabilities=frozenset({"seatbelt", "broker:spawn-bound"}),
            )
        return ResourceSupport(SupportLevel.UNSUPPORTED, "unknown resource")

    def invoke(line, payload, context):
        seen.append((line.selector, context.principal_id, context.worker.broker_epoch))
        return "brokered"

    dispatcher = MacOSObjectDispatcher(
        {
            "read_record": MacOSToolSpec(
                "worker:run", source, hashlib.sha256(source.read_bytes()).hexdigest()
            )
        },
        launcher=launcher,
        lifecycle_checker=checker,
        recovery_directory=tmp_path / "recovery",
        runtime_roots=(code, *roots),
        executable_roots=roots,
        runtime_aliases=aliases,
        runtime_libraries=images,
        mediators=(ResourceMediatorAdapter("record-mediator", assess, invoke),),
    )
    principal = Principal("alice", frozenset(), frozenset(), "session")
    call = ToolCall(
        Tool("read_record", ToolDac("owner", {"*": "x"}), frozenset(), ()),
        {},
        {},
        "call",
        0,
    )
    grant = ObjectGrant(
        "alice",
        "read_record",
        "call",
        "policy",
        (
            ObjectGrantLine(
                "record:0",
                "record",
                "read",
                "one",
                {},
                Requirement.NEED,
                EnforcementKind.BROKER,
            ),
        ),
    )
    return dispatcher, principal, call, grant, seen, secret


def test_broker_result_receipt_and_cleanup(route):
    dispatcher, principal, call, grant, seen, _ = route
    result = dispatcher.invoke(principal, call, grant)
    assert result.value == "brokered"
    assert result.receipt.grant_digest == grant.digest
    assert len(seen) == 1 and seen[0][:2] == ("one", "alice")
    assert seen[0][2] != "no-broker"
    assert dispatcher.audit_records()[0].allowed
    assert not list(dispatcher.recovery_directory.glob("*.json"))
    traces = dispatcher.lifecycle_records()
    assert len(traces) == 1 and traces[0]["cleanup_confirmed"]
    assert not any(
        rule["domain"] == "resource_limit" and rule["selector"] == "cpu_ms"
        for rule in traces[0]["certificate"]["grant"]["rules"]
    )
    dispatcher.lifecycle_checker.require(
        traces[0]["binding"],
        traces[0]["events"],
        "ready",
        certificate=traces[0]["certificate"],
        object_route=True,
    )


@pytest.mark.parametrize(
    "arguments,expected",
    [
        ({"operation": "write"}, "denied"),
        ({"selector": "other"}, "denied"),
        ({"attack": "file"}, "blocked"),
        ({"attack": "network"}, "blocked"),
        ({"attack": "fork"}, "blocked"),
    ],
)
def test_broker_cannot_expand_authority(route, arguments, expected):
    dispatcher, principal, call, grant, seen, secret = route
    result = dispatcher.invoke(
        principal, replace(call, args={**arguments, "path": str(secret)}), grant
    )
    assert result.value == expected
    assert not seen
    assert secret.read_text() == "private"


def test_wrong_grant_binding_refused(route):
    dispatcher, principal, call, grant, seen, _ = route
    with pytest.raises(HostExecutionDenied, match="grant_binding"):
        dispatcher.invoke(principal, call, replace(grant, call_id="other"))
    assert not seen


@pytest.mark.parametrize("mutation", ["missing", "selector", "dependency", "custody"])
def test_lean_refuses_resource_inventory_mutations(route, monkeypatch, mutation):
    dispatcher, principal, call, grant, seen, _ = route
    original = LeanLifecycleChecker.require_grant

    def altered(self, captured, obligations, *, object_route=False):
        changed = copy.deepcopy(obligations)
        row = next(row for row in changed if row["id"].endswith(":bypass"))
        if mutation == "missing":
            changed.remove(row)
        elif mutation == "selector":
            row["selector"] = "other"
        elif mutation == "dependency":
            row["dependencies"] = []
        else:
            next(row for row in changed if row["id"].endswith(":custody"))[
                "operation"
            ] = "worker_credentials"
        return original(self, captured, changed, object_route=object_route)

    monkeypatch.setattr(LeanLifecycleChecker, "require_grant", altered)
    with pytest.raises(HostExecutionDenied, match="lean_lifecycle_refused"):
        dispatcher.invoke(principal, call, grant)
    assert not seen


@pytest.fixture
def closed_graph(route, monkeypatch):
    if shutil.which("cedar") is None:
        pytest.skip("pinned Cedar CLI required")

    monkeypatch.setattr(_runtime_policy, "_policy", None)
    monkeypatch.setattr(_runtime_policy, "_started", False)
    monkeypatch.setattr(_runtime_policy, "_system_loaded", True)
    install_mac_policy(
        'forbid(principal == slangGraph::User::"blocked", action, resource);'
    )

    @tool
    def read_record() -> str:
        """Read the caller's exact record through the native worker."""
        raise AssertionError("unconfined body executed")

    dispatcher, principal, _, _, seen, _ = route
    config = cedar_security(
        read_record,
        dispatcher=dispatcher,
        classes="class record {\noperations read\nobject item\nnormalizer identity\nattrs\nenforced_by broker\n}",
        manifest="runs macos\nrecord read one need",
        policy='permit(principal == slangGraph::User::"alice", action, resource);',
    )
    config = replace(config, closed_admission=True)
    builder = StateGraph(MessagesState)
    builder.add_node("tools", ToolNode([read_record], security=config))
    builder.add_edge(START, "tools")
    graph = builder.compile(security=config)
    return graph, config, dispatcher, principal, seen


def _invoke_closed(fixture):

    graph, config, _, principal, _ = fixture
    return graph.invoke(
        {
            "messages": [
                AIMessage(
                    "", tool_calls=[{"name": "read_record", "args": {}, "id": "call"}]
                )
            ]
        },
        with_principal({}, principal, modules=config.modules),
    )


def test_closed_admission_cedar_mac_and_native_broker(closed_graph):
    result = _invoke_closed(closed_graph)
    assert result["messages"][-1].content == "brokered"
    assert result["messages"][-1].status == "success"
    assert closed_graph[2].activation_receipts()
    assert len(closed_graph[4]) == 1


@pytest.mark.parametrize(
    "field", ["runtime_roots", "runtime_libraries", "lifecycle_checker", "mediators"]
)
def test_admitted_route_mutation_refused(closed_graph, field, tmp_path):
    dispatcher = closed_graph[2]
    if field == "runtime_roots":
        dispatcher.runtime_roots += (tmp_path,)
    elif field == "runtime_libraries":
        dispatcher.runtime_libraries = ()
    elif field == "mediators":
        dispatcher.mediators = (
            replace(dispatcher.mediators[0], invoke=lambda *args: "unbound"),
        )
    else:
        dispatcher.lifecycle_checker = None
    with pytest.raises((PermissionError, ValueError), match="admission:"):
        _invoke_closed(closed_graph)
    assert not closed_graph[4]
    assert not dispatcher.activation_receipts()
