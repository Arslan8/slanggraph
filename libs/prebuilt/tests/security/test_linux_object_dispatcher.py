"""Sealed Cedar-to-Linux dispatch and malicious implementation tests."""

from __future__ import annotations

import hashlib
from dataclasses import replace
from pathlib import Path

import pytest
from langchain_core.messages import AIMessage
from langchain_core.tools import tool
from langgraph._internal import _runtime_policy
from langgraph.graph import START, MessagesState, StateGraph

from langgraph.prebuilt import ToolNode
from langgraph.prebuilt.security import (
    HostExecutionError,
    LinuxObjectDispatcher,
    LinuxToolSpec,
    Principal,
    cedar_security,
    install_mac_policy,
    with_principal,
)
from langgraph.prebuilt.security.linux_object import _object_authority_key
from langgraph.prebuilt.security.object_policy import (
    EnforcementKind,
    ObjectGrant,
    ObjectGrantLine,
)
from langgraph.prebuilt.security.profile import Requirement
from langgraph.prebuilt.security.types import Tool, ToolCall, ToolDac

_FIXTURES = Path(__file__).with_name("fixtures")
_ARTIFACT = _FIXTURES / "linux_tools.py"


@tool
def read_file(path: str) -> str:
    """Read one exact file in an isolated worker."""
    raise AssertionError("unconfined callback executed")


@tool
def hostile_probe(path: str, forbidden_path: str) -> str:
    """Receive an allowed path but substitute a forbidden path internally."""
    raise AssertionError("unconfined callback executed")


@pytest.fixture(autouse=True)
def isolated_runtime(monkeypatch):
    monkeypatch.delenv("LANGGRAPH_MAC_DIR", raising=False)
    monkeypatch.setattr(_runtime_policy, "_policy", None)
    monkeypatch.setattr(_runtime_policy, "_started", False)
    monkeypatch.setattr(_runtime_policy, "_system_loaded", True)


def _dispatcher(*names: str, worker_pool_capacity: int = 0) -> LinuxObjectDispatcher:
    digest = hashlib.sha256(_ARTIFACT.read_bytes()).hexdigest()
    return LinuxObjectDispatcher(
        {
            name: LinuxToolSpec(f"linux_tools:{name}", _ARTIFACT, digest)
            for name in names
        },
        runtime_roots=(_FIXTURES,),
        worker_pool_capacity=worker_pool_capacity,
    )


def _graph(selected, dispatcher):
    security = cedar_security(
        selected,
        manifest="runs linux\nfs read @{path} need",
        policy='permit(principal == slangGraph::User::"alice", action, resource);',
        dispatcher=dispatcher,
    )
    security = replace(security, closed_admission=True)
    node = ToolNode([selected], security=security)
    builder = StateGraph(MessagesState)
    builder.add_node("tools", node)
    builder.add_edge(START, "tools")
    return builder.compile(security=security), security


def _invoke(graph, security, name, arguments):
    principal = Principal("alice", frozenset(), frozenset(), "session")
    return graph.invoke(
        {
            "messages": [
                AIMessage(
                    content="",
                    tool_calls=[
                        {
                            "name": name,
                            "args": arguments,
                            "id": f"{name}-call",
                        }
                    ],
                )
            ]
        },
        config=with_principal({}, principal, modules=security.modules),
    )["messages"][-1]


def test_sealed_linux_object_read_succeeds(tmp_path):
    allowed = tmp_path / "allowed.txt"
    allowed.write_text("ALICE_ALLOWED")
    dispatcher = _dispatcher("read_file")
    install_mac_policy(
        'forbid(principal, action == slangGraph::Action::"fs::write", resource);'
    )
    graph, security = _graph(read_file, dispatcher)

    message = _invoke(graph, security, "read_file", {"path": str(allowed)})

    assert message.status == "success"
    assert message.content == "ALICE_ALLOWED"
    assert len(dispatcher.activation_receipts()) == 1
    lowering = dispatcher.lowering_records()[0]
    assert (
        lowering["object_grant_digest"]
        == security.host_executor.authorization_grants()[0].digest
    )
    assert lowering["object_grant_digest"] != lowering["native_grant_digest"]


def test_object_dispatcher_claims_shared_prewarmed_worker(tmp_path, monkeypatch):
    allowed = tmp_path / "allowed.txt"
    allowed.write_text("POOLED_OBJECT")
    dispatcher = _dispatcher("read_file", worker_pool_capacity=1)
    install_mac_policy(
        'forbid(principal, action == slangGraph::Action::"fs::write", resource);'
    )
    _, security = _graph(read_file, dispatcher)
    principal = Principal("alice", frozenset(), frozenset(), "session")
    call = ToolCall(
        Tool("read_file", ToolDac("owner", {}), frozenset(), ()),
        {"path": str(allowed)},
        {},
        "pooled-call",
        0,
    )
    executor = security.host_executor
    grant = executor._authorize(principal, call, ())
    try:
        assert dispatcher.prewarm(principal, call, grant, count=1) == 1
        assert dispatcher.activation_receipts() == ()
        monkeypatch.setattr(
            "langgraph.prebuilt.security.linux_object._exact_file",
            lambda *_args: (_ for _ in ()).throw(
                AssertionError("runtime repeated preflight path lowering")
            ),
        )
        monkeypatch.setattr(
            "langgraph.prebuilt.security.linux._LinuxBubblewrapAdapter.lower",
            lambda *_args: (_ for _ in ()).throw(
                AssertionError("runtime repeated host-policy lowering")
            ),
        )
        result = dispatcher.invoke(principal, call, grant)
        assert result.value == "POOLED_OBJECT"
        assert dict(dispatcher.worker_pool_stats()) == {
            "capacity": 1,
            "hits": 1,
            "idle": 0,
            "misses": 0,
        }
    finally:
        dispatcher.close()


def test_runtime_binds_prepared_host_policy_without_relowering(tmp_path, monkeypatch):
    allowed = tmp_path / "allowed.txt"
    allowed.write_text("PREPARED")
    monkeypatch.setattr(
        "langgraph.prebuilt.security.linux._verify_bubblewrap_host",
        lambda *_args: None,
    )
    dispatcher = _dispatcher("read_file", worker_pool_capacity=1)
    principal = Principal("alice", frozenset(), frozenset(), "session")

    def invocation(call_id: str):
        call = ToolCall(
            Tool("read_file", ToolDac("owner", {}), frozenset(), ()),
            {"path": str(allowed)},
            {},
            call_id,
            0,
        )
        grant = ObjectGrant(
            "alice",
            "read_file",
            call_id,
            "policy-digest",
            (
                ObjectGrantLine(
                    "fs:read:path",
                    "fs",
                    "read",
                    str(allowed),
                    {},
                    Requirement.NEED,
                    EnforcementKind.KERNEL,
                ),
            ),
        )
        return call, grant

    preflight_call, preflight_grant = invocation("preflight")
    template = dispatcher._new_worker(
        principal, preflight_call, preflight_grant, preflight=True
    )
    template._prepare_execution(
        principal,
        preflight_call,
        (),
        asynchronous=False,
        preflight=True,
    )
    assert template.lowered_grant is not None
    # The dispatcher and generic executor intentionally use different keys.
    object_key = _object_authority_key(preflight_grant)
    with dispatcher._lock:
        dispatcher._prepared_rules[object_key] = template.lowered_grant.rules
        dispatcher._prepared_workers[object_key] = template

    monkeypatch.setattr(
        "langgraph.prebuilt.security.linux_object._exact_file",
        lambda *_args: (_ for _ in ()).throw(AssertionError("path relowered")),
    )
    monkeypatch.setattr(
        "langgraph.prebuilt.security.linux._LinuxBubblewrapAdapter.lower",
        lambda *_args: (_ for _ in ()).throw(AssertionError("host policy relowered")),
    )
    runtime_call, runtime_grant = invocation("runtime")
    runtime = dispatcher._new_worker(principal, runtime_call, runtime_grant)
    prepared = runtime._prepare_execution(
        principal,
        runtime_call,
        (),
        asynchronous=False,
        preflight=False,
    )
    assert (
        prepared.plan.adapter_plans
        == next(
            iter(dispatcher._worker_pool_state.prepared_policies.values())
        ).adapter_plans
    )


def test_internal_path_substitution_is_blocked_after_legitimate_call(tmp_path):
    allowed = tmp_path / "allowed.txt"
    forbidden = tmp_path / "forbidden.txt"
    allowed.write_text("ALICE_ALLOWED")
    forbidden.write_text("BOB_SYNTHETIC_SECRET_7be9")
    dispatcher = _dispatcher("hostile_probe")
    install_mac_policy(
        'forbid(principal, action == slangGraph::Action::"fs::write", resource);'
    )
    graph, security = _graph(hostile_probe, dispatcher)

    with pytest.raises(HostExecutionError, match="FileNotFoundError") as caught:
        _invoke(
            graph,
            security,
            "hostile_probe",
            {"path": str(allowed), "forbidden_path": str(forbidden)},
        )

    assert "BOB_SYNTHETIC_SECRET_7be9" not in str(caught.value)
    assert forbidden.read_text() == "BOB_SYNTHETIC_SECRET_7be9"
    assert len(dispatcher.activation_receipts()) == 1
