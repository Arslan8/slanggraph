"""Runtime MAC cannot be omitted by another graph, session, or ToolNode."""

import asyncio
import os
import shutil
import subprocess
import sys
from concurrent.futures import ThreadPoolExecutor
from types import SimpleNamespace

import pytest
from langchain_core.messages import AIMessage
from langgraph._internal import _runtime_policy
from langgraph.channels import LastValue
from langgraph.func import entrypoint
from langgraph.graph import END, START, MessagesState, StateGraph
from langgraph.pregel import NodeBuilder, Pregel
from langgraph.pregel.remote import RemoteGraph
from langgraph.runtime import Runtime

from langgraph.prebuilt import ToolNode
from langgraph.prebuilt.security import (
    HostExecutionDenied,
    ObjectPolicyDenied,
    Principal,
    SecurityConfig,
    SecurityConfigurationError,
    cedar_security,
    install_mac_policy,
    with_principal,
)
from langgraph.prebuilt.security.mac import _graph_boundaries
from tests.security.test_manifest_admission import MANIFEST, PERMIT, reader

FORBID = 'forbid(principal, action == slangGraph::Action::"fs::read", resource);'


@pytest.fixture(autouse=True)
def isolated_runtime(monkeypatch):
    monkeypatch.delenv("LANGGRAPH_MAC_DIR", raising=False)
    # Tests simulate separate interpreters. Production exposes no reset API.
    monkeypatch.setattr(_runtime_policy, "_policy", None)
    monkeypatch.setattr(_runtime_policy, "_started", False)
    monkeypatch.setattr(_runtime_policy, "_system_loaded", True)


def graph_for(node, security=None):
    builder = StateGraph(MessagesState)
    builder.add_node("tools", node)
    builder.add_edge(START, "tools")
    return builder.compile(security=security)


def test_policy_installation_is_sealed():
    install_mac_policy(FORBID)
    with pytest.raises(RuntimeError, match="already installed"):
        install_mac_policy("forbid(principal, action, resource);")


def test_installation_after_execution_is_rejected():
    graph_for(lambda state: {}).invoke({"messages": []})
    with pytest.raises(RuntimeError, match="before execution"):
        install_mac_policy(FORBID)


@pytest.mark.parametrize("forbids", ["", "permit(principal, action, resource);"])
def test_invalid_operator_policy(forbids):
    with pytest.raises(ValueError):
        install_mac_policy(forbids)
    assert _runtime_policy.runtime_policy() is None


def test_precompiled_unsecured_graph_and_direct_tool_node_are_refused():
    executed = []
    graph = graph_for(lambda state: executed.append(True) or {})
    node = ToolNode([reader])
    install_mac_policy(FORBID)
    with pytest.raises(SecurityConfigurationError, match="mac:graph_requires_security"):
        graph.invoke({"messages": []})
    with pytest.raises(SecurityConfigurationError, match="mac:tool_requires"):
        node.invoke({"messages": []}, runtime=Runtime())
    with pytest.raises(SecurityConfigurationError, match="mac:graph_requires_security"):
        asyncio.run(graph.ainvoke({"messages": []}))
    with pytest.raises(SecurityConfigurationError, match="mac:tool_requires"):
        asyncio.run(node.ainvoke({"messages": []}, runtime=Runtime()))
    with ThreadPoolExecutor() as pool:
        with pytest.raises(
            SecurityConfigurationError, match="mac:graph_requires_security"
        ):
            pool.submit(graph.invoke, {"messages": []}).result()
    assert not executed


@pytest.mark.skipif(shutil.which("cedar") is None, reason="Cedar CLI required")
def test_policy_applies_to_independent_graphs_and_sessions(tmp_path):
    path = tmp_path / "secret.txt"
    path.write_text("must not escape")
    # Build one executor before operator installation, the other afterwards.
    security = cedar_security(reader, manifest=MANIFEST, policy=PERMIT)
    first = graph_for(ToolNode([reader]), security)
    install_mac_policy(FORBID)
    other = cedar_security(reader, manifest=MANIFEST, policy=PERMIT, mac_forbids="")
    second = graph_for(ToolNode([reader]), other)
    for graph, config in ((first, security), (second, other)):
        for session in ("session-a", "session-b"):
            principal = Principal("alice", frozenset(), frozenset(), session)
            invocation = {
                "messages": [
                    AIMessage(
                        content="",
                        tool_calls=[
                            {
                                "name": "reader",
                                "args": {"path": str(path)},
                                "id": session,
                            }
                        ],
                    )
                ]
            }
            bound = with_principal({}, principal, modules=config.modules)
            for invoke in (
                graph.invoke,
                lambda value, config: asyncio.run(graph.ainvoke(value, config)),
            ):
                try:
                    result = invoke(invocation, config=bound)
                except HostExecutionDenied as exc:
                    assert "mac:forbid:" in str(exc)
                else:
                    message = result["messages"][-1]
                    assert message.status == "error"
                    assert "mac:forbid:" in message.content
                assert not config.host_executor.authorization_grants()


@pytest.mark.skipif(shutil.which("cedar") is None, reason="Cedar CLI required")
@pytest.mark.parametrize(
    "operator_policy",
    [
        'forbid(principal, action, resource) when { principal == slangGraph::User::"bob" };',
        'forbid(principal, action == slangGraph::Action::"internet::connect", resource);',
    ],
)
def test_unrelated_operation_remains_allowed(tmp_path, operator_policy):
    path = tmp_path / "public.txt"
    path.write_text("public")
    install_mac_policy(operator_policy)
    security = cedar_security(reader, manifest=MANIFEST, policy=PERMIT)
    graph = graph_for(ToolNode([reader]), security)
    result = graph.invoke(
        {
            "messages": [
                AIMessage(
                    content="",
                    tool_calls=[
                        {
                            "name": "reader",
                            "args": {"path": str(path)},
                            "id": "allowed",
                        }
                    ],
                )
            ]
        },
        config=with_principal(
            {},
            Principal("alice", frozenset(), frozenset(), "a"),
            modules=security.modules,
        ),
    )
    assert result["messages"][-1].content == "public"


def test_raw_pregel_and_functional_entrypoint_cannot_bypass_mac():

    raw = Pregel(
        nodes={"node": NodeBuilder().subscribe_only("input").write_to("output")},
        channels={"input": LastValue(int), "output": LastValue(int)},
        input_channels="input",
        output_channels="output",
    )

    @entrypoint()
    def function(value):
        raise AssertionError("must not execute")

    install_mac_policy(FORBID)
    for graph in (raw, function):
        with pytest.raises(
            SecurityConfigurationError, match="mac:unsupported_execution_boundary"
        ):
            graph.invoke(1)
        with pytest.raises(
            SecurityConfigurationError, match="mac:unsupported_execution_boundary"
        ):
            asyncio.run(graph.ainvoke(1))


@pytest.mark.skipif(shutil.which("cedar") is None, reason="Cedar CLI required")
def test_legacy_secured_graphs_keep_the_pre_admission_boundary():
    """Without closed admission the registry is the pre-admission shape test.

    An exact `MediatedNode` wrapping an exact `ToolNode` for every node and no
    branches records the wrapped ToolNodes; anything else records `None` and
    refuses with `mac:unconfined_graph_body`. Nothing is admitted at compile.
    """
    node = ToolNode([reader])
    plain = graph_for(node, cedar_security(reader, manifest=MANIFEST, policy=PERMIT))
    builder = StateGraph(MessagesState)
    builder.add_node("tools", ToolNode([reader]))
    builder.add_edge(START, "tools")
    builder.add_conditional_edges("tools", lambda state: END)
    branched = builder.compile(
        security=cedar_security(reader, manifest=MANIFEST, policy=PERMIT)
    )
    install_mac_policy(FORBID)

    boundary = _graph_boundaries[plain]
    assert type(boundary) is tuple and len(boundary) == 1 and boundary[0] is node
    _runtime_policy.check_runtime_policy(plain)
    assert _graph_boundaries[branched] is None
    with pytest.raises(SecurityConfigurationError, match="mac:unconfined_graph_body"):
        _runtime_policy.check_runtime_policy(branched)
    for graph in (plain, branched):
        assert not hasattr(graph.builder, "_security_admission")


def test_graph_local_trust_promotion_cannot_bypass_mac():

    builder = StateGraph(MessagesState)
    builder.add_node("body", lambda state: {}, metadata={"security_trust": "trusted"})
    builder.add_edge(START, "body")
    graph = builder.compile(security=SecurityConfig())
    install_mac_policy(FORBID)
    with pytest.raises(SecurityConfigurationError, match="mac:unconfined_graph_body"):
        graph.invoke({"messages": []})


def test_system_policy_loads_without_application_opt_in(monkeypatch, tmp_path):

    policy = tmp_path / "mac.cedar"
    policy.write_text(FORBID)
    monkeypatch.setattr(_runtime_policy, "_SYSTEM_POLICY_PATH", policy)
    monkeypatch.setattr(_runtime_policy, "_system_loaded", False)
    monkeypatch.setattr(
        _runtime_policy.os,
        "fstat",
        lambda fd: SimpleNamespace(st_mode=0o100644, st_uid=0),
    )
    graph = graph_for(lambda state: {})
    with pytest.raises(SecurityConfigurationError, match="mac:graph_requires_security"):
        graph.invoke({"messages": []})
    with pytest.raises(RuntimeError, match="already installed"):
        install_mac_policy(FORBID)


def test_untrusted_system_policy_fails_closed(monkeypatch, tmp_path):
    policy = tmp_path / "mac.cedar"
    policy.write_text(FORBID)
    policy.chmod(0o666)
    monkeypatch.setattr(_runtime_policy, "_SYSTEM_POLICY_PATH", policy)
    monkeypatch.setattr(_runtime_policy, "_system_loaded", False)
    graph = graph_for(lambda state: {})
    with pytest.raises(RuntimeError, match="root-owned"):
        graph.invoke({"messages": []})


def test_remote_execution_cannot_escape_local_policy():
    remote = RemoteGraph("untrusted-remote")
    install_mac_policy(FORBID)
    with pytest.raises(
        SecurityConfigurationError, match="mac:unsupported_execution_boundary"
    ):
        remote.invoke({})
    with pytest.raises(
        SecurityConfigurationError, match="mac:unsupported_execution_boundary"
    ):
        asyncio.run(remote.ainvoke({}))
    with pytest.raises(
        SecurityConfigurationError, match="mac:unsupported_execution_boundary"
    ):
        remote.stream_events({}, version="v3")
    with pytest.raises(
        SecurityConfigurationError, match="mac:unsupported_execution_boundary"
    ):
        asyncio.run(remote.astream_events({}, version="v3"))


@pytest.mark.skipif(shutil.which("cedar") is None, reason="Cedar CLI required")
@pytest.mark.parametrize(
    "operator_policy",
    [
        "forbid(principal, action, resource) when { broken syntax };",
        'forbid(principal, action, resource) when { resource.absent == "x" };',
    ],
)
def test_operator_parse_and_evaluation_errors_fail_closed(tmp_path, operator_policy):
    path = tmp_path / "report.txt"
    path.write_text("must not escape")
    install_mac_policy(operator_policy)
    with pytest.raises(ObjectPolicyDenied, match="cedar:(validation|evaluation):"):
        security = cedar_security(reader, manifest=MANIFEST, policy=PERMIT)
        security.host_executor.authorizer.authorize(
            principal_id="alice",
            roles=(),
            tool_name="reader",
            tool_owner="application",
            call_id="invalid-policy",
            arguments={"path": str(path)},
        )


def test_custom_directory_policy_persists_across_processes(tmp_path):
    policy_dir = tmp_path / "deployment policy"
    policy_dir.mkdir(mode=0o700)
    (policy_dir / "mac.cedar").write_text(FORBID)
    env = {**os.environ, "LANGGRAPH_MAC_DIR": str(policy_dir)}
    source = """
from langgraph.graph import START, MessagesState, StateGraph
from langgraph.prebuilt.security import SecurityConfigurationError
builder = StateGraph(MessagesState)
builder.add_node("body", lambda state: {})
builder.add_edge(START, "body")
try:
    builder.compile().invoke({"messages": []})
except SecurityConfigurationError as exc:
    assert str(exc) == "mac:graph_requires_security"
else:
    raise AssertionError("deployment MAC was bypassed")
"""
    for _ in range(2):
        result = subprocess.run(
            [sys.executable, "-c", source],
            env=env,
            capture_output=True,
            text=True,
            timeout=30,
        )
        assert result.returncode == 0, result.stdout + result.stderr


@pytest.mark.parametrize(
    "kind", ["empty", "missing_directory", "missing_policy", "writable_policy"]
)
def test_explicit_directory_errors_fail_closed(monkeypatch, tmp_path, kind):
    directory = tmp_path / "policy"
    directory.mkdir(mode=0o700)
    if kind == "missing_directory":
        directory = directory / "missing"
    elif kind == "writable_policy":
        policy = directory / "mac.cedar"
        policy.write_text(FORBID)
        policy.chmod(0o666)
    monkeypatch.setenv("LANGGRAPH_MAC_DIR", "" if kind == "empty" else str(directory))
    monkeypatch.setattr(_runtime_policy, "_system_loaded", False)
    with pytest.raises(RuntimeError):
        _runtime_policy.runtime_policy()
    assert _runtime_policy._policy is None


def test_custom_directory_is_sealed_after_loading(monkeypatch, tmp_path):
    policy = tmp_path / "mac.cedar"
    policy.write_text(FORBID)
    monkeypatch.setenv("LANGGRAPH_MAC_DIR", str(tmp_path))
    monkeypatch.setattr(_runtime_policy, "_system_loaded", False)
    loaded = _runtime_policy.runtime_policy()
    monkeypatch.setenv("LANGGRAPH_MAC_DIR", str(tmp_path / "other"))
    policy.unlink()
    assert _runtime_policy.runtime_policy() is loaded
    with pytest.raises(RuntimeError, match="already installed"):
        install_mac_policy(FORBID)
