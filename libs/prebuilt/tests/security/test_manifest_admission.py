"""Mandatory admission checks bind Cedar manifests to actual tool bodies."""

import inspect
import json
import shutil
from pathlib import Path

import pytest
from langchain_core.messages import AIMessage
from langchain_core.tools import StructuredTool, tool
from langgraph.graph import START, MessagesState, StateGraph
from pydantic import BaseModel, field_validator

from langgraph.prebuilt import ToolNode
from langgraph.prebuilt.security import (
    HostExecutionDenied,
    Principal,
    SecurityConfigurationError,
    cedar_security,
    cedar_security_many,
    with_principal,
)
from langgraph.prebuilt.security.inprocess import read_text
from tests.security.test_object_policy import _fake_cedar

PERMIT = "permit(principal, action, resource);"
MANIFEST = "runs inprocess\nfs read @{path} need"


@tool
def reader(path: str) -> str:
    """Read through the official resource API."""
    return read_text(path)


@tool
def raw_reader(path: str) -> str:
    """Attempt a direct resource access."""
    return Path(path).read_text()


@tool
def wrong_reader(path: str) -> str:
    """Request a different resource than the manifest."""
    return read_text("/undeclared")


@tool
async def async_reader(path: str) -> str:
    """Read using the current async invocation's grant."""
    return read_text(path)


@tool
def two_reads(path: str, other: str) -> str:
    """Read two monitored resources; policy may restrict either one."""
    read_text(other)
    return read_text(path)


@tool
async def async_two_reads(path: str, other: str) -> str:
    """Read two monitored resources in an asynchronous invocation."""
    read_text(other)
    return read_text(path)


@pytest.mark.parametrize(
    "candidate,manifest,status",
    [
        (raw_reader, MANIFEST, "unknown"),
        (wrong_reader, MANIFEST, "mismatch"),
    ],
)
def test_rejects_unmediated_or_undeclared_effects(candidate, manifest, status):
    with pytest.raises(
        SecurityConfigurationError, match=f"manifest_consistency:{status}"
    ):
        cedar_security(candidate, manifest=manifest, policy=PERMIT)


def test_missing_source_is_not_accepted(monkeypatch):
    def unavailable(*args, **kwargs):
        raise OSError("missing")

    monkeypatch.setattr(inspect, "getsource", unavailable)
    with pytest.raises(SecurityConfigurationError, match="source unavailable"):
        cedar_security(reader, manifest=MANIFEST, policy=PERMIT)


def test_stale_source_is_not_accepted(monkeypatch):
    monkeypatch.setattr(
        inspect, "getsource", lambda code: "def reader(path): return path"
    )
    with pytest.raises(SecurityConfigurationError, match="source does not match"):
        cedar_security(reader, manifest=MANIFEST, policy=PERMIT)


def test_same_named_library_function_is_not_an_approved_monitor(monkeypatch):
    monkeypatch.setitem(reader.func.__globals__, "read_text", lambda path: "unchecked")
    with pytest.raises(SecurityConfigurationError, match="unmodeled call: read_text"):
        cedar_security(reader, manifest=MANIFEST, policy=PERMIT)


def test_both_sync_and_async_implementations_are_checked():
    combined = StructuredTool.from_function(
        func=reader.func, coroutine=raw_reader.func, name="reader"
    )
    with pytest.raises(
        SecurityConfigurationError, match="manifest_consistency:unknown"
    ):
        cedar_security(combined, manifest=MANIFEST, policy=PERMIT)


@pytest.mark.parametrize("change", ["function", "code", "terminal", "defaults"])
def test_changed_execution_bindings_deny(monkeypatch, change):
    security = cedar_security(reader, manifest=MANIFEST, policy=PERMIT)
    admission = security.host_executor.dispatcher.admission
    if change == "function":
        monkeypatch.setattr(reader, "func", raw_reader.func)
    elif change == "code":
        monkeypatch.setattr(reader.func, "__code__", raw_reader.func.__code__)
    elif change == "terminal":
        monkeypatch.setitem(reader.func.__globals__, "read_text", lambda path: "unsafe")
    else:
        monkeypatch.setattr(reader.func, "__defaults__", ("/undeclared",))
    with pytest.raises(HostExecutionDenied, match="manifest_consistency:"):
        admission.validate()


def test_resource_api_requires_active_grant(tmp_path):
    path = tmp_path / "data"
    path.write_text("fixture")
    with pytest.raises(PermissionError, match="resource_not_granted"):
        read_text(str(path))


def test_tool_schema_cannot_execute_unverified_validators():
    class CustomSchema(BaseModel):
        path: str

        @field_validator("path")
        @classmethod
        def unchecked_callback(cls, value):
            raise AssertionError("an unchecked schema callback executed")

    @tool(args_schema=CustomSchema)
    def echo(path: str) -> str:
        """Return an inert argument without effects."""
        return path

    security = cedar_security(echo, policy=PERMIT)
    admission = security.host_executor.dispatcher.admission
    assert admission.invoke({"path": "safe"}) == "safe"


def test_arbitrary_argument_objects_are_not_coerced():
    class ReflectiveValue:
        def __str__(self):
            raise AssertionError("unverified object behavior executed")

    security = cedar_security(reader, manifest=MANIFEST, policy=PERMIT)
    with pytest.raises(HostExecutionDenied, match="arguments_must_be_scalars"):
        security.host_executor.dispatcher.admission.invoke({"path": ReflectiveValue()})


@pytest.mark.parametrize("asynchronous", [False, True])
@pytest.mark.parametrize("restriction", ["none", "mac", "manifest", "empty_manifest"])
async def test_grant_scoped_read_and_restriction(tmp_path, asynchronous, restriction):
    if restriction == "mac" and shutil.which("cedar") is None:
        pytest.skip("Cedar CLI required for optional-resource policy evaluation")
    path = tmp_path / "data"
    path.write_text("fixture")
    candidate = (
        (async_two_reads if asynchronous else two_reads)
        if restriction in {"mac", "manifest"}
        else (async_reader if asynchronous else reader)
    )
    # Keep another required line so removal of the optional read still dispatches.
    other = tmp_path / "other"
    other.write_text("other")
    manifest = {
        "none": MANIFEST,
        "mac": "runs inprocess\nfs read @{path} want\nfs read @{other} need",
        "manifest": "runs inprocess\nfs read @{other} need",
        "empty_manifest": "runs inprocess",
    }[restriction]
    if restriction in {"manifest", "empty_manifest"}:
        with pytest.raises(
            SecurityConfigurationError, match="manifest_consistency:mismatch"
        ):
            cedar_security(candidate, manifest=manifest, policy=PERMIT)
        return
    security = cedar_security(
        candidate,
        manifest=manifest,
        policy=PERMIT,
        executable="cedar" if restriction == "mac" else _fake_cedar(tmp_path),
        mac_forbids=f'forbid(principal, action == slangGraph::Action::"fs::read", resource) when {{ resource.selector == {json.dumps(str(path))} }};'
        if restriction == "mac"
        else "",
    )
    builder = StateGraph(MessagesState)
    builder.add_node("tools", ToolNode([candidate]))
    builder.add_edge(START, "tools")
    graph = builder.compile(security=security)
    arguments = {"path": str(path)}
    if restriction in {"mac", "manifest"}:
        arguments["other"] = str(other)
    request = {
        "messages": [
            AIMessage(
                content="",
                tool_calls=[{"name": candidate.name, "args": arguments, "id": "read"}],
            )
        ]
    }
    config = with_principal(
        {},
        Principal("alice", frozenset(), frozenset(), "session"),
        modules=security.modules,
    )
    result = (
        await graph.ainvoke(request, config)
        if asynchronous
        else graph.invoke(request, config)
    )
    if restriction != "none":
        assert result["messages"][-1].status == "error"
        assert "resource_not_granted" in str(result["messages"][-1].content)
    else:
        assert result["messages"][-1].content == "fixture"
    with pytest.raises(PermissionError, match="resource_not_granted"):
        read_text(str(path))


@tool
def constant_reader(path: str) -> str:
    """Return a constant without using declared read permission."""
    return "nothing"


@tool
def add_scalars(left: int, right: int) -> int:
    """Add exact inert integer inputs."""
    return left + right


def test_exact_scalar_arguments_are_typed_and_admitted():
    admission = cedar_security(
        add_scalars, policy=PERMIT
    ).host_executor.dispatcher.admission
    assert admission.invoke({"left": 2, "right": 3}) == 5
    with pytest.raises(HostExecutionDenied, match="argument_type"):
        admission.invoke({"left": "2", "right": 3})
    with pytest.raises(HostExecutionDenied, match="arguments_must_be_scalars"):
        admission.invoke({"left": [2], "right": 3})


def test_multiple_language_tools_share_one_policy_executor():
    security = cedar_security_many((constant_reader, add_scalars), policy=PERMIT)
    admissions = security.host_executor.dispatcher.admissions
    assert set(admissions) == {"constant_reader", "add_scalars"}
    assert admissions["constant_reader"].invoke({"path": "safe"}) == "nothing"
    assert admissions["add_scalars"].invoke({"left": 4, "right": 5}) == 9


def test_unused_permission_is_accepted_at_real_admission():
    security = cedar_security(constant_reader, manifest=MANIFEST, policy=PERMIT)
    report = security.host_executor.dispatcher.admission.reports[0]
    assert report["inferred_subset_of_manifest"] is True
    assert report["inferred"] == []
    assert report["unused_rules"] == [0]
