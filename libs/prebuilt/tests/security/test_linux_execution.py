"""End-to-end Linux host-enforcement integration tests."""

from __future__ import annotations

import asyncio
import hashlib
import json
import os
import py_compile
import time
from dataclasses import replace
from pathlib import Path
from threading import RLock
from typing import Annotated
from unittest.mock import Mock

import pytest
from langchain_core.messages import AIMessage
from langchain_core.tools import Tool as SimpleTool
from langchain_core.tools import tool

from langgraph.prebuilt import InjectedState, ToolNode
from langgraph.prebuilt.security import (
    Confidentiality,
    DacOverrides,
    Decision,
    Effect,
    ForbidConstraint,
    LinuxSandboxExecutor,
    LinuxToolSpec,
    MemoryAuditSink,
    Principal,
    ResourceArg,
    RulePredicate,
    SecurityConfig,
    SecurityConfigurationError,
    SecurityModule,
    SessionFlowPolicy,
    SqliteAuditSink,
    SqliteFlowStateStore,
    ToolCall,
    ToolFlowRule,
    TypedPolicyBackend,
    Verdict,
    dac,
    effects,
    guarded_tool,
    parse_profiles,
    with_principal,
)
from langgraph.prebuilt.security import linux as linux_security
from langgraph.prebuilt.security.enforcement import (
    AuthorityDomain,
    EnforcementObligation,
    ObligationKind,
    SupportLevel,
)
from langgraph.prebuilt.security.execution import (
    HostExecutionDenied,
    HostExecutionError,
)
from langgraph.prebuilt.security.host_boundary import (
    HostExecutorBoundary,
    StackBoundaryPolicy,
    make_host_router,
)
from langgraph.prebuilt.security.linux import (
    _assess_path_obligation,
    _nested_mount_points,
    _read_fd_json,
    _verified_resource_fd,
)
from langgraph.prebuilt.security.stack import SecurityStack
from langgraph.prebuilt.security.types import Tool, ToolDac

_FIXTURES = Path(__file__).with_name("fixtures").resolve()


def _input(name: str, args: dict[str, object]) -> dict[str, object]:
    return {
        "messages": [
            AIMessage(
                content="",
                tool_calls=[{"name": name, "args": args, "id": "call-1"}],
            )
        ]
    }


def _config(principal: Principal) -> dict[str, object]:
    runtime = Mock(store=None, context=None, stream_writer=lambda _: None)
    return with_principal({"configurable": {"__pregel_runtime": runtime}}, principal)


def _security(
    profile_text: str,
    entrypoint: str,
    *,
    audit_sink: MemoryAuditSink | SqliteAuditSink | None = None,
    default_limits: dict[str, int] | None = None,
    worker_pool_capacity: int = 0,
) -> SecurityConfig:
    profiles = parse_profiles(profile_text, source="linux-test.slp")
    artifact = _FIXTURES / "linux_tools.py"
    executor = LinuxSandboxExecutor(
        profiles,
        {
            "read_file": LinuxToolSpec(
                entrypoint,
                artifact,
                hashlib.sha256(artifact.read_bytes()).hexdigest(),
            )
        },
        runtime_roots=(_FIXTURES,),
        policy_backend=TypedPolicyBackend(),
        default_limits=default_limits,
        worker_pool_capacity=worker_pool_capacity,
    )
    return SecurityConfig(
        dac_overrides=DacOverrides(profiles=profiles.tools),
        host_executor=executor,
        audit_sink=audit_sink,
    )


def _profile(root: Path, *, network: bool = False) -> str:
    resource = "net connect 443 need" if network else "fs read ${path} need"
    principal_resource = "net connect 443" if network else f"fs read {root}/**"
    return f"""
tool read_file {{
  owner analyst
  grant analyst: call
  runs linux
  syscalls @minimal
  {resource}
}}
principal alice {{
  roles analyst
  {principal_resource}
}}
"""


def test_tool_node_executes_only_inside_activated_linux_worker(tmp_path: Path) -> None:
    """The registered in-process callback is never used when Linux is enabled."""
    allowed = tmp_path / "allowed.txt"
    allowed.write_text("sandbox-result")
    parent_executed: list[str] = []

    @tool
    @dac(owner="analyst", grants={"analyst": "x", "*": "-"})
    @effects(Effect.READ, resources=[ResourceArg("path", "path", "realpath")])
    def read_file(path: str) -> str:
        """Parent-process callback that must not execute."""
        parent_executed.append(path)
        return "parent-result"

    audit = MemoryAuditSink()
    security = _security(_profile(tmp_path), "linux_tools:read_file", audit_sink=audit)
    node = ToolNode((read_file,), security=security)
    principal = Principal("alice", frozenset({"analyst"}), frozenset(), "session")

    result = node.invoke(
        _input("read_file", {"path": str(allowed)}),
        config=_config(principal),
    )

    assert parent_executed == []
    assert result["messages"][0].content == "sandbox-result"
    assert result["messages"][0].status == "success"
    assert isinstance(security.host_executor, LinuxSandboxExecutor)
    receipts = security.host_executor.activation_receipts()
    assert len(receipts) == 1
    assert receipts[0].grant_digest
    assert receipts[0].evidence
    activation = [record for record in audit.records() if record.stage == "activation"]
    assert len(activation) == 1
    payload = json.loads(activation[0].reason.removeprefix("activation_receipt:"))
    assert payload == receipts[0].canonical()
    assert audit.verify() == (True, None)


def test_prewarmed_worker_is_claimed_once_with_fresh_activation(tmp_path: Path) -> None:
    """Preflight confinement removes launch cost without caching invocation authority."""
    allowed = tmp_path / "allowed.txt"
    allowed.write_text("pooled-result")
    security = _security(
        _profile(tmp_path),
        "linux_tools:read_file",
        worker_pool_capacity=1,
    )
    assert isinstance(security.host_executor, LinuxSandboxExecutor)
    executor = security.host_executor
    tool_info = Tool(
        "read_file",
        ToolDac("analyst", {"analyst": "x", "*": "-"}),
        frozenset({Effect.READ}),
        (ResourceArg("path", "path", "realpath"),),
    )
    call = ToolCall(
        tool_info,
        {"path": str(allowed)},
        {"path": str(allowed)},
        "preflight-call",
        0,
    )
    principal = Principal("alice", frozenset({"analyst"}), frozenset(), "session")
    try:
        assert executor.prewarm(principal, call, (), count=1) == 1
        assert dict(executor.worker_pool_stats()) == {
            "capacity": 1,
            "hits": 0,
            "idle": 1,
            "misses": 0,
        }
        assert executor.activation_receipts() == ()
        result = executor.invoke(principal, replace(call, call_id="runtime-call"), ())
        assert result.value == "pooled-result"
        assert result.receipt.nonce
        assert dict(executor.worker_pool_stats()) == {
            "capacity": 1,
            "hits": 1,
            "idle": 0,
            "misses": 0,
        }
        assert len(executor.activation_receipts()) == 1
    finally:
        executor.close()


def test_prewarmed_worker_rejects_different_native_plan(tmp_path: Path) -> None:
    """A pool miss cannot broaden a worker's preinstalled filesystem authority."""
    first = tmp_path / "first.txt"
    second = tmp_path / "second.txt"
    first.write_text("first")
    second.write_text("second")
    security = _security(
        _profile(tmp_path),
        "linux_tools:read_file",
        worker_pool_capacity=1,
    )
    assert isinstance(security.host_executor, LinuxSandboxExecutor)
    executor = security.host_executor
    tool_info = Tool(
        "read_file",
        ToolDac("analyst", {"analyst": "x", "*": "-"}),
        frozenset({Effect.READ}),
        (ResourceArg("path", "path", "realpath"),),
    )
    principal = Principal("alice", frozenset({"analyst"}), frozenset(), "session")

    def call(path: Path, call_id: str) -> ToolCall:
        return ToolCall(
            tool_info,
            {"path": str(path)},
            {"path": str(path)},
            call_id,
            0,
        )

    try:
        assert executor.prewarm(principal, call(first, "preflight"), (), count=1) == 1
        result = executor.invoke(principal, call(second, "runtime"), ())
        assert result.value == "second"
        stats = dict(executor.worker_pool_stats())
        assert stats["hits"] == 0
        assert stats["misses"] == 1
        assert stats["idle"] == 1
    finally:
        executor.close()


@pytest.mark.asyncio
@pytest.mark.parametrize("converted", [False, True])
@pytest.mark.parametrize("api", ["invoke", "ainvoke", "events_v1", "events_v2"])
async def test_legacy_api_uses_real_host_after_conversion(
    tmp_path: Path, converted, api
) -> None:
    allowed = tmp_path / "allowed.txt"
    allowed.write_text("linux-legacy-result")
    local_calls = []

    def local_read(path: str) -> str:
        local_calls.append(path)
        raise AssertionError("legacy callback must execute only in the host worker")

    target = SimpleTool(name="read_file", func=local_read, description="Read a file")
    effects(Effect.READ, resources=[ResourceArg("path", "path", "realpath")])(target)
    dac(owner="analyst", grants={"analyst": "x", "*": "-"})(target)
    security = _security(_profile(tmp_path), "linux_tools:read_file")
    guarded = guarded_tool(target, security=security)
    secured = guarded.as_tool(arg_types={"path": str}) if converted else guarded
    principal = Principal(
        "alice", frozenset({"analyst"}), frozenset(), "legacy-session"
    )
    config = _config(principal)
    args = {"path": str(allowed)}
    if api == "invoke":
        result = await asyncio.to_thread(secured.invoke, args, config)
    elif api == "ainvoke":
        result = await secured.ainvoke(args, config)
    else:
        result = [
            event
            async for event in secured.astream_events(
                args, config, version=api.removeprefix("events_")
            )
        ]
    assert "linux-legacy-result" in str(result)
    assert not local_calls
    assert isinstance(security.host_executor, LinuxSandboxExecutor)
    assert len(security.host_executor.activation_receipts()) == 1


@pytest.mark.parametrize("asynchronous", [False, True])
def test_verified_router_executes_through_real_linux_host(
    tmp_path: Path, asynchronous: bool
) -> None:
    """The certified core uses the existing activation-before-execution host."""
    allowed = tmp_path / "allowed.txt"
    allowed.write_text("verified-host-result")
    security = _security(_profile(tmp_path), "linux_tools:read_file")
    assert isinstance(security.host_executor, LinuxSandboxExecutor)
    tool_info = Tool(
        "read_file",
        ToolDac("analyst", {"analyst": "x", "*": "-"}),
        frozenset({Effect.READ}),
        (ResourceArg("path", "path", "realpath"),),
    )
    call = ToolCall(
        tool_info, {"path": str(allowed)}, {"path": str(allowed)}, "verified", 0
    )
    principal = Principal("alice", frozenset({"analyst"}), frozenset(), "session")
    stack = SecurityStack(())
    try:
        router = make_host_router(
            StackBoundaryPolicy(stack), HostExecutorBoundary(security.host_executor)
        )
        result = (
            asyncio.run(router.ainvoke(principal, call))
            if asynchronous
            else router.invoke(principal, call)
        )
    finally:
        stack.close()
    assert result.value == "verified-host-result"
    assert result.receipt.grant_digest
    assert result.receipt.evidence
    assert security.host_executor.activation_receipts() == (result.receipt,)


def test_hostile_tool_cannot_read_undeclared_file(tmp_path: Path) -> None:
    """A hostile entry point cannot exceed the final filesystem grant."""
    allowed_root = tmp_path / "allowed"
    allowed_root.mkdir()
    allowed = allowed_root / "visible.txt"
    allowed.write_text("visible")
    forbidden = tmp_path / "secret.txt"
    forbidden.write_text("secret")

    @tool
    @dac(owner="analyst", grants={"analyst": "x", "*": "-"})
    @effects(Effect.READ, resources=[ResourceArg("path", "path", "realpath")])
    def read_file(path: str, forbidden_path: str) -> str:
        """Local callback with the worker's public schema."""
        raise AssertionError("parent callback executed")

    audit = MemoryAuditSink()
    security = _security(
        _profile(allowed_root),
        "linux_tools:hostile_probe",
        audit_sink=audit,
    )
    node = ToolNode((read_file,), security=security, handle_tool_errors=True)
    principal = Principal("alice", frozenset({"analyst"}), frozenset(), "session")

    result = node.invoke(
        _input(
            "read_file",
            {"path": str(allowed), "forbidden_path": str(forbidden)},
        ),
        config=_config(principal),
    )

    assert result["messages"][0].status == "error"
    assert "sandboxed tool failed" in str(result["messages"][0].content)
    assert any(record.stage == "activation" for record in audit.records())
    outcomes = [record for record in audit.records() if record.stage == "outcome"]
    assert outcomes[-1].outcome is not None
    assert outcomes[-1].outcome.value == "failed"


def test_unsupported_network_grant_denies_before_tool_code(tmp_path: Path) -> None:
    """The Linux filesystem backend never claims unsupported network authority."""
    executed: list[bool] = []

    @tool
    @dac(owner="analyst", grants={"analyst": "x", "*": "-"})
    def read_file() -> str:
        """Tool that must be rejected during exact obligation negotiation."""
        executed.append(True)
        return "unexpected"

    node = ToolNode(
        (read_file,),
        security=_security(_profile(tmp_path, network=True), "linux_tools:read_file"),
    )
    principal = Principal("alice", frozenset({"analyst"}), frozenset(), "session")

    result = node.invoke(
        _input("read_file", {}),
        config=_config(principal),
    )

    assert executed == []
    assert result["messages"][0].status == "error"
    assert "adapter_rule_unsupported" in str(result["messages"][0].content)


@pytest.mark.asyncio
async def test_async_tool_node_uses_same_linux_activation_path(tmp_path: Path) -> None:
    """Async execution waits for the same verified worker startup barrier."""
    allowed = tmp_path / "allowed.txt"
    allowed.write_text("async-sandbox-result")

    @tool
    @dac(owner="analyst", grants={"analyst": "x", "*": "-"})
    @effects(Effect.READ, resources=[ResourceArg("path", "path", "realpath")])
    async def read_file(path: str) -> str:
        """Parent coroutine that must not execute."""
        raise AssertionError(path)

    node = ToolNode(
        (read_file,),
        security=_security(_profile(tmp_path), "linux_tools:async_read_file"),
    )
    principal = Principal("alice", frozenset({"analyst"}), frozenset(), "session")

    result = await node.ainvoke(
        _input("read_file", {"path": str(allowed)}),
        config=_config(principal),
    )

    assert result["messages"][0].content == "async-sandbox-result"


def test_linux_worker_enforces_authorized_write(tmp_path: Path) -> None:
    """Read-plus-write authority lowers to a writable stable bind mount."""
    target = tmp_path / "target.txt"
    target.write_text("before")
    profiles = f"""
tool read_file {{
  owner analyst
  grant analyst: call
  runs linux
  syscalls @minimal
  fs read+write+truncate ${{path}} need
}}
principal alice {{
  roles analyst
  fs read+write+truncate {tmp_path}/**
}}
"""

    @tool
    @dac(owner="analyst", grants={"analyst": "x", "*": "-"})
    @effects(
        Effect.READ,
        Effect.WRITE,
        resources=[ResourceArg("path", "path", "realpath")],
    )
    def read_file(path: str, content: str) -> str:
        """Parent writer that must not execute."""
        raise AssertionError(path, content)

    node = ToolNode(
        (read_file,),
        security=_security(profiles, "linux_tools:write_file"),
    )
    principal = Principal("alice", frozenset({"analyst"}), frozenset(), "session")

    result = node.invoke(
        _input("read_file", {"path": str(target), "content": "after"}),
        config=_config(principal),
    )

    assert result["messages"][0].content == "written"
    assert target.read_text() == "after"


@pytest.mark.parametrize(
    ("entrypoint", "expected_type"),
    [
        ("linux_tools:network_probe", "PermissionError"),
        ("linux_tools:exec_probe", "PermissionError"),
        ("linux_tools:fork_probe", "PermissionError"),
        ("linux_tools:thread_probe", "RuntimeError"),
        ("linux_tools:unix_socket_probe", "PermissionError"),
    ],
)
def test_linux_worker_blocks_ambient_network_and_exec(
    tmp_path: Path, entrypoint: str, expected_type: str
) -> None:
    """Namespace and seccomp controls deny authority omitted from the grant."""
    profiles = """
tool read_file {
  owner analyst
  grant analyst: call
  runs linux
  syscalls @minimal
}
principal alice {
  roles analyst
}
"""

    @tool
    @dac(owner="analyst", grants={"analyst": "x", "*": "-"})
    def read_file() -> str:
        """Parent callback that must not execute."""
        raise AssertionError

    node = ToolNode(
        (read_file,),
        security=_security(profiles, entrypoint),
        handle_tool_errors=True,
    )
    principal = Principal("alice", frozenset({"analyst"}), frozenset(), "session")

    result = node.invoke(_input("read_file", {}), config=_config(principal))

    assert result["messages"][0].status == "error"
    assert expected_type in str(result["messages"][0].content)


def test_linux_worker_clears_ambient_environment(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    """Host secrets and working directory do not cross the worker baseline."""
    monkeypatch.setenv("SLANGGRAPH_TEST_SECRET", "must-not-cross")
    profiles = """
tool read_file {
  owner analyst
  grant analyst: call
  runs linux
  syscalls @minimal
}
principal alice {
  roles analyst
}
"""

    @tool
    @dac(owner="analyst", grants={"analyst": "x", "*": "-"})
    def read_file() -> dict[str, object]:
        """Parent callback that must not execute."""
        raise AssertionError

    guarded = guarded_tool(
        read_file,
        security=_security(profiles, "linux_tools:environment_probe"),
    )
    principal = Principal("alice", frozenset({"analyst"}), frozenset(), "session")

    result = guarded.invoke({}, config=_config(principal))

    assert result["cwd"] == "/tmp"
    environment = result["environment"]
    assert isinstance(environment, dict)
    assert "SLANGGRAPH_TEST_SECRET" not in environment
    assert environment["PATH"] == "/usr/bin"


def test_linux_worker_bounds_file_and_tmpfs_growth(tmp_path: Path) -> None:
    """Kernel ceilings bound writable files and the private temporary filesystem."""
    profiles = """
tool read_file {
  owner analyst
  grant analyst: call
  runs linux
  syscalls @minimal
}
principal alice {
  roles analyst
}
"""
    limits = {
        "address_space_bytes": 1_073_741_824,
        "cpu_ms": 30_000,
        "file_size_bytes": 1_048_576,
        "nofile": 64,
        "pids": 1,
        "tmpfs_bytes": 1_048_576,
        "wall_ms": 30_000,
    }

    @tool
    @dac(owner="analyst", grants={"analyst": "x", "*": "-"})
    def read_file(size: int) -> str:
        """Parent callback that must not execute."""
        raise AssertionError(size)

    guarded = guarded_tool(
        read_file,
        security=_security(
            profiles,
            "linux_tools:file_limit_probe",
            default_limits=limits,
        ),
    )
    principal = Principal("alice", frozenset({"analyst"}), frozenset(), "session")

    result = guarded.invoke({"size": 2_097_152}, config=_config(principal))

    assert result.startswith("blocked:")


def test_linux_worker_inherits_no_ambient_descriptors(tmp_path: Path) -> None:
    """Mount and startup descriptors are closed before untrusted code runs."""
    profiles = """
tool read_file {
  owner analyst
  grant analyst: call
  runs linux
  syscalls @minimal
}
principal alice {
  roles analyst
}
"""

    @tool
    @dac(owner="analyst", grants={"analyst": "x", "*": "-"})
    def read_file() -> list[int]:
        """Parent callback that must not execute."""
        raise AssertionError

    guarded = guarded_tool(
        read_file,
        security=_security(profiles, "linux_tools:descriptor_probe"),
    )
    principal = Principal("alice", frozenset({"analyst"}), frozenset(), "session")

    assert guarded.invoke({}, config=_config(principal)) == []


def test_linux_mount_descriptor_is_bound_to_authorized_object(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    """A resource replacement between resolution and mount fails closed."""
    authorized = tmp_path / "authorized.txt"
    replacement = tmp_path / "replacement.txt"
    authorized.write_text("authorized")
    replacement.write_text("replacement")
    actual_stat = os.stat

    def replaced_stat(
        path: os.PathLike[str] | str,
        *,
        dir_fd: int | None = None,
        follow_symlinks: bool = True,
    ) -> os.stat_result:
        if Path(path) == authorized:
            return actual_stat(
                replacement,
                dir_fd=dir_fd,
                follow_symlinks=follow_symlinks,
            )
        return actual_stat(path, dir_fd=dir_fd, follow_symlinks=follow_symlinks)

    monkeypatch.setattr(os, "stat", replaced_stat)

    with pytest.raises(HostExecutionDenied, match="resource_identity_changed"):
        _verified_resource_fd(authorized)


def test_untrusted_runtime_root_cannot_initialize_before_confinement(
    tmp_path: Path,
) -> None:
    """Python isolated mode prevents runtime-root startup hooks before seccomp."""
    runtime_root = tmp_path / "runtime"
    writable = tmp_path / "writable"
    runtime_root.mkdir()
    writable.mkdir()
    marker = writable / "preconfinement.txt"
    (runtime_root / "sitecustomize.py").write_text(
        f"from pathlib import Path\nPath({str(marker)!r}).write_text('escaped')\n"
    )
    profiles = parse_profiles(
        f"""
tool read_file {{
  owner analyst
  grant analyst: call
  runs linux
  syscalls @minimal
  fs read+write+create+delete+truncate ${{path}}/** need
}}
principal alice {{
  roles analyst
  fs read+write+create+delete+truncate {writable}/**
}}
""",
        source="linux-test.slp",
    )
    artifact = _FIXTURES / "linux_tools.py"
    executor = LinuxSandboxExecutor(
        profiles,
        {
            "read_file": LinuxToolSpec(
                "linux_tools:noop_path",
                artifact,
                hashlib.sha256(artifact.read_bytes()).hexdigest(),
            )
        },
        runtime_roots=(runtime_root, _FIXTURES),
        policy_backend=TypedPolicyBackend(),
    )
    security = SecurityConfig(
        dac_overrides=DacOverrides(profiles=profiles.tools),
        host_executor=executor,
    )

    @tool
    @dac(owner="analyst", grants={"analyst": "x", "*": "-"})
    @effects(Effect.WRITE, resources=[ResourceArg("path", "path", "realpath")])
    def read_file(path: str) -> str:
        """Parent callback that must not execute."""
        raise AssertionError(path)

    guarded = guarded_tool(read_file, security=security)
    principal = Principal("alice", frozenset({"analyst"}), frozenset(), "session")

    assert guarded.invoke({"path": str(writable)}, config=_config(principal)) == "noop"
    assert not marker.exists()


def test_writable_directory_exposes_only_supported_operation_set(
    tmp_path: Path,
) -> None:
    """Full directory grants allow data mutation but not rename or metadata changes."""
    writable = tmp_path / "writable"
    writable.mkdir()
    profiles = f"""
tool read_file {{
  owner analyst
  grant analyst: call
  runs linux
  syscalls @minimal
  fs read+write+create+delete+truncate ${{path}}/** need
}}
principal alice {{
  roles analyst
  fs read+write+create+delete+truncate {writable}/**
}}
"""

    @tool
    @dac(owner="analyst", grants={"analyst": "x", "*": "-"})
    @effects(Effect.WRITE, resources=[ResourceArg("path", "path", "realpath")])
    def read_file(path: str) -> dict[str, str]:
        """Parent callback that must not execute."""
        raise AssertionError(path)

    guarded = guarded_tool(
        read_file,
        security=_security(profiles, "linux_tools:directory_operation_probe"),
    )
    principal = Principal("alice", frozenset({"analyst"}), frozenset(), "session")

    result = guarded.invoke({"path": str(writable)}, config=_config(principal))

    assert result == {
        "ioctl": "blocked",
        "metadata": "blocked",
        "rename": "blocked",
    }
    assert list(writable.iterdir()) == []


@pytest.mark.parametrize("operations", ["write", "create", "delete", "truncate"])
def test_narrow_directory_mutation_grants_fail_lowering(
    tmp_path: Path, operations: str
) -> None:
    """A writable bind is rejected unless every operation it exposes is granted."""
    writable = tmp_path / "writable"
    writable.mkdir()
    profiles = f"""
tool read_file {{
  owner analyst
  grant analyst: call
  runs linux
  syscalls @minimal
  fs {operations} ${{path}}/** need
}}
principal alice {{
  roles analyst
  fs {operations} {writable}/**
}}
"""

    @tool
    @dac(owner="analyst", grants={"analyst": "x", "*": "-"})
    @effects(Effect.WRITE, resources=[ResourceArg("path", "path", "realpath")])
    def read_file(path: str) -> str:
        """Parent callback that must not execute."""
        raise AssertionError(path)

    node = ToolNode(
        (read_file,),
        security=_security(profiles, "linux_tools:noop_path"),
    )
    principal = Principal("alice", frozenset({"analyst"}), frozenset(), "session")

    result = node.invoke(
        _input("read_file", {"path": str(writable)}), config=_config(principal)
    )

    assert result["messages"][0].status == "error"
    assert "adapter_lowering_failed" in str(result["messages"][0].content)


def test_worker_protocol_bounds_request_and_response(tmp_path: Path) -> None:
    """Both protocol directions reject oversized and deeply nested values."""
    profiles = """
tool read_file {
  owner analyst
  grant analyst: call
  runs linux
  syscalls @minimal
}
principal alice {
  roles analyst
}
"""

    @tool
    @dac(owner="analyst", grants={"analyst": "x", "*": "-"})
    def read_file(size: int = 0, depth: int = 0, payload: str = "") -> object:
        """Parent callback that must not execute."""
        raise AssertionError(size, depth, payload)

    principal = Principal("alice", frozenset({"analyst"}), frozenset(), "session")
    oversized_security = _security(profiles, "linux_tools:oversized_result")
    oversized = ToolNode(
        (read_file,), security=oversized_security, handle_tool_errors=True
    )
    oversized_result = oversized.invoke(
        _input("read_file", {"size": 2_000_000}), config=_config(principal)
    )
    assert oversized_result["messages"][0].status == "error"
    assert "ValueError" in str(oversized_result["messages"][0].content)

    nested = ToolNode(
        (read_file,),
        security=_security(profiles, "linux_tools:deeply_nested_result"),
        handle_tool_errors=True,
    )
    nested_result = nested.invoke(
        _input("read_file", {"depth": 80}), config=_config(principal)
    )
    assert nested_result["messages"][0].status == "error"
    assert "indeterminate" in str(nested_result["messages"][0].content)

    request_security = _security(profiles, "linux_tools:noop_path")
    request = ToolNode((read_file,), security=request_security)
    request_result = request.invoke(
        _input("read_file", {"payload": "x" * 2_000_000}),
        config=_config(principal),
    )
    assert request_result["messages"][0].status == "error"
    assert "request_not_serializable" in str(request_result["messages"][0].content)
    assert isinstance(request_security.host_executor, LinuxSandboxExecutor)
    assert request_security.host_executor.activation_receipts() == ()


def test_wall_timeout_confirms_worker_termination_before_return(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    """The supervisor confirms the concrete worker PID is gone before returning."""
    profiles = """
tool read_file {
  owner analyst
  grant analyst: call
  runs linux
  syscalls @minimal
}
principal alice {
  roles analyst
}
"""
    limits = {
        "address_space_bytes": 1_073_741_824,
        "cpu_ms": 30_000,
        "file_size_bytes": 1_048_576,
        "nofile": 64,
        "pids": 1,
        "tmpfs_bytes": 1_048_576,
        "wall_ms": 100,
    }
    confirmations: list[bool] = []
    original = linux_security._confirm_worker_terminated

    def track(pid: int, start_time: str, *, timeout_s: float) -> bool:
        confirmed = original(pid, start_time, timeout_s=timeout_s)
        confirmations.append(confirmed)
        return confirmed

    monkeypatch.setattr(linux_security, "_confirm_worker_terminated", track)

    @tool
    @dac(owner="analyst", grants={"analyst": "x", "*": "-"})
    def read_file() -> str:
        """Parent callback that must not execute."""
        raise AssertionError

    node = ToolNode(
        (read_file,),
        security=_security(
            profiles,
            "linux_tools:slow_probe",
            default_limits=limits,
        ),
        handle_tool_errors=True,
    )
    principal = Principal("alice", frozenset({"analyst"}), frozenset(), "session")

    started = time.monotonic()
    result = node.invoke(_input("read_file", {}), config=_config(principal))

    assert time.monotonic() - started < 3
    assert result["messages"][0].status == "error"
    assert "tool_timeout" in str(result["messages"][0].content)
    assert confirmations == [True]


def test_guarded_tool_uses_linux_host_executor(tmp_path: Path) -> None:
    """Direct guarded calls share the activated host execution path."""
    allowed = tmp_path / "allowed.txt"
    allowed.write_text("guarded-sandbox-result")
    executed: list[str] = []

    @tool
    @dac(owner="analyst", grants={"analyst": "x", "*": "-"})
    @effects(Effect.READ, resources=[ResourceArg("path", "path", "realpath")])
    def read_file(path: str) -> str:
        """Parent callback that must not execute."""
        executed.append(path)
        return "parent"

    guarded = guarded_tool(
        read_file,
        security=_security(_profile(tmp_path), "linux_tools:read_file"),
    )
    principal = Principal("alice", frozenset({"analyst"}), frozenset(), "session")

    result = guarded.invoke({"path": str(allowed)}, config=_config(principal))

    assert result == "guarded-sandbox-result"
    assert executed == []


def test_linux_tool_spec_rejects_unverified_artifact() -> None:
    """A manifest cannot bind an entry point to unverified executable bytes."""
    artifact = _FIXTURES / "linux_tools.py"

    with pytest.raises(ValueError, match="digest does not match"):
        LinuxToolSpec("linux_tools:read_file", artifact, "0" * 64)


def test_linux_executor_rechecks_artifact_at_dispatch(tmp_path: Path) -> None:
    """Changing an artifact after configuration denies before worker release."""
    artifact = tmp_path / "linux_tools.py"
    artifact.write_bytes((_FIXTURES / "linux_tools.py").read_bytes())
    digest = hashlib.sha256(artifact.read_bytes()).hexdigest()
    profiles = parse_profiles(_profile(tmp_path), source="linux-test.slp")
    executor = LinuxSandboxExecutor(
        profiles,
        {"read_file": LinuxToolSpec("linux_tools:read_file", artifact, digest)},
        runtime_roots=(tmp_path,),
        policy_backend=TypedPolicyBackend(),
    )
    security = SecurityConfig(
        dac_overrides=DacOverrides(profiles=profiles.tools),
        host_executor=executor,
    )

    @tool
    @dac(owner="analyst", grants={"analyst": "x", "*": "-"})
    @effects(Effect.READ, resources=[ResourceArg("path", "path", "realpath")])
    def read_file(path: str) -> str:
        """Parent callback that must not execute."""
        raise AssertionError(path)

    artifact.write_text(artifact.read_text() + "\n# changed after manifest creation\n")
    allowed = tmp_path / "allowed.txt"
    allowed.write_text("value")
    node = ToolNode((read_file,), security=security)
    principal = Principal("alice", frozenset({"analyst"}), frozenset(), "session")

    result = node.invoke(
        _input("read_file", {"path": str(allowed)}),
        config=_config(principal),
    )

    assert result["messages"][0].status == "error"
    assert "host:artifact_changed" in str(result["messages"][0].content)


def test_linux_executor_loads_pinned_path_not_shadow_module(tmp_path: Path) -> None:
    """A same-named module in an earlier runtime root cannot replace the artifact."""
    allowed = tmp_path / "allowed.txt"
    allowed.write_text("pinned-result")
    shadow_root = tmp_path / "shadow"
    shadow_root.mkdir()
    (shadow_root / "linux_tools.py").write_text(
        "def read_file(path):\n    return 'shadow-result'\n"
    )
    profiles = parse_profiles(_profile(tmp_path), source="linux-test.slp")
    artifact = _FIXTURES / "linux_tools.py"
    executor = LinuxSandboxExecutor(
        profiles,
        {
            "read_file": LinuxToolSpec(
                "linux_tools:read_file",
                artifact,
                hashlib.sha256(artifact.read_bytes()).hexdigest(),
            )
        },
        runtime_roots=(shadow_root, _FIXTURES),
        policy_backend=TypedPolicyBackend(),
    )
    security = SecurityConfig(
        dac_overrides=DacOverrides(profiles=profiles.tools),
        host_executor=executor,
    )

    @tool
    @dac(owner="analyst", grants={"analyst": "x", "*": "-"})
    @effects(Effect.READ, resources=[ResourceArg("path", "path", "realpath")])
    def read_file(path: str) -> str:
        """Parent callback that must not execute."""
        raise AssertionError(path)

    node = ToolNode((read_file,), security=security)
    principal = Principal("alice", frozenset({"analyst"}), frozenset(), "session")

    result = node.invoke(
        _input("read_file", {"path": str(allowed)}),
        config=_config(principal),
    )

    assert result["messages"][0].content == "pinned-result"


def test_linux_executor_ignores_unchecked_bytecode_cache(tmp_path: Path) -> None:
    """Unchecked bytecode cannot replace the source bytes bound by the manifest."""
    artifact = tmp_path / "pinned_tool.py"
    artifact.write_text("def read_file(path):\n    return 'unchecked-bytecode'\n")
    py_compile.compile(
        str(artifact),
        invalidation_mode=py_compile.PycInvalidationMode.UNCHECKED_HASH,
    )
    artifact.write_text(
        "from pathlib import Path\n"
        "def read_file(path):\n"
        "    return Path(path).read_text()\n"
    )
    digest = hashlib.sha256(artifact.read_bytes()).hexdigest()
    allowed = tmp_path / "allowed.txt"
    allowed.write_text("source-result")
    profiles = parse_profiles(_profile(tmp_path), source="linux-test.slp")
    executor = LinuxSandboxExecutor(
        profiles,
        {"read_file": LinuxToolSpec("pinned_tool:read_file", artifact, digest)},
        runtime_roots=(tmp_path,),
        policy_backend=TypedPolicyBackend(),
    )
    security = SecurityConfig(
        dac_overrides=DacOverrides(profiles=profiles.tools),
        host_executor=executor,
    )

    @tool
    @dac(owner="analyst", grants={"analyst": "x", "*": "-"})
    @effects(Effect.READ, resources=[ResourceArg("path", "path", "realpath")])
    def read_file(path: str) -> str:
        """Parent callback that must not execute."""
        raise AssertionError(path)

    node = ToolNode((read_file,), security=security)
    principal = Principal("alice", frozenset({"analyst"}), frozenset(), "session")

    result = node.invoke(
        _input("read_file", {"path": str(allowed)}),
        config=_config(principal),
    )

    assert result["messages"][0].content == "source-result"


def test_linux_executor_rejects_inexact_writable_mount(tmp_path: Path) -> None:
    """A coarse writable bind is not used for a narrower write-only grant."""
    target = tmp_path / "target.txt"
    target.write_text("before")
    profiles = f"""
tool read_file {{
  owner analyst
  grant analyst: call
  runs linux
  syscalls @minimal
  fs write ${{path}} need
}}
principal alice {{
  roles analyst
  fs write {tmp_path}/**
}}
"""

    @tool
    @dac(owner="analyst", grants={"analyst": "x", "*": "-"})
    @effects(Effect.WRITE, resources=[ResourceArg("path", "path", "realpath")])
    def read_file(path: str, content: str) -> str:
        """Parent callback that must not execute."""
        raise AssertionError(path, content)

    node = ToolNode(
        (read_file,),
        security=_security(profiles, "linux_tools:write_file"),
    )
    principal = Principal("alice", frozenset({"analyst"}), frozenset(), "session")

    result = node.invoke(
        _input("read_file", {"path": str(target), "content": "after"}),
        config=_config(principal),
    )

    assert result["messages"][0].status == "error"
    assert "adapter_lowering_failed" in str(result["messages"][0].content)
    assert target.read_text() == "before"


def test_linux_activation_receipt_survives_sqlite_reopen(tmp_path: Path) -> None:
    """Complete activation evidence is retained in the durable hash chain."""
    allowed = tmp_path / "allowed.txt"
    allowed.write_text("durable-result")
    audit_path = tmp_path / "audit.sqlite"
    audit = SqliteAuditSink(audit_path)

    @tool
    @dac(owner="analyst", grants={"analyst": "x", "*": "-"})
    @effects(Effect.READ, resources=[ResourceArg("path", "path", "realpath")])
    def read_file(path: str) -> str:
        """Parent callback that must not execute."""
        raise AssertionError(path)

    security = _security(
        _profile(tmp_path),
        "linux_tools:read_file",
        audit_sink=audit,
    )
    node = ToolNode((read_file,), security=security)
    principal = Principal("alice", frozenset({"analyst"}), frozenset(), "session")

    result = node.invoke(
        _input("read_file", {"path": str(allowed)}),
        config=_config(principal),
    )
    assert result["messages"][0].content == "durable-result"
    audit.close()

    reopened = SqliteAuditSink(audit_path)
    activation = [
        record for record in reopened.records() if record.stage == "activation"
    ]
    assert len(activation) == 1
    assert activation[0].reason.startswith("activation_receipt:")
    assert reopened.verify() == (True, None)
    reopened.close()


def test_linux_executor_rejects_nonminimal_syscall_profile() -> None:
    """The adapter never maps an unknown syscall class to its minimal filter."""
    profiles = parse_profiles(
        """
tool read_file {
  owner analyst
  grant analyst: call
  runs linux
  syscalls @file-read
}
principal alice {
  roles analyst
}
""",
        source="linux-test.slp",
    )
    artifact = _FIXTURES / "linux_tools.py"

    with pytest.raises(ValueError, match="exactly 'syscalls @minimal'"):
        LinuxSandboxExecutor(
            profiles,
            {
                "read_file": LinuxToolSpec(
                    "linux_tools:read_file",
                    artifact,
                    hashlib.sha256(artifact.read_bytes()).hexdigest(),
                )
            },
            runtime_roots=(_FIXTURES,),
            policy_backend=TypedPolicyBackend(),
        )


def test_linux_executor_rejects_injected_tool_arguments(tmp_path: Path) -> None:
    """Unsupported coordinator capabilities cannot silently disappear in a worker."""

    @tool
    @dac(owner="analyst", grants={"analyst": "x", "*": "-"})
    def read_file(state: Annotated[dict[str, object], InjectedState]) -> str:
        """Tool whose injected coordinator state cannot cross confinement."""
        raise AssertionError(state)

    with pytest.raises(SecurityConfigurationError, match="injected tool arguments"):
        ToolNode(
            (read_file,),
            security=_security(
                _profile(tmp_path),
                "linux_tools:read_file",
            ),
        )


def test_mandatory_policy_can_reject_runtime_baseline(tmp_path: Path) -> None:
    """Protocol and runtime authority are policy inputs, never adapter additions."""

    class NoProtocol(SecurityModule):
        name = "no_protocol"

        def tool_call_permission(
            self, principal: Principal, call: ToolCall
        ) -> Decision:
            del principal, call
            return Decision(
                Verdict.ALLOW,
                "forbid_protocol",
                constraints=(
                    ForbidConstraint(
                        "no-ipc",
                        RulePredicate(domain="ipc"),
                        "protocol_not_authorized",
                    ),
                ),
            )

    @tool
    @dac(owner="analyst", grants={"analyst": "x", "*": "-"})
    def read_file() -> str:
        """Parent callback that must not execute."""
        raise AssertionError

    security = _security(
        """
tool read_file {
  owner analyst
  grant analyst: call
  runs linux
  syscalls @minimal
}
principal alice {
  roles analyst
}
""",
        "linux_tools:read_file",
    )
    security = replace(security, modules=(NoProtocol(),))
    node = ToolNode((read_file,), security=security)
    principal = Principal("alice", frozenset({"analyst"}), frozenset(), "session")

    result = node.invoke(_input("read_file", {}), config=_config(principal))

    assert result["messages"][0].status == "error"
    assert "required_authority_removed" in str(result["messages"][0].content)
    assert isinstance(security.host_executor, LinuxSandboxExecutor)
    assert security.host_executor.activation_receipts() == ()


def test_unconfirmed_termination_retains_durable_flow_reservation(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    """A6/A7: recovery requires kernel evidence and survives coordinator restart."""
    flow_path = tmp_path / "flow.sqlite"
    store = SqliteFlowStateStore(flow_path)
    rules = {
        "read_file": ToolFlowRule(sink_ceiling=Confidentiality.PUBLIC),
        "read_secret": ToolFlowRule(output_label=Confidentiality.SECRET),
    }
    flow = SessionFlowPolicy(rules, store=store)
    base = _security(
        """
tool read_file {
  owner analyst
  grant analyst: call
  runs linux
  syscalls @minimal
}
principal alice {
  roles analyst
}
""",
        "linux_tools:read_file",
    )
    security = replace(base, flow_policy=flow)
    assert isinstance(security.host_executor, LinuxSandboxExecutor)
    actual_confirmation = linux_security._confirm_worker_terminated
    monkeypatch.setattr(
        linux_security,
        "_confirm_worker_terminated",
        lambda pid, start_time, *, timeout_s: False,
    )

    @tool
    @dac(owner="analyst", grants={"analyst": "x", "*": "-"})
    def read_file() -> str:
        """Parent callback that must not execute."""
        raise AssertionError

    node = ToolNode((read_file,), security=security, handle_tool_errors=True)
    principal = Principal("alice", frozenset({"analyst"}), frozenset(), "session")

    result = node.invoke(_input("read_file", {}), config=_config(principal))

    assert result["messages"][0].status == "error"
    recovery_ids = flow.unresolved_terminations(principal)
    assert len(recovery_ids) == 1
    blocked, reservation = flow.acquire(principal, "read_secret")
    assert blocked.reason == "flow:concurrent_egress"
    assert reservation is None
    store.close()

    recovered_store = SqliteFlowStateStore(flow_path)
    recovered = SessionFlowPolicy(rules, store=recovered_store)
    assert recovered.unresolved_terminations(principal) == recovery_ids
    monkeypatch.setattr(
        linux_security, "_confirm_worker_terminated", actual_confirmation
    )
    assert recovered.recover_termination(
        principal, recovery_ids[0], security.host_executor
    )
    assert recovered.unresolved_terminations(principal) == ()
    allowed, reservation = recovered.acquire(principal, "read_secret")
    assert allowed.verdict is Verdict.ALLOW
    recovered.release(principal, reservation)
    recovered_store.close()


def test_worker_cleanup_is_independent_and_preserves_active_error(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    """Cleanup failures cannot skip termination recovery or replace execution errors."""
    executor = object.__new__(LinuxSandboxExecutor)
    executor._termination_lock = RLock()
    executor._unresolved = {}
    executor._recovery_leases = {}
    process = Mock()
    process.poll.side_effect = RuntimeError("poll failed")
    process.kill.side_effect = RuntimeError("kill failed")
    process.wait.side_effect = RuntimeError("wait failed")
    receipt = Mock()
    active_error = HostExecutionError(
        "tool failed", receipt, linux_security.ExecutionOutcome.FAILED
    )
    confirmations: list[tuple[int, str]] = []

    def fail_confirmation(pid: int, start_time: str, *, timeout_s: float) -> bool:
        confirmations.append((pid, start_time))
        raise OSError("confirmation failed")

    monkeypatch.setattr(linux_security.os, "close", Mock(side_effect=OSError("close")))
    monkeypatch.setattr(linux_security, "_confirm_worker_terminated", fail_confirmation)
    monkeypatch.setattr(
        linux_security,
        "_remove_private_artifact",
        Mock(side_effect=OSError("remove")),
    )

    executor._cleanup_worker(
        status_read=10,
        status_write=11,
        inherited_fds=(12,),
        process=process,
        child_pid=123,
        child_start_time="456",
        artifact_directory=tmp_path,
        host=Mock(boot_id="boot"),
        receipt=receipt,
        leases=(),
        active_error=active_error,
    )

    assert confirmations == [(123, "456")]
    assert process.kill.call_count == 1
    assert process.wait.call_count == 1
    assert active_error.outcome is linux_security.ExecutionOutcome.INDETERMINATE
    assert active_error.recovery is not None
    assert active_error.recovery in executor.unresolved_terminations()


def test_bubblewrap_status_accepts_partial_pipe_reads(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """Status framing accumulates partial kernel reads before decoding JSON."""
    chunks = iter((b'{"child-pid":', b" 123}"))
    monkeypatch.setattr(linux_security.select, "select", lambda *args: ([10], [], []))
    monkeypatch.setattr(linux_security.os, "read", lambda *args: next(chunks))

    assert _read_fd_json(10, 1.0) == {"child-pid": 123}


@pytest.mark.asyncio
async def test_cancellation_waits_for_confirmed_linux_termination(
    tmp_path: Path,
) -> None:
    """A6: cancellation cannot release flow state while a worker remains alive."""
    limits = {
        "address_space_bytes": 1_073_741_824,
        "cpu_ms": 30_000,
        "file_size_bytes": 1_048_576,
        "nofile": 64,
        "pids": 1,
        "tmpfs_bytes": 1_048_576,
        "wall_ms": 150,
    }
    store = SqliteFlowStateStore(tmp_path / "cancel-flow.sqlite")
    rules = {
        "read_file": ToolFlowRule(sink_ceiling=Confidentiality.PUBLIC),
        "read_secret": ToolFlowRule(output_label=Confidentiality.SECRET),
    }
    flow = SessionFlowPolicy(rules, store=store)
    base = _security(
        """
tool read_file {
  owner analyst
  grant analyst: call
  runs linux
  syscalls @minimal
}
principal alice {
  roles analyst
}
""",
        "linux_tools:slow_probe",
        default_limits=limits,
    )
    security = replace(base, flow_policy=flow)
    assert isinstance(security.host_executor, LinuxSandboxExecutor)

    @tool
    @dac(owner="analyst", grants={"analyst": "x", "*": "-"})
    async def read_file() -> str:
        """Parent callback that must not execute."""
        raise AssertionError

    node = ToolNode((read_file,), security=security, handle_tool_errors=True)
    principal = Principal("alice", frozenset({"analyst"}), frozenset(), "session")
    invocation = asyncio.create_task(
        node.ainvoke(_input("read_file", {}), config=_config(principal))
    )
    for _ in range(100):
        if security.host_executor.activation_receipts():
            break
        await asyncio.sleep(0.01)
    assert security.host_executor.activation_receipts()
    invocation.cancel()

    with pytest.raises(asyncio.CancelledError):
        await invocation

    assert flow.unresolved_terminations(principal) == ()
    allowed, reservation = flow.acquire(principal, "read_secret")
    assert allowed.verdict is Verdict.ALLOW
    flow.release(principal, reservation)
    store.close()


def test_special_file_grant_is_rejected_before_worker_release(tmp_path: Path) -> None:
    """A2: device-like filesystem objects require a different adapter."""
    fifo = tmp_path / "channel"
    os.mkfifo(fifo)

    @tool
    @dac(owner="analyst", grants={"analyst": "x", "*": "-"})
    @effects(Effect.READ, resources=[ResourceArg("path", "path", "realpath")])
    def read_file(path: str) -> str:
        """Parent callback that must not execute."""
        raise AssertionError(path)

    security = _security(_profile(tmp_path), "linux_tools:read_file")
    node = ToolNode((read_file,), security=security)
    principal = Principal("alice", frozenset({"analyst"}), frozenset(), "session")

    result = node.invoke(
        _input("read_file", {"path": str(fifo)}), config=_config(principal)
    )

    assert result["messages"][0].status == "error"
    assert "adapter_rule_unsupported" in str(result["messages"][0].content)
    assert isinstance(security.host_executor, LinuxSandboxExecutor)
    assert security.host_executor.activation_receipts() == ()


def test_directory_with_nested_mounts_is_not_claimed_as_one_exact_subtree() -> None:
    """A2: live subtrees crossing mount boundaries require separate grants."""
    assert _nested_mount_points(Path("/"))
    support, reason = _assess_path_obligation(
        EnforcementObligation(
            "root-read",
            "root-rule",
            ObligationKind.OPERATE,
            AuthorityDomain.FILESYSTEM,
            "read",
            "/",
            {"subtree": True},
        )
    )

    assert support is SupportLevel.UNSUPPORTED
    assert reason == "nested_mount_requires_separate_grants"


def test_linux_limits_reject_inexact_cpu_and_physical_memory_claims(
    tmp_path: Path,
) -> None:
    """A8: the adapter advertises only limits with matching mechanisms."""
    profiles = parse_profiles(_profile(tmp_path), source="linux-test.slp")
    artifact = _FIXTURES / "linux_tools.py"
    invalid = {
        "address_space_bytes": 1_073_741_824,
        "cpu_ms": 1500,
        "file_size_bytes": 1_048_576,
        "nofile": 64,
        "pids": 1,
        "tmpfs_bytes": 1_048_576,
        "wall_ms": 30_000,
    }
    with pytest.raises(ValueError, match="whole-second"):
        LinuxSandboxExecutor(
            profiles,
            {
                "read_file": LinuxToolSpec(
                    "linux_tools:read_file",
                    artifact,
                    hashlib.sha256(artifact.read_bytes()).hexdigest(),
                )
            },
            runtime_roots=(_FIXTURES,),
            policy_backend=TypedPolicyBackend(),
            default_limits=invalid,
        )

    memory_profiles = _profile(tmp_path).replace(
        "syscalls @minimal", "syscalls @minimal\n  limits mem 256M"
    )
    security = _security(memory_profiles, "linux_tools:read_file")

    @tool
    @dac(owner="analyst", grants={"analyst": "x", "*": "-"})
    @effects(Effect.READ, resources=[ResourceArg("path", "path", "realpath")])
    def read_file(path: str) -> str:
        """Parent callback that must not execute."""
        raise AssertionError(path)

    target = tmp_path / "target"
    target.write_text("value")
    node = ToolNode((read_file,), security=security)
    principal = Principal("alice", frozenset({"analyst"}), frozenset(), "session")
    result = node.invoke(
        _input("read_file", {"path": str(target)}), config=_config(principal)
    )
    assert result["messages"][0].status == "error"
    assert "adapter_rule_unsupported" in str(result["messages"][0].content)
