from __future__ import annotations

import hashlib
import json
import os
import subprocess
import sys
from dataclasses import replace
from pathlib import Path

import pytest

from langgraph.prebuilt.security.broker import CredentialBroker, GitHubAppIssuer
from langgraph.prebuilt.security.capabilities import probe_landlock_abi
from langgraph.prebuilt.security.cedar import CedarPolicyBackend
from langgraph.prebuilt.security.enforcement import AuthorityDomain, GrantRule
from langgraph.prebuilt.security.landlock import (
    LandlockSandboxExecutor,
    build_ruleset,
    open_path_descriptor,
)
from langgraph.prebuilt.security.linux import LinuxToolSpec
from langgraph.prebuilt.security.policy import TypedPolicyBackend
from langgraph.prebuilt.security.profile import parse_profiles
from langgraph.prebuilt.security.types import Principal, Tool, ToolCall, ToolDac

pytestmark = pytest.mark.skipif(
    probe_landlock_abi() < 1, reason="Landlock is unavailable"
)


def _read_rule(path: Path) -> GrantRule:
    return GrantRule("allowed", AuthorityDomain.FILESYSTEM, "read", str(path))


def _fake_cedar(tmp_path: Path) -> Path:
    executable = tmp_path / "cedar"
    executable.write_text(
        "#!/usr/bin/env python3\n"
        "import json, pathlib, sys\n"
        "if sys.argv[1] == 'validate':\n"
        "    print('VALID')\n"
        "    raise SystemExit(0)\n"
        "tests = json.loads(pathlib.Path(sys.argv[sys.argv.index('--tests') + 1]).read_text())\n"
        "policy = pathlib.Path(sys.argv[sys.argv.index('--policies') + 1]).read_text()\n"
        "for test in tests:\n"
        "    request = test['request']\n"
        "    needle = f\"resource == {request['resource']}\"\n"
        "    actual = 'allow' if needle in policy and not request['context']['matchedForbids'] else 'deny'\n"
        "    if actual != test['decision']:\n"
        "        raise SystemExit(1)\n"
        "print(f'results: {len(tests)} passed, 0 failed')\n",
        encoding="utf-8",
    )
    executable.chmod(0o755)
    return executable


def _run_probe(ruleset_fd: int, allowed: Path, denied: Path) -> dict[str, object]:
    source = """
import ctypes
import json
import os
import sys
from langgraph.prebuilt.security._linux_worker import _apply_landlock

fd = int(sys.argv[1])
allowed = sys.argv[2]
denied = sys.argv[3]
_apply_landlock(fd)
result = {}
for name, path in (("allowed", allowed), ("denied", denied)):
    try:
        result[name] = open(path).read()
    except OSError as exc:
        result[name] = exc.errno
libc = ctypes.CDLL(None, use_errno=True)
raw = libc.open(denied.encode(), os.O_RDONLY)
result["ctypes"] = ctypes.get_errno() if raw < 0 else 0
if raw >= 0:
    os.close(raw)
read_fd, write_fd = os.pipe()
pid = os.fork()
if pid == 0:
    os.close(read_fd)
    try:
        open(denied).read()
    except OSError as exc:
        os.write(write_fd, str(exc.errno).encode())
    else:
        os.write(write_fd, b"0")
    os._exit(0)
os.close(write_fd)
result["grandchild"] = int(os.read(read_fd, 16))
os.waitpid(pid, 0)
print(json.dumps(result))
"""
    completed = subprocess.run(
        (sys.executable, "-c", source, str(ruleset_fd), str(allowed), str(denied)),
        pass_fds=(ruleset_fd,),
        check=True,
        capture_output=True,
        text=True,
    )
    return json.loads(completed.stdout)


def test_one_granted_file_blocks_second_file_ctypes_and_grandchild(
    tmp_path: Path,
) -> None:
    allowed = tmp_path / "allowed.txt"
    denied = tmp_path / "denied.txt"
    allowed.write_text("allowed")
    denied.write_text("denied")
    ruleset = build_ruleset((_read_rule(allowed),))
    try:
        result = _run_probe(ruleset.fd, allowed, denied)
    finally:
        ruleset.close()

    assert result["allowed"] == "allowed"
    assert result["denied"] == 13
    assert result["ctypes"] == 13
    assert result["grandchild"] == 13


def test_openat2_resolution_rejects_magic_links() -> None:
    with pytest.raises(OSError):
        descriptor = open_path_descriptor("/proc/self/fd/0")
        os.close(descriptor)


def test_landlock_executor_runs_allowed_call_and_blocks_hostile_second_path(
    tmp_path: Path,
) -> None:
    allowed = tmp_path / "allowed.txt"
    denied = tmp_path / "denied.txt"
    allowed.write_text("allowed")
    denied.write_text("denied")
    fixture = Path(__file__).with_name("fixtures") / "linux_tools.py"
    profiles = parse_profiles(
        f"""
tool hostile {{
  owner analyst
  grant analyst: call
  runs linux
  syscalls @minimal
  fs read ${{path}} need
}}
principal alice {{
  roles analyst
  fs read {tmp_path}/**
}}
"""
    )
    executor = LandlockSandboxExecutor(
        profiles,
        {
            "hostile": LinuxToolSpec(
                "linux_tools:hostile_probe",
                fixture,
                hashlib.sha256(fixture.read_bytes()).hexdigest(),
            )
        },
        runtime_roots=(fixture.parent,),
        policy_backend=TypedPolicyBackend(),
    )
    principal = Principal("alice", frozenset({"analyst"}), frozenset(), "session")
    tool = Tool("hostile", ToolDac("analyst", {"analyst": "x"}), frozenset(), ())
    call = ToolCall(
        tool,
        {"path": str(allowed), "forbidden_path": str(denied)},
        {"path": str(allowed)},
        "call-1",
        0,
    )

    with pytest.raises(Exception, match="sandboxed tool failed"):
        executor.invoke(principal, call, ())
    receipt = executor.activation_receipts()[0]
    assert receipt.rule_enforcement
    assert {item.support.value for item in receipt.rule_enforcement} <= {
        "exact",
        "tightened",
    }


def test_landlock_executor_defaults_to_cedar() -> None:
    fixture = Path(__file__).with_name("fixtures") / "linux_tools.py"
    profiles = parse_profiles(
        """
tool hostile {
  owner analyst
  grant analyst: call
  runs linux
  syscalls @minimal
}
principal alice {
  roles analyst
}
"""
    )
    executor = LandlockSandboxExecutor(
        profiles,
        {
            "hostile": LinuxToolSpec(
                "linux_tools:hostile_probe",
                fixture,
                hashlib.sha256(fixture.read_bytes()).hexdigest(),
            )
        },
        runtime_roots=(fixture.parent,),
    )
    assert isinstance(executor.policy_backend, CedarPolicyBackend)


def test_landlock_executor_assigns_worker_to_attested_cgroup(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    fixture = Path(__file__).with_name("fixtures") / "linux_tools.py"
    profiles = parse_profiles(
        """
tool environment {
  owner analyst
  grant analyst: call
  runs linux
  syscalls @minimal
}
principal alice {
  roles analyst
}
"""
    )
    executor = LandlockSandboxExecutor(
        profiles,
        {
            "environment": LinuxToolSpec(
                "linux_tools:environment_probe",
                fixture,
                hashlib.sha256(fixture.read_bytes()).hexdigest(),
            )
        },
        runtime_roots=(fixture.parent,),
        policy_backend=TypedPolicyBackend(),
    )
    executor._cgroup_root = tmp_path
    executor.capabilities = replace(
        executor.capabilities, cgroup_delegated=True, cgroup_kill=True
    )
    events: list[object] = []

    class FakeCgroup:
        @classmethod
        def create(cls, root: Path, limits: object) -> FakeCgroup:
            events.append(("create", root, limits))
            return cls()

        def assign(self, pid: int) -> None:
            events.append(("assign", pid))

        def kill(self) -> bool:
            events.append("kill")
            return True

        def close(self) -> None:
            events.append("close")

    monkeypatch.setattr(
        "langgraph.prebuilt.security.landlock.CgroupV2Scope", FakeCgroup
    )
    principal = Principal("alice", frozenset({"analyst"}), frozenset(), "session")
    tool = Tool("environment", ToolDac("analyst", {"analyst": "x"}), frozenset(), ())
    call = ToolCall(tool, {}, {}, "call-cgroup", 0)

    result = executor.invoke(principal, call, ())

    assert isinstance(result.value, dict)
    assert events[0][0] == "create"
    assert events[1][0] == "assign"
    assert events[-1] == "close"
    mechanisms = {item.mechanism for item in result.receipt.rule_enforcement}
    assert "cgroup:v2+rlimit:cpu_ms" in mechanisms
    assert "cgroup:v2+rlimit:pids" in mechanisms


def test_landlock_worker_uses_preconfined_broker_without_receiving_token() -> None:
    fixture = Path(__file__).with_name("fixtures") / "linux_tools.py"
    profiles = parse_profiles(
        """
tool brokered {
  owner analyst
  grant analyst: call
  runs linux
  syscalls @minimal
  service github(issuer: github_app, repository: org/repo, permission: issues_write) need
}
principal alice {
  roles analyst
  service github(issuer: github_app, repository: org/repo, permission: issues_write)
  credential github_app(repository: org/repo, permission: issues_write)
}
"""
    )
    seen: list[tuple[str, object]] = []

    def handler(token, operation, payload, spawn):
        assert token == "parent-only-token"
        seen.append((operation, payload))
        return {"status": "created"}

    broker = CredentialBroker(
        {"github_app": GitHubAppIssuer(lambda spawn, scope: "parent-only-token")},
        {"github": handler},
    )
    runtime_roots = tuple(
        Path(item).resolve()
        for item in (fixture.parent, *sys.path)
        if item and Path(item).exists()
    )
    executor = LandlockSandboxExecutor(
        profiles,
        {
            "brokered": LinuxToolSpec(
                "linux_tools:broker_probe",
                fixture,
                hashlib.sha256(fixture.read_bytes()).hexdigest(),
            )
        },
        runtime_roots=runtime_roots,
        policy_backend=TypedPolicyBackend(),
        credential_broker=broker,
    )
    principal = Principal("alice", frozenset({"analyst"}), frozenset(), "session")
    tool = Tool("brokered", ToolDac("analyst", {"analyst": "x"}), frozenset(), ())
    call = ToolCall(tool, {"body": "hello"}, {"body": "hello"}, "call-broker", 0)

    result = executor.invoke(principal, call, ())

    assert result.value == {"status": "created"}
    assert seen == [("invoke", {"body": "hello"})]
    assert broker.audit_records()[0].reason == "exact_scope"
    mechanisms = {item.mechanism for item in result.receipt.rule_enforcement}
    assert "broker:socketpair+exact-scope" in mechanisms


@pytest.mark.parametrize("asynchronous", [False, True])
async def test_cedar_policy_runs_on_sync_and_async_landlock_invocation(
    tmp_path: Path, asynchronous: bool
) -> None:
    data = tmp_path / "allowed.txt"
    data.write_text("allowed")
    fixture = Path(__file__).with_name("fixtures") / "linux_tools.py"
    profiles = parse_profiles(
        f"""
tool reader {{
  owner analyst
  grant analyst: call
  runs linux
  syscalls @minimal
  fs read ${{path}} need
}}
principal alice {{
  roles analyst
  fs read {tmp_path}/**
}}
"""
    )
    executor = LandlockSandboxExecutor(
        profiles,
        {
            "reader": LinuxToolSpec(
                "linux_tools:read_file",
                fixture,
                hashlib.sha256(fixture.read_bytes()).hexdigest(),
            )
        },
        runtime_roots=(fixture.parent,),
        policy_backend=CedarPolicyBackend(_fake_cedar(tmp_path)),
    )
    principal = Principal("alice", frozenset({"analyst"}), frozenset(), "session")
    tool = Tool("reader", ToolDac("analyst", {"analyst": "x"}), frozenset(), ())
    call = ToolCall(tool, {"path": str(data)}, {"path": str(data)}, "call-cedar", 0)

    result = (
        await executor.ainvoke(principal, call, ())
        if asynchronous
        else executor.invoke(principal, call, ())
    )

    assert result.value == "allowed"
