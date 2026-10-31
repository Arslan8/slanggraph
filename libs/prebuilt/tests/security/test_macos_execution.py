"""Exact lowering and real macOS Seatbelt boundary regressions."""

from __future__ import annotations

import asyncio
import hashlib
import json
import os
import platform
import subprocess
import sys
import time
from dataclasses import replace
from pathlib import Path
from unittest.mock import Mock

import pytest

from langgraph.prebuilt.security import (
    Decision,
    ForbidConstraint,
    MacOSNativeLauncher,
    MacOSSandboxExecutor,
    MacOSToolSpec,
    Principal,
    RulePredicate,
    ToolCall,
    Verdict,
    parse_profiles,
)
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
from langgraph.prebuilt.security.host_boundary import make_authorized_host_router
from langgraph.prebuilt.security.macos import (
    _MacOSSeatbeltAdapter,
    _process_identity,
    _seatbelt_profile,
    _unique_pairs,
    _validate_json,
)
from langgraph.prebuilt.security.types import Tool, ToolDac

_NATIVE = pytest.mark.skipif(
    platform.system() != "Darwin", reason="requires macOS Seatbelt"
)
_PRINCIPAL = Principal("alice", frozenset({"reader"}), frozenset(), "session")
_SOURCE = """
import os
import socket
import subprocess
import asyncio

def run(operation="read", path="", other=""):
    if operation == "sleep":
        import time
        time.sleep(10)
    if operation == "flood":
        os.write(1, b"x" * 2000000)
        print("ignored")
        return True
    if operation == "read":
        with open(path) as f:
            return f.read()
    if operation == "raw-fork":
        import _ctypes
        class CInt(_ctypes._SimpleCData):
            _type_ = "i"
        class Fork(_ctypes.CFuncPtr):
            _flags_ = 1 | 8
            _restype_ = CInt
            _argtypes_ = ()
        fork = Fork(_ctypes.dlsym(_ctypes.dlopen(None), "fork"))
        child = fork()
        if child == -1:
            error = _ctypes.get_errno()
            if error in {1, 13}:
                return "denied"
            raise OSError(error, os.strerror(error))
        if child == 0:
            os._exit(0)
        os.waitpid(child, 0)
        return "allowed"
    try:
        if operation == "spawn":
            child = os.posix_spawn("/usr/bin/true", ["true"], {})
            os.waitpid(child, 0)
        elif operation == "signal":
            os.kill(int(other), 0)
        elif operation == "write":
            with open(path, "w") as f:
                f.write("changed")
        elif operation == "connect":
            with socket.socket() as s:
                s.connect(("127.0.0.1", int(other)))
        elif operation == "fork":
            child = os.fork()
            if child == 0:
                os._exit(0)
            os.waitpid(child, 0)
        elif operation == "exec":
            os.execve("/usr/bin/true", ["true"], {})
        return "allowed"
    except PermissionError:
        return "denied"

async def arun(**kwargs):
    await asyncio.sleep(0)
    return run(**kwargs)
"""


def _profiles(directory: Path, extra: str = ""):
    # Experimental fixture omits the Linux-default syscall obligation through
    # the existing immutable profile type; no parser defaults are changed.
    document = _parsed_profiles(directory, extra)
    if not extra:
        document = replace(
            document,
            tools={
                "reader": replace(document.tools["reader"], syscall_sets=frozenset())
            },
        )
    return document


def _parsed_profiles(directory: Path, extra: str = ""):
    return parse_profiles(f"""
tool reader {{
  owner reader
  grant reader: call
  runs macos
  fs read {directory}/** need
  {extra}
}}
principal alice {{
  roles reader
  fs read {directory}/**
}}
""")


def _call(**args):
    return ToolCall(
        Tool("reader", ToolDac("reader", {"reader": "x"}), frozenset(), ()),
        args,
        {},
        "call-1",
        0,
    )


@pytest.fixture(scope="session")
def launcher(tmp_path_factory):
    return MacOSNativeLauncher.build(tmp_path_factory.mktemp("macos-native") / "build")


@pytest.fixture
def native(tmp_path: Path):
    root = tmp_path.resolve()
    data = root / "data"
    data.mkdir()
    (data / "report").write_text("allowed report")
    (root / "secret").write_text("forbidden secret")
    source = root / "tool.py"
    source.write_text(_SOURCE)
    spec = MacOSToolSpec(
        "macos_tool:run", source, hashlib.sha256(source.read_bytes()).hexdigest()
    )
    return root, data, spec


def _executor(data, spec, launcher, *, profiles=None, **kwargs):
    return MacOSSandboxExecutor(
        profiles or _profiles(data),
        {"reader": spec},
        launcher=launcher,
        experimental=True,
        recovery_directory=data.parent / "recovery",
        **kwargs,
    )


def test_manifest_pins_source(tmp_path: Path):
    source = tmp_path / "tool.py"
    source.write_text("def run(): return 1")
    with pytest.raises(ValueError, match="digest"):
        MacOSToolSpec("tool:run", source, "0" * 64)
    with pytest.raises(ValueError, match="entrypoint"):
        MacOSToolSpec(
            "tool:bad-name", source, hashlib.sha256(source.read_bytes()).hexdigest()
        )


def test_platform_guard(monkeypatch):
    monkeypatch.setattr(
        "langgraph.prebuilt.security.macos.platform.system", lambda: "Linux"
    )
    with pytest.raises(RuntimeError, match="requires macOS"):
        MacOSSandboxExecutor(
            parse_profiles(""),
            {},
            launcher=None,
            recovery_directory=Path("/tmp"),
            experimental=True,
        )


def test_profile_escapes_paths():
    profile = _seatbelt_profile(
        [('/data/"x) (allow default) ;', False), ("/data/tree", True)]
    )
    assert '(literal "/data/\\"x) (allow default) ;")' in profile
    assert '(subpath "/data/tree")' in profile
    assert profile.startswith("(version 1)\n(deny default)\n")
    with pytest.raises(ValueError, match="control"):
        _seatbelt_profile([("/data/\n(allow default)", False)])


@pytest.mark.parametrize(
    "domain,operation,selector,conditions",
    [
        (AuthorityDomain.FILESYSTEM, "write", "/tmp/file", {"subtree": False}),
        (AuthorityDomain.PROCESS, "syscall_set", "minimal", {}),
        (AuthorityDomain.NETWORK, "connect", "443", {"protocol": "tcp"}),
        (AuthorityDomain.RESOURCE_LIMIT, "limit", "memory_bytes", {"maximum": 1024}),
        (AuthorityDomain.RESOURCE_LIMIT, "limit", "cpu_ms", {"maximum": 1500}),
        (AuthorityDomain.RESOURCE_LIMIT, "limit", "nofile", {"maximum": True}),
        (
            AuthorityDomain.RESOURCE_LIMIT,
            "limit",
            "wall_ms",
            {"maximum": 10, "unknown": True},
        ),
        (AuthorityDomain.DELEGATION, "delegate", "child", {}),
        (AuthorityDomain.SERVICE, "invoke", "http", {}),
    ],
)
def test_unsupported_authority(domain, operation, selector, conditions):
    adapter = _MacOSSeatbeltAdapter(b"key", "boot", 10)
    kind = (
        ObligationKind.RESOURCE_LIMIT
        if domain is AuthorityDomain.RESOURCE_LIMIT
        else ObligationKind.OPERATE
    )
    obligation = EnforcementObligation(
        "obligation", "rule", kind, domain, operation, selector, conditions
    )
    assert (
        adapter.assess(obligation, adapter.attest("nonce")).support
        is SupportLevel.UNSUPPORTED
    )


def test_unknown_path_conditions_fail_closed(tmp_path: Path):
    adapter = _MacOSSeatbeltAdapter(b"key", "boot", 10)
    obligation = EnforcementObligation(
        "id",
        "rule",
        ObligationKind.OPERATE,
        AuthorityDomain.FILESYSTEM,
        "read",
        str(tmp_path.resolve()),
        {"subtree": True, "excluded_paths": ("/secret",)},
    )
    assert (
        adapter.assess(obligation, adapter.attest("nonce")).support
        is SupportLevel.UNSUPPORTED
    )


def test_foreign_host_and_forged_activation_rejected():
    adapter = _MacOSSeatbeltAdapter(b"key", "boot", 10)
    host = adapter.attest("nonce")
    assert adapter.verify(host)
    assert not adapter.verify(replace(host, platform="linux"))
    assert not adapter.verify(replace(host, boot_id="other"))
    with pytest.raises(ValueError, match="not verified"):
        adapter.activate(
            Mock(native_plan_digest="digest"), Mock(digest="context"), "nonce"
        )


@_NATIVE
def test_read_and_receipt(native, launcher):
    _, data, spec = native
    executor = _executor(data, spec, launcher)
    result = executor.invoke(_PRINCIPAL, _call(path=str(data / "report")), ())
    assert result.value == "allowed report"
    assert result.receipt.artifact_digest == spec.artifact_digest
    assert result.receipt.activated_obligations
    assert executor.activation_receipts() == (result.receipt,)
    assert not executor.unresolved_terminations()


@_NATIVE
@pytest.mark.parametrize(
    "operation", ["write", "fork", "exec", "connect", "raw-fork", "spawn", "signal"]
)
def test_ambient_effects_denied(native, launcher, operation):
    _, data, spec = native
    executor = _executor(data, spec, launcher)
    result = executor.invoke(
        _PRINCIPAL,
        _call(
            operation=operation,
            path=str(data / "report"),
            other=str(os.getpid()) if operation == "signal" else "9",
        ),
        (),
    )
    assert result.value == "denied"
    assert (data / "report").read_text() == "allowed report"


@_NATIVE
def test_ungranted_read_and_symlink_escape_denied(native, launcher):
    root, data, spec = native
    (data / "escape").symlink_to(root / "secret")
    executor = _executor(data, spec, launcher)
    for path in (root / "secret", data / "escape"):
        with pytest.raises(HostExecutionError) as error:
            executor.invoke(_PRINCIPAL, _call(path=str(path)), ())
        assert error.value.termination_confirmed


@_NATIVE
def test_changed_artifact_denied_before_activation(native, launcher):
    _, data, spec = native
    executor = _executor(data, spec, launcher)
    spec.artifact_path.write_text("raise RuntimeError('changed')")
    with pytest.raises(HostExecutionDenied, match="artifact_changed"):
        executor.invoke(_PRINCIPAL, _call(), ())
    assert not executor.activation_receipts()


@_NATIVE
def test_syscall_request_denied(native, launcher):
    _, data, spec = native
    executor = _executor(
        data, spec, launcher, profiles=_profiles(data, "syscalls @minimal")
    )
    with pytest.raises(HostExecutionDenied, match="unsupported"):
        executor.invoke(_PRINCIPAL, _call(), ())
    assert not executor.activation_receipts()


@_NATIVE
def test_timeout_confirms_termination(native, launcher):
    _, data, spec = native
    executor = MacOSSandboxExecutor(
        _profiles(data),
        {"reader": spec},
        launcher=launcher,
        experimental=True,
        recovery_directory=data.parent / "recovery",
        default_limits={"cpu_ms": 1000, "nofile": 64, "wall_ms": 100},
    )
    with pytest.raises(HostExecutionError) as error:
        executor.invoke(_PRINCIPAL, _call(operation="sleep"), ())
    assert error.value.termination_confirmed
    assert not executor.unresolved_terminations()


@_NATIVE
async def test_async_tool(native, launcher):
    _, data, spec = native
    executor = _executor(data, replace(spec, entrypoint="macos_tool:arun"), launcher)
    result = await executor.ainvoke(_PRINCIPAL, _call(path=str(data / "report")), ())
    assert result.value == "allowed report"


@_NATIVE
async def test_cancellation_waits_for_termination(native, launcher):
    _, data, spec = native
    executor = MacOSSandboxExecutor(
        _profiles(data),
        {"reader": spec},
        launcher=launcher,
        experimental=True,
        recovery_directory=data.parent / "recovery",
        default_limits={"cpu_ms": 1000, "nofile": 64, "wall_ms": 200},
    )
    task = asyncio.create_task(
        executor.ainvoke(_PRINCIPAL, _call(operation="sleep"), ())
    )
    while not executor.activation_receipts():
        await asyncio.sleep(0.01)
        if task.done():
            await task
    task.cancel()
    await asyncio.sleep(0.02)
    assert not task.done()
    task.cancel()
    with pytest.raises(asyncio.CancelledError):
        await task
    assert not executor.unresolved_terminations()


@_NATIVE
def test_process_identity_and_missing_process():
    assert _process_identity(os.getpid())
    process = subprocess.Popen(["/usr/bin/true"])
    process.wait()
    assert _process_identity(process.pid) is None


@_NATIVE
def test_experimental_opt_in_required(native, launcher):
    _, data, spec = native
    with pytest.raises(HostExecutionDenied, match="experimental_route_disabled"):
        MacOSSandboxExecutor(
            _profiles(data),
            {"reader": spec},
            launcher=launcher,
            recovery_directory=data.parent / "recovery",
        )


@_NATIVE
def test_guardian_reaps_after_controller_sigkill(native, launcher):
    root, data, spec = native
    # A separate real controller dies without running executor finally blocks.
    # The native guardian must reclaim its child solely from pipe EOF.
    program = """
import json, sys
from dataclasses import replace
from pathlib import Path
from langgraph.prebuilt.security import MacOSSandboxExecutor, MacOSNativeLauncher, MacOSToolSpec, Principal, ToolCall, parse_profiles
from langgraph.prebuilt.security.types import Tool, ToolDac
v=json.loads(sys.argv[1])
p=parse_profiles(v["profiles"])
p=replace(p, tools={"reader":replace(p.tools["reader"],syscall_sets=frozenset())})
l=MacOSNativeLauncher(**{k:Path(x) if k in {"path","library","stdlib","dynload"} else x for k,x in v["launcher"].items()})
s=MacOSToolSpec("macos_tool:run",Path(v["source"]),v["digest"])
e=MacOSSandboxExecutor(p,{"reader":s},launcher=l,experimental=True,recovery_directory=Path(v["recovery"]))
c=ToolCall(Tool("reader",ToolDac("reader",{"reader":"x"}),frozenset(),()),{"operation":"sleep"},{},"crash-call",0)
e.invoke(Principal("alice",frozenset({"reader"}),frozenset(),"session"),c,())
"""
    payload = {
        "profiles": f"tool reader {{\n owner reader\n grant reader: call\n runs macos\n fs read {data}/** need\n}}\nprincipal alice {{\n roles reader\n fs read {data}/**\n}}",
        "source": str(spec.artifact_path),
        "digest": spec.artifact_digest,
        "recovery": str(root / "recovery"),
        "launcher": {
            key: str(getattr(launcher, key))
            for key in (
                "path",
                "digest",
                "library",
                "library_digest",
                "stdlib",
                "dynload",
            )
        },
    }
    controller = subprocess.Popen(
        [sys.executable, "-c", program, json.dumps(payload)],
        stdout=subprocess.DEVNULL,
        stderr=subprocess.PIPE,
    )
    try:
        deadline = time.monotonic() + 10
        records = []
        while time.monotonic() < deadline and controller.poll() is None:
            records = list((root / "recovery").glob("*.json"))
            if records:
                break
            time.sleep(0.02)
        if not records:
            raise AssertionError(controller.communicate(timeout=2)[1])
        record = json.loads(records[0].read_text())
        identity = _process_identity(record["pid"])
        assert identity == record["start_time"]
        time.sleep(0.05)
        controller.kill()
        controller.wait(timeout=2)
        deadline = time.monotonic() + 3
        while (
            time.monotonic() < deadline and _process_identity(record["pid"]) == identity
        ):
            time.sleep(0.02)
        assert _process_identity(record["pid"]) != identity
        assert records[0].exists()  # Only the controller reconciles durable state.
        recovered = _executor(data, spec, launcher)
        pending = recovered.unresolved_terminations()
        assert len(pending) == 1
        assert recovered.confirm_termination(pending[0])
        assert not list((root / "recovery").glob("*.json"))
    finally:
        if controller.poll() is None:
            controller.kill()
        controller.wait(timeout=2)
        if controller.stderr:
            controller.stderr.close()


@_NATIVE
def test_mandatory_constraints_prevent_release(native, launcher):
    _, data, spec = native
    executor = _executor(data, spec, launcher)
    restriction = ForbidConstraint(
        "deny-data",
        RulePredicate(domain="filesystem"),
        "test restriction",
        module="test-policy",
    )
    with pytest.raises(HostExecutionDenied):
        executor.invoke(_PRINCIPAL, _call(path=str(data / "report")), (restriction,))
    assert executor.activation_receipts() == ()
    assert not list(executor.recovery_directory.glob("*.json"))


@_NATIVE
def test_host_router_uses_macos_executor(native, launcher):
    _, data, spec = native
    executor = _executor(data, spec, launcher)
    router = make_authorized_host_router(executor)
    result = router.invoke(
        _PRINCIPAL,
        _call(path=str(data / "report")),
        Decision(Verdict.ALLOW, "test allow"),
    )
    assert result.value == "allowed report"


@_NATIVE
def test_hard_links_follow_authorized_names(native, launcher):
    root, data, spec = native
    os.link(root / "secret", data / "inside")
    os.link(data / "report", root / "outside")
    executor = _executor(data, spec, launcher)
    assert (
        executor.invoke(_PRINCIPAL, _call(path=str(data / "inside")), ()).value
        == "forbidden secret"
    )
    with pytest.raises(HostExecutionError):
        executor.invoke(_PRINCIPAL, _call(path=str(root / "outside")), ())


@_NATIVE
def test_module_initialization_is_confined(native, launcher):
    root, data, spec = native
    code = f"try:\n open({str(root / 'secret')!r}).read()\n violation=True\nexcept PermissionError:\n violation=False\ndef run(): return violation\n"
    spec.artifact_path.write_text(code)
    updated = replace(spec, artifact_digest=hashlib.sha256(code.encode()).hexdigest())
    executor = _executor(data, updated, launcher)
    assert executor.invoke(_PRINCIPAL, _call(), ()).value is False


@_NATIVE
def test_standard_library_sleep_survives_capability_disposal(native, launcher):
    _, data, spec = native
    code = "def run():\n import time\n time.sleep(0.01)\n return True\n"
    spec.artifact_path.write_text(code)
    updated = replace(spec, artifact_digest=hashlib.sha256(code.encode()).hexdigest())
    executor = _executor(data, updated, launcher)
    assert executor.invoke(_PRINCIPAL, _call(), ()).value is True


@pytest.mark.parametrize("value", [float("inf"), float("nan"), float("-inf")])
def test_nonfinite_worker_values_refused(value):
    with pytest.raises(ValueError, match="non-finite"):
        _validate_json({"result": value})


def test_duplicate_worker_fields_refused():
    with pytest.raises(ValueError, match="duplicate"):
        _unique_pairs([("status", "ok"), ("status", "error")])
