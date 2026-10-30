"""Worker cleanup belongs to this call, never a caller's handled exception.

The child speaks the real startup/result protocol over OS pipes. Its activation
and termination confirmation are controlled fixtures, not confinement evidence.
No bubblewrap installation or permission to create namespaces is required.
"""

from __future__ import annotations

import asyncio
import hashlib
import os
import subprocess
import sys
import time
from pathlib import Path
from threading import Event, RLock
from types import SimpleNamespace
from unittest.mock import Mock

import pytest

from langgraph.prebuilt.security import linux
from langgraph.prebuilt.security.enforcement import (
    ActivationReceipt,
    AdapterPlan,
    EnforcementMode,
    EnforcementPlan,
)
from langgraph.prebuilt.security.execution import HostExecutionError
from langgraph.prebuilt.security.linux import LinuxSandboxExecutor, LinuxToolSpec
from langgraph.prebuilt.security.types import (
    ExecutionOutcome,
    Principal,
    Tool,
    ToolCall,
    ToolDac,
)

_CHILD = """
import json, os, sys
request = json.loads(sys.stdin.buffer.readline())
status_fd = int(sys.argv[1])
os.write(status_fd, json.dumps({"child-pid": os.getpid()}).encode())
os.close(status_fd)
print(json.dumps({
    "status": "ready",
    "plan_digest": request["plan_digest"],
    "startup_challenge": request["startup_challenge"],
}), flush=True)
assert sys.stdin.buffer.readline() == b"GO\\n"
with open(sys.argv[2], "w") as marker:
    marker.write("GO received")
print(json.dumps({"status": "ok", "result": "useful-result"}), flush=True)
"""


def test_committed_worker_cleanup_runs_off_the_invocation_path(monkeypatch):
    executor = object.__new__(LinuxSandboxExecutor)
    executor._reaper_lock = RLock()
    executor._reaper_threads = set()
    started = Event()
    release = Event()

    def cleanup(**_):
        started.set()
        assert release.wait(2)

    monkeypatch.setattr(executor, "_cleanup_worker", cleanup)
    executor._schedule_committed_cleanup({})
    assert started.wait(1)
    with executor._reaper_lock:
        assert len(executor._reaper_threads) == 1
    release.set()
    deadline = time.monotonic() + 2
    while time.monotonic() < deadline:
        with executor._reaper_lock:
            if not executor._reaper_threads:
                break
        time.sleep(0.001)
    with executor._reaper_lock:
        assert not executor._reaper_threads


@pytest.fixture
def worker(tmp_path: Path, monkeypatch: pytest.MonkeyPatch):
    artifact = tmp_path / "tool.py"
    artifact.write_text("def run(): return 'useful-result'\n")
    spec = LinuxToolSpec(
        "tool:run", artifact, hashlib.sha256(artifact.read_bytes()).hexdigest()
    )
    executor = object.__new__(LinuxSandboxExecutor)
    executor.python_executable = Path(sys.executable)
    executor._worker_script = artifact
    executor._worker_digest = spec.artifact_digest
    executor.runtime_roots = (tmp_path,)
    executor.startup_timeout_s = 5.0
    executor.default_wall_timeout_s = 5.0
    executor._receipt_lock = RLock()
    executor._receipts = []
    executor._termination_lock = RLock()
    executor._unresolved = {}
    executor._recovery_leases = {}
    executor.integrity_recheck = linux.IntegrityRecheckMode.FULL
    executor.integrity_chunk_bytes = 65_536
    executor.integrity_samples = 4
    executor.worker_pool_capacity = 0
    receipt = ActivationReceipt(
        "grant",
        "plan",
        "host",
        "context",
        "nonce",
        EnforcementMode.ENFORCED,
        (),
        frozenset(),
        1.0,
    )
    adapter_plan = AdapterPlan(
        linux._ADAPTER_ID, frozenset({"controlled"}), "native-plan", {}
    )
    plan = EnforcementPlan(
        "grant", "host", "obligation", EnforcementMode.ENFORCED, (), (adapter_plan,)
    )
    adapter = Mock(python_digest=linux._file_digest(Path(sys.executable)))
    coordinator = Mock()
    coordinator.activate.return_value = receipt
    coordinator.validate_receipt.return_value = True
    principal = Principal("alice", frozenset(), frozenset(), "session")
    tool = Tool("controlled", ToolDac("owner", {"owner": "x"}), frozenset(), ())
    call = ToolCall(tool, {}, {}, "call", 0)
    harness = SimpleNamespace(
        executor=executor,
        receipt=receipt,
        confirmed=True,
        injected=None,
        cleanup_errors=[],
        children=[],
        status_fds=[],
        go_marker=tmp_path / "go-received",
        principal=principal,
        call=call,
        spec=spec,
        grant=Mock(),
        host=Mock(boot_id="boot"),
        plan=plan,
        adapter=adapter,
        coordinator=coordinator,
    )

    def command(*_):
        read_fd, write_fd = os.pipe()
        harness.status_fds.extend((read_fd, write_fd))
        directory = tmp_path / "private-artifact"
        directory.mkdir()
        return (
            [sys.executable, "-c", _CHILD, str(write_fd), str(harness.go_marker)],
            (),
            read_fd,
            write_fd,
            directory,
        )

    monkeypatch.setattr(executor, "_worker_command", command)
    monkeypatch.setattr(linux, "_sandbox_payload_pid", lambda pid, **_: pid)
    monkeypatch.setattr(
        linux,
        "_execution_context",
        lambda pid: SimpleNamespace(process_identity=f"{pid}:controlled-start"),
    )
    monkeypatch.setattr(
        linux, "_confirm_worker_terminated", lambda *_, **__: harness.confirmed
    )
    original_popen = subprocess.Popen

    def spawn(*args, **kwargs):
        child = original_popen(*args, **kwargs)
        # The Lean integration also launches a checker using subprocess.run.
        # Retain only the controlled worker here; run owns the checker process.
        if args[0][0] == sys.executable:
            harness.children.append(child)
        return child

    monkeypatch.setattr(linux.subprocess, "Popen", spawn)
    original_read = linux._readline_json
    reads = 0

    def read(*args, **kwargs):
        nonlocal reads
        reads += 1
        if reads == 2 and harness.injected is not None:
            raise harness.injected
        return original_read(*args, **kwargs)

    monkeypatch.setattr(linux, "_readline_json", read)
    original_cleanup = executor._cleanup_worker

    def cleanup(**kwargs):
        harness.cleanup_errors.append(kwargs["active_error"])
        return original_cleanup(**kwargs)

    monkeypatch.setattr(executor, "_cleanup_worker", cleanup)
    monkeypatch.setattr(
        executor,
        "_schedule_committed_cleanup",
        lambda values: executor._cleanup_worker(**values),
    )
    harness.run = lambda: executor._run_worker(
        harness.principal,
        harness.call,
        harness.spec,
        harness.grant,
        harness.host,
        harness.plan,
        None,
        adapter,
        harness.coordinator,
        (),
        asynchronous=False,
        grant_projection=getattr(harness, "grant_projection", None),
        obligation_projection=getattr(harness, "obligation_projection", None),
    )
    yield harness
    for child in harness.children:
        if child.poll() is None:
            child.kill()
        child.wait(timeout=5)
        for stream in (child.stdin, child.stdout, child.stderr):
            if stream is not None:
                stream.close()


def _prior_error(worker) -> HostExecutionError:
    return HostExecutionError("earlier call", worker.receipt, ExecutionOutcome.FAILED)


def test_success_inside_handled_error_keeps_prior_lifetime_unchanged(worker):
    prior = _prior_error(worker)
    try:
        raise prior
    except HostExecutionError:
        result = worker.run()
    assert result.value == "useful-result"
    assert result.receipt is worker.receipt
    assert worker.cleanup_errors == [None]
    assert prior.outcome is ExecutionOutcome.FAILED
    assert prior.termination_confirmed is False
    assert prior.recovery is None
    assert not worker.executor.unresolved_terminations()
    assert all(child.poll() is not None for child in worker.children)
    for fd in worker.status_fds:
        with pytest.raises(OSError):
            os.fstat(fd)


def test_unknown_cleanup_inside_handled_error_cannot_return_success(worker):
    worker.confirmed = False
    prior = _prior_error(worker)
    try:
        raise prior
    except HostExecutionError:
        with pytest.raises(HostExecutionError) as caught:
            worker.run()
    failure = caught.value
    assert failure is not prior
    assert failure.outcome is ExecutionOutcome.INDETERMINATE
    assert failure.termination_confirmed is False
    assert failure.recovery in worker.executor.unresolved_terminations()
    assert worker.cleanup_errors == [None]
    assert prior.outcome is ExecutionOutcome.FAILED
    assert prior.termination_confirmed is False
    assert prior.recovery is None


@pytest.mark.parametrize("confirmed", [False, True])
def test_actual_host_error_is_preserved_inside_handled_error(worker, confirmed):
    worker.confirmed = confirmed
    active = HostExecutionError("current call", worker.receipt, ExecutionOutcome.FAILED)
    worker.injected = active
    prior = _prior_error(worker)
    try:
        raise prior
    except HostExecutionError:
        with pytest.raises(HostExecutionError) as caught:
            worker.run()
    assert caught.value is active
    assert worker.cleanup_errors == [active]
    assert active.termination_confirmed is confirmed
    assert active.outcome is (
        ExecutionOutcome.FAILED if confirmed else ExecutionOutcome.INDETERMINATE
    )
    assert (active.recovery is None) is confirmed
    assert prior.outcome is ExecutionOutcome.FAILED
    assert prior.termination_confirmed is False
    assert prior.recovery is None


@pytest.mark.parametrize(
    "error_type", [KeyboardInterrupt, SystemExit, GeneratorExit, asyncio.CancelledError]
)
@pytest.mark.parametrize("confirmed", [False, True])
def test_base_exception_is_current_cleanup_context(worker, error_type, confirmed):
    worker.confirmed = confirmed
    active = error_type("current call")
    worker.injected = active
    prior = _prior_error(worker)
    expected = error_type if confirmed else HostExecutionError
    try:
        raise prior
    except HostExecutionError:
        with pytest.raises(expected) as caught:
            worker.run()
    assert worker.cleanup_errors == [active]
    if confirmed:
        assert caught.value is active
    else:
        assert caught.value.__context__ is active
        assert caught.value.outcome is ExecutionOutcome.INDETERMINATE
        assert caught.value.recovery in worker.executor.unresolved_terminations()
    assert prior.outcome is ExecutionOutcome.FAILED
    assert prior.termination_confirmed is False
    assert prior.recovery is None


@pytest.mark.parametrize("error_type", [TimeoutError, OSError, ValueError])
def test_translated_failure_is_current_cleanup_context(worker, error_type):
    original = error_type("current call")
    worker.injected = original
    with pytest.raises(HostExecutionError) as caught:
        worker.run()
    assert caught.value.__cause__ is original
    assert worker.cleanup_errors == [caught.value]
    assert caught.value.termination_confirmed is True
    assert caught.value.outcome is ExecutionOutcome.INDETERMINATE
