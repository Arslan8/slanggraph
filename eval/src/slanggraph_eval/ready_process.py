"""Run a child behind a READY/GO barrier with parent monotonic timing."""

from __future__ import annotations

import contextlib
import json
import os
import select
import signal
import subprocess
import time
from dataclasses import dataclass
from pathlib import Path

_READY = {"argus_eval_protocol": 1, "state": "ready"}


@dataclass(frozen=True, slots=True)
class ReadyProcessResult:
    returncode: int | None
    stdout: str
    stderr: str
    timed_out: bool
    ready_observed: bool
    cleanup_confirmed: bool
    process_group_id: int
    preflight_ns: int
    runtime_start_ns: int
    runtime_end_ns: int

    @property
    def runtime_ns(self) -> int:
        return self.runtime_end_ns - self.runtime_start_ns


def _group_exists(process_group_id: int) -> bool:
    try:
        os.killpg(process_group_id, 0)
    except ProcessLookupError:
        return False
    return True


def _terminate(process: subprocess.Popen[str], grace_seconds: float) -> bool:
    with contextlib.suppress(ProcessLookupError):
        os.killpg(process.pid, signal.SIGTERM)
    deadline = time.monotonic() + grace_seconds
    while _group_exists(process.pid) and time.monotonic() < deadline:
        time.sleep(0.01)
    if _group_exists(process.pid):
        with contextlib.suppress(ProcessLookupError):
            os.killpg(process.pid, signal.SIGKILL)
    with contextlib.suppress(subprocess.TimeoutExpired):
        process.wait(timeout=grace_seconds)
    return not _group_exists(process.pid)


def _await_ready(
    process: subprocess.Popen[str], timeout: float
) -> tuple[bool, list[str], list[str]]:
    assert process.stdout is not None and process.stderr is not None
    stdout: list[str] = []
    stderr: list[str] = []
    deadline = time.monotonic() + timeout
    while process.poll() is None:
        remaining = deadline - time.monotonic()
        if remaining <= 0:
            return False, stdout, stderr
        readable, _, _ = select.select(
            [process.stdout, process.stderr], [], [], min(remaining, 0.25)
        )
        for stream in readable:
            line = stream.readline()
            if not line:
                continue
            if stream is process.stderr:
                stderr.append(line)
                continue
            try:
                marker = json.loads(line)
            except json.JSONDecodeError:
                stdout.append(line)
                continue
            if marker == _READY:
                return True, stdout, stderr
            stdout.append(line)
    remaining_stdout, remaining_stderr = process.communicate()
    stdout.append(remaining_stdout)
    stderr.append(remaining_stderr)
    return False, stdout, stderr


def run_ready_process(
    command: list[str],
    *,
    cwd: Path,
    env: dict[str, str] | None,
    preflight_timeout: float,
    runtime_timeout: float,
    cleanup_grace_seconds: float = 5.0,
) -> ReadyProcessResult:
    """Wait for child preparation, then time GO through process-group cleanup."""
    child_env = dict(os.environ if env is None else env)
    child_env["ARGUS_EVAL_READY_PROTOCOL"] = "1"
    preflight_started = time.monotonic_ns()
    process = subprocess.Popen(
        command,
        cwd=cwd,
        env=child_env,
        stdin=subprocess.PIPE,
        stdout=subprocess.PIPE,
        stderr=subprocess.PIPE,
        text=True,
        start_new_session=True,
    )
    ready, stdout_prefix, stderr_prefix = _await_ready(process, preflight_timeout)
    preflight_ns = time.monotonic_ns() - preflight_started
    if not ready:
        preflight_timed_out = process.poll() is None
        cleanup_confirmed = _terminate(process, cleanup_grace_seconds)
        tail_stdout, tail_stderr = process.communicate()
        now = time.monotonic_ns()
        return ReadyProcessResult(
            returncode=process.returncode,
            stdout="".join(stdout_prefix) + tail_stdout,
            stderr="".join(stderr_prefix) + tail_stderr,
            timed_out=preflight_timed_out,
            ready_observed=False,
            cleanup_confirmed=cleanup_confirmed,
            process_group_id=process.pid,
            preflight_ns=preflight_ns,
            runtime_start_ns=now,
            runtime_end_ns=now,
        )

    assert process.stdin is not None
    runtime_start_ns = time.monotonic_ns()
    process.stdin.write("GO\n")
    process.stdin.flush()
    process.stdin.close()
    process.stdin = None
    timed_out = False
    try:
        tail_stdout, tail_stderr = process.communicate(timeout=runtime_timeout)
        cleanup_confirmed = True
    except subprocess.TimeoutExpired:
        timed_out = True
        cleanup_confirmed = _terminate(process, cleanup_grace_seconds)
        tail_stdout, tail_stderr = process.communicate()
    runtime_end_ns = time.monotonic_ns()
    return ReadyProcessResult(
        returncode=None if timed_out else process.returncode,
        stdout="".join(stdout_prefix) + tail_stdout,
        stderr="".join(stderr_prefix) + tail_stderr,
        timed_out=timed_out,
        ready_observed=True,
        cleanup_confirmed=cleanup_confirmed,
        process_group_id=process.pid,
        preflight_ns=preflight_ns,
        runtime_start_ns=runtime_start_ns,
        runtime_end_ns=runtime_end_ns,
    )
