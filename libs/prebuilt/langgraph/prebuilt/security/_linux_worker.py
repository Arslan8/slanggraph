"""Trusted startup shim for the Linux sandbox executor.

This module is an implementation detail. It applies resource and syscall
restrictions before importing the operator-selected tool entry point.
"""

from __future__ import annotations

import asyncio
import builtins
import contextlib
import ctypes
import errno
import inspect
import io
import json
import os
import resource
import sys
import time
from collections.abc import Mapping
from dataclasses import dataclass
from types import ModuleType
from typing import Any

_MAX_FRAME = 1_048_576
_ALLOWED_SYSCALLS = (
    "access",
    "arch_prctl",
    "brk",
    "clock_gettime",
    "clock_nanosleep",
    "close",
    "dup",
    "dup2",
    "dup3",
    "epoll_create1",
    "epoll_ctl",
    "epoll_pwait",
    "epoll_wait",
    "eventfd2",
    "exit",
    "exit_group",
    "faccessat",
    "faccessat2",
    "fcntl",
    "fdatasync",
    "fstat",
    "fsync",
    "ftruncate",
    "futex",
    "getcwd",
    "getdents64",
    "getegid",
    "geteuid",
    "getgid",
    "getpid",
    "getppid",
    "getrandom",
    "gettid",
    "getuid",
    "lseek",
    "madvise",
    "mkdir",
    "mkdirat",
    "mmap",
    "mprotect",
    "mremap",
    "munmap",
    "nanosleep",
    "newfstatat",
    "open",
    "openat",
    "pipe",
    "pipe2",
    "poll",
    "ppoll",
    "pread64",
    "prlimit64",
    "pselect6",
    "read",
    "readlink",
    "readlinkat",
    "readv",
    "restart_syscall",
    "rmdir",
    "rseq",
    "rt_sigaction",
    "rt_sigprocmask",
    "rt_sigreturn",
    "sched_getaffinity",
    "sched_yield",
    "select",
    "set_robust_list",
    "set_tid_address",
    "sigaltstack",
    "stat",
    "statx",
    "sysinfo",
    "truncate",
    "uname",
    "unlink",
    "unlinkat",
    "write",
    "writev",
)
_KILL_SYSCALLS = (
    "bpf",
    "process_vm_readv",
    "ptrace",
    "unshare",
)


class _DiscardTextIO(io.TextIOBase):
    """Accept tool text without retaining it in the protocol process."""

    def write(self, value: str) -> int:
        if not isinstance(value, str):
            raise TypeError("tool output must be text")
        return len(value)


_DISCARD_OUTPUT = _DiscardTextIO()


@dataclass(slots=True)
class _PreparedInvocation:
    """Side-effect-free worker preparation completed before the release barrier."""

    request: Mapping[str, Any]
    module: ModuleType
    code: Any
    attribute_path: tuple[str, ...]
    args: dict[str, Any]
    call: dict[str, Any]


def main() -> int:
    """Run one request after a parent-verified startup barrier."""
    protocol_output = sys.stdout
    event_loop: asyncio.AbstractEventLoop | None = None
    try:
        request = _read_request()
        ruleset_fd = request.get("landlock_ruleset_fd")
        broker_fd = request.get("broker_fd")
        if ruleset_fd is not None:
            if type(ruleset_fd) is not int or ruleset_fd < 3:
                raise ValueError("invalid Landlock ruleset descriptor")
            if broker_fd is not None and (type(broker_fd) is not int or broker_fd < 3):
                raise ValueError("invalid broker descriptor")
            _apply_landlock(
                ruleset_fd,
                frozenset({broker_fd}) if isinstance(broker_fd, int) else frozenset(),
            )
        _apply_limits(request.get("limits"))
        if bool(request.get("asynchronous")):
            event_loop = asyncio.new_event_loop()
        _apply_seccomp()
        pool_key = request.get("pool_key")
        prepared: _PreparedInvocation
        if request.get("pool_bootstrap") is True:
            if not isinstance(pool_key, str) or len(pool_key) != 64:
                raise ValueError("invalid worker pool key")
            prepared = _prepare_invocation(request)
            _write(protocol_output, {"pool_key": pool_key, "status": "pooled"})
            request = _read_request()
            if request.get("pool_key") != pool_key:
                raise ValueError("worker pool key mismatch")
            prepared = _bind_prepared_invocation(prepared, request)
        else:
            prepared = _prepare_invocation(request)
        _write(
            protocol_output,
            {
                "plan_digest": request["plan_digest"],
                "startup_challenge": request["startup_challenge"],
                "status": "ready",
            },
        )
        if sys.stdin.readline(16) != "GO\n":
            return 73
        timing_ns: dict[str, int] | None = (
            {} if request.get("evaluation_telemetry") is True else None
        )
        body_started = time.perf_counter_ns() if timing_ns is not None else 0
        result = _invoke(prepared, event_loop, timing_ns=timing_ns)
        body_ns = (
            time.perf_counter_ns() - body_started if timing_ns is not None else None
        )
        _write_result(
            protocol_output,
            result,
            body_ns=body_ns,
            timing_ns=timing_ns,
        )
        return 0
    except BaseException as exc:
        try:
            _write(
                protocol_output,
                {"error_type": type(exc).__name__, "status": "error"},
            )
        except BaseException:
            pass
        return 70
    finally:
        if event_loop is not None:
            event_loop.close()


def _read_request() -> Mapping[str, Any]:
    line = sys.stdin.readline(_MAX_FRAME + 1)
    if not line or len(line) > _MAX_FRAME or not line.endswith("\n"):
        raise ValueError("invalid request frame")
    value = json.loads(line)
    if not isinstance(value, dict):
        raise ValueError("request must be an object")
    if value.get("pool_bootstrap") is True:
        required = {"asynchronous", "limits", "pool_key"}
        if not required.issubset(value):
            raise ValueError("pool bootstrap is missing required fields")
        return value
    required = {
        "args",
        "artifact_path",
        "call_id",
        "entrypoint",
        "plan_digest",
        "runtime_roots",
        "startup_challenge",
        "tool_name",
    }
    if not required.issubset(value):
        raise ValueError("request is missing required fields")
    if (
        "evaluation_telemetry" in value
        and type(value["evaluation_telemetry"]) is not bool
    ):
        raise TypeError("evaluation_telemetry must be a boolean")
    return value


def _apply_limits(raw: object) -> None:
    limits = raw if isinstance(raw, Mapping) else {}
    cpu_ms = limits.get("cpu_ms")
    if isinstance(cpu_ms, int):
        if cpu_ms % 1000:
            raise ValueError("cpu_ms must use whole-second RLIMIT_CPU granularity")
        seconds = cpu_ms // 1000
        resource.setrlimit(resource.RLIMIT_CPU, (seconds, seconds))
    address_space = limits.get("address_space_bytes")
    if isinstance(address_space, int):
        resource.setrlimit(resource.RLIMIT_AS, (address_space, address_space))
    file_size = limits.get("file_size_bytes")
    if isinstance(file_size, int):
        resource.setrlimit(resource.RLIMIT_FSIZE, (file_size, file_size))
    nofile = limits.get("nofile")
    if isinstance(nofile, int):
        resource.setrlimit(resource.RLIMIT_NOFILE, (nofile, nofile))
    pids = limits.get("pids")
    if isinstance(pids, int):
        resource.setrlimit(resource.RLIMIT_NPROC, (pids, pids))


def _apply_landlock(
    ruleset_fd: int, preserve_fds: frozenset[int] = frozenset()
) -> None:
    """Enter the parent-built ruleset with no ambient resource descriptors."""
    descriptors: list[int] = []
    try:
        descriptors = [int(name) for name in os.listdir("/proc/self/fd")]
    except (OSError, ValueError):
        soft_limit = resource.getrlimit(resource.RLIMIT_NOFILE)[0]
        maximum = 65_536 if soft_limit == resource.RLIM_INFINITY else int(soft_limit)
        descriptors = list(range(3, maximum))
    for descriptor in descriptors:
        if descriptor <= 2 or descriptor == ruleset_fd or descriptor in preserve_fds:
            continue
        try:
            os.close(descriptor)
        except OSError:
            pass
    libc = ctypes.CDLL(None, use_errno=True)
    if libc.prctl(38, 1, 0, 0, 0) != 0:
        raise OSError(ctypes.get_errno(), "PR_SET_NO_NEW_PRIVS failed")
    ctypes.set_errno(0)
    if libc.syscall(446, ruleset_fd, 0) != 0:
        raise OSError(ctypes.get_errno(), "landlock_restrict_self failed")
    os.close(ruleset_fd)


def _apply_seccomp() -> None:
    library = ctypes.CDLL("libseccomp.so.2", use_errno=True)
    library.seccomp_init.argtypes = [ctypes.c_uint32]
    library.seccomp_init.restype = ctypes.c_void_p
    library.seccomp_syscall_resolve_name.argtypes = [ctypes.c_char_p]
    library.seccomp_syscall_resolve_name.restype = ctypes.c_int
    library.seccomp_rule_add.argtypes = [
        ctypes.c_void_p,
        ctypes.c_uint32,
        ctypes.c_int,
        ctypes.c_uint,
    ]
    library.seccomp_rule_add.restype = ctypes.c_int
    library.seccomp_load.argtypes = [ctypes.c_void_p]
    library.seccomp_load.restype = ctypes.c_int
    library.seccomp_release.argtypes = [ctypes.c_void_p]
    allow = ctypes.c_uint32(0x7FFF0000)
    deny = ctypes.c_uint32(0x00050000 | errno.EPERM)
    kill = ctypes.c_uint32(0x80000000)
    context = library.seccomp_init(deny)
    if not context:
        raise OSError("seccomp initialization failed")
    try:
        for name in _KILL_SYSCALLS:
            number = library.seccomp_syscall_resolve_name(name.encode())
            if number < 0:
                continue
            if library.seccomp_rule_add(context, kill, number, 0) != 0:
                raise OSError(f"seccomp kill rule failed:{name}")
        for name in _ALLOWED_SYSCALLS:
            number = library.seccomp_syscall_resolve_name(name.encode())
            if number < 0:
                continue
            if library.seccomp_rule_add(context, allow, number, 0) != 0:
                raise OSError(f"seccomp rule failed:{name}")
        if library.seccomp_load(context) != 0:
            raise OSError("seccomp activation failed")
    finally:
        library.seccomp_release(context)


def _prepare_invocation(request: Mapping[str, Any]) -> _PreparedInvocation:
    """Read and compile pinned tool bytes without executing tool code."""
    entrypoint = str(request["entrypoint"])
    module_name, _, attribute_path = entrypoint.partition(":")
    if not module_name or not attribute_path:
        raise ValueError("tool entrypoint must name a module and attribute")
    artifact_path = str(request["artifact_path"])
    runtime_roots = request["runtime_roots"]
    if not isinstance(runtime_roots, list) or any(
        type(item) is not str for item in runtime_roots
    ):
        raise TypeError("runtime_roots must be a list of paths")
    tool_import_roots = request.get("tool_import_roots", [])
    if not isinstance(tool_import_roots, list) or any(
        type(item) is not str for item in tool_import_roots
    ):
        raise TypeError("tool_import_roots must be a list of paths")
    fixed_runtime_roots = list(sys.path)
    sys.path[:] = tool_import_roots + runtime_roots + fixed_runtime_roots
    module = ModuleType(module_name)
    module.__file__ = artifact_path
    module.__package__ = module_name.rpartition(".")[0]
    importer = _worker_importer(request)
    if importer is not None:
        module.__dict__["__builtins__"] = {**vars(builtins), "__import__": importer}
    sys.modules[module_name] = module
    with open(artifact_path, "rb") as source:
        code = compile(source.read(), artifact_path, "exec", dont_inherit=True)
    args, call = _invocation_values(request)
    return _PreparedInvocation(
        request, module, code, tuple(attribute_path.split(".")), args, call
    )


def _bind_prepared_invocation(
    prepared: _PreparedInvocation, request: Mapping[str, Any]
) -> _PreparedInvocation:
    """Bind dynamic call data to code compiled in the confined preflight phase."""
    for name in (
        "artifact_path",
        "asynchronous",
        "entrypoint",
        "runtime_roots",
        "tool_import_roots",
        "tool_name",
    ):
        if request.get(name, [] if name == "tool_import_roots" else None) != (
            prepared.request.get(name, [] if name == "tool_import_roots" else None)
        ):
            raise ValueError(f"pooled worker invariant changed:{name}")
    args, call = _invocation_values(request)
    return _PreparedInvocation(
        request,
        prepared.module,
        prepared.code,
        prepared.attribute_path,
        args,
        call,
    )


def _invocation_values(
    request: Mapping[str, Any],
) -> tuple[dict[str, Any], dict[str, Any]]:
    args = request["args"]
    if not isinstance(args, dict):
        raise TypeError("tool arguments must be an object")
    call = {
        "args": args,
        "id": str(request["call_id"]),
        "name": str(request["tool_name"]),
        "type": "tool_call",
    }
    return args, call


def _invoke(
    prepared: _PreparedInvocation,
    event_loop: asyncio.AbstractEventLoop | None,
    *,
    timing_ns: dict[str, int] | None = None,
) -> Any:
    request = prepared.request
    with (
        contextlib.redirect_stdout(_DISCARD_OUTPUT),
        contextlib.redirect_stderr(_DISCARD_OUTPUT),
    ):
        started = time.perf_counter_ns() if timing_ns is not None else 0
        exec(prepared.code, prepared.module.__dict__)
        if timing_ns is not None:
            timing_ns["module_execution"] = time.perf_counter_ns() - started
        started = time.perf_counter_ns() if timing_ns is not None else 0
        target: Any = prepared.module
        for part in prepared.attribute_path:
            target = getattr(target, part)
        if timing_ns is not None:
            timing_ns["target_resolution"] = time.perf_counter_ns() - started
        started = time.perf_counter_ns() if timing_ns is not None else 0
        if bool(request.get("asynchronous")) and hasattr(target, "ainvoke"):
            if event_loop is None:
                raise RuntimeError("async worker event loop is unavailable")
            result = event_loop.run_until_complete(target.ainvoke(prepared.call))
        elif hasattr(target, "invoke"):
            result = target.invoke(prepared.call)
        else:
            result = target(**prepared.args)
            if inspect.isawaitable(result):
                if event_loop is None:
                    raise RuntimeError("async result requires an async worker")
                result = event_loop.run_until_complete(result)
        if timing_ns is not None:
            timing_ns["target_call"] = time.perf_counter_ns() - started
        return result


class _RecordsClient:
    """Minimal worker-side client for the built-in record mediator."""

    __slots__ = ()

    def read(self, record: str) -> dict[str, object]:
        _text(record, "record")
        result = _broker_request(_record_service(record), "read", {})
        if (
            type(result) is not dict
            or set(result) != {"found", "value"}
            or type(result["found"]) is not bool
            or not (result["value"] is None or type(result["value"]) is str)
        ):
            raise TypeError("invalid db_record.read result")
        return result

    def write(self, record: str, value: str) -> dict[str, bool]:
        _text(record, "record")
        _text(value, "value")
        return _record_mutation(
            _broker_request(_record_service(record), "write", {"value": value}),
            "write",
        )

    def delete(self, record: str) -> dict[str, bool]:
        _text(record, "record")
        return _record_mutation(
            _broker_request(_record_service(record), "delete", {}), "delete"
        )


def _worker_importer(request: Mapping[str, Any]):
    raw = request.get("broker_client_imports", [])
    if not isinstance(raw, list) or any(type(item) is not str for item in raw):
        raise TypeError("broker_client_imports must be a list of module names")
    supported = "langgraph.prebuilt.security.mediators.records"
    if any(item != supported for item in raw):
        raise ValueError("unsupported broker client import")
    if supported not in raw:
        return None
    records_module = ModuleType(supported)
    records_module.records = _RecordsClient()

    def importing(name, globals=None, locals=None, fromlist=(), level=0):
        if name == supported and level == 0 and fromlist:
            return records_module
        return builtins.__import__(name, globals, locals, fromlist, level)

    return importing


def _record_service(record: str) -> str:
    return json.dumps(["db_record", record], separators=(",", ":"))


def _record_mutation(result: Any, operation: str) -> dict[str, bool]:
    if (
        type(result) is not dict
        or set(result) != {"ok"}
        or type(result["ok"]) is not bool
    ):
        raise TypeError(f"invalid db_record.{operation} result")
    return result


def _text(value: object, name: str) -> None:
    if type(value) is not str:
        raise TypeError(f"{name} requires str")


def _broker_request(service: str, operation: str, payload: Mapping[str, Any]) -> Any:
    """Use the inherited spawn-bound channel without importing the host package."""
    raw_fd = os.environ.get("SLANGGRAPH_BROKER_FD")
    if raw_fd is None:
        raise PermissionError("broker:channel_unavailable")
    try:
        descriptor = int(raw_fd)
    except ValueError as exc:
        raise PermissionError("broker:invalid_channel") from exc
    encoded = json.dumps(
        {"operation": operation, "payload": dict(payload), "service": service},
        sort_keys=True,
        separators=(",", ":"),
    ).encode()
    if len(encoded) + 1 > _MAX_FRAME:
        raise ValueError("broker request exceeds frame limit")
    duplicate = os.dup(descriptor)
    try:
        pending = memoryview(encoded + b"\n")
        while pending:
            written = os.write(duplicate, pending)
            if written <= 0:
                raise PermissionError("broker:channel_closed")
            pending = pending[written:]
        response = bytearray()
        while len(response) <= _MAX_FRAME:
            chunk = os.read(duplicate, min(65_536, _MAX_FRAME + 1 - len(response)))
            if not chunk:
                break
            response.extend(chunk)
            if response.endswith(b"\n"):
                break
        frame = bytes(response)
        if not frame or len(frame) > _MAX_FRAME or not frame.endswith(b"\n"):
            raise PermissionError("broker:invalid_response")
        result = json.loads(frame)
        if not isinstance(result, dict) or result.get("status") != "ok":
            reason = (
                result.get("error", "broker:denied")
                if isinstance(result, dict)
                else "broker:invalid_response"
            )
            raise PermissionError(str(reason))
        return result.get("result")
    finally:
        os.close(duplicate)


def _encode_json_value(value: object) -> str:
    """Validate and encode exact result data in one recursive pass."""
    kind = type(value)
    if value is None or kind in {bool, int, float, str}:
        return json.dumps(value, separators=(",", ":"))
    if isinstance(value, list | tuple) and kind in {list, tuple}:
        return "[" + ",".join(_encode_json_value(item) for item in value) + "]"
    if isinstance(value, dict) and kind is dict:
        if any(type(key) is not str for key in value):
            raise ValueError("result mappings require string keys")
        return (
            "{"
            + ",".join(
                json.dumps(key) + ":" + _encode_json_value(value[key])
                for key in sorted(value)
            )
            + "}"
        )
    raise TypeError(f"result type is not supported:{kind.__name__}")


def _write_result(
    stream: Any,
    result: object,
    *,
    body_ns: int | None = None,
    timing_ns: Mapping[str, int] | None = None,
) -> None:
    serialization_started = time.perf_counter_ns() if body_ns is not None else 0
    result_json = _encode_json_value(result)
    serialization_ns = (
        time.perf_counter_ns() - serialization_started if body_ns is not None else None
    )
    telemetry = (
        '"evaluation_timing_ns":'
        + json.dumps(
            {
                "function_body": body_ns,
                "result_serialization": serialization_ns,
                **(timing_ns or {}),
            },
            sort_keys=True,
            separators=(",", ":"),
        )
        + ","
        if body_ns is not None
        else ""
    )
    encoded = "{" + telemetry + '"result":' + result_json + ',"status":"ok"}'
    if len(encoded) > _MAX_FRAME:
        raise ValueError("response frame exceeds limit")
    stream.write(encoded + "\n")
    stream.flush()


def _write(stream: Any, value: Mapping[str, Any]) -> None:
    encoded = json.dumps(value, sort_keys=True, separators=(",", ":"))
    if len(encoded) > _MAX_FRAME:
        raise ValueError("response frame exceeds limit")
    stream.write(encoded + "\n")
    stream.flush()


if __name__ == "__main__":
    raise SystemExit(main())
