"""Descriptor-based Landlock lowering for the phase-one Linux backend."""

from __future__ import annotations

import asyncio
import ctypes
import errno
import hashlib
import hmac
import json
import os
import posixpath
import secrets
import signal
import socket
import stat
import subprocess
import sys
import tempfile
import time
from collections import deque
from collections.abc import Mapping, Sequence
from dataclasses import dataclass
from pathlib import Path
from threading import RLock
from types import MappingProxyType, SimpleNamespace
from typing import Any

from langgraph.prebuilt.security.broker import (
    BrokerSession,
    CredentialBroker,
    SpawnRecord,
)
from langgraph.prebuilt.security.capabilities import (
    _current_cgroup_path,
    probe_landlock_abi,
    probe_linux_capabilities,
)
from langgraph.prebuilt.security.cedar import CedarPolicyBackend
from langgraph.prebuilt.security.cgroup import CgroupV2Scope
from langgraph.prebuilt.security.enforcement import (
    ActivationEvidence,
    ActivationReceipt,
    AuthorityDomain,
    EnforcementMode,
    GrantRule,
    RequirementEntry,
    RequirementLedger,
    RuleEnforcement,
    SupportLevel,
    compile_grant,
    compile_obligations,
)
from langgraph.prebuilt.security.execution import (
    HostExecutionDenied,
    HostExecutionError,
    HostExecutionResult,
)
from langgraph.prebuilt.security.lean_lifecycle import (
    LeanLifecycleChecker,
    LeanLifecycleSession,
    _capture_receipt_certificate,
    _data,
)
from langgraph.prebuilt.security.policy import MandatoryPolicyBackend
from langgraph.prebuilt.security.profile import ProfileDocument
from langgraph.prebuilt.security.types import (
    ExecutionOutcome,
    PolicyConstraint,
    Principal,
    ToolCall,
)

_CREATE_RULESET = 444
_ADD_RULE = 445
_PATH_BENEATH = 1
_NET_PORT = 2
_OPENAT2 = 437
_AT_FDCWD = -100
_RESOLVE_NO_MAGICLINKS = 0x02
_RESOLVE_NO_SYMLINKS = 0x04
_RESOLVE_BENEATH = 0x08

_EXECUTE = 1 << 0
_WRITE_FILE = 1 << 1
_READ_FILE = 1 << 2
_READ_DIR = 1 << 3
_REMOVE_DIR = 1 << 4
_REMOVE_FILE = 1 << 5
_MAKE_CHAR = 1 << 6
_MAKE_DIR = 1 << 7
_MAKE_REG = 1 << 8
_MAKE_SOCK = 1 << 9
_MAKE_FIFO = 1 << 10
_MAKE_BLOCK = 1 << 11
_MAKE_SYM = 1 << 12
_REFER = 1 << 13
_TRUNCATE = 1 << 14
_IOCTL_DEV = 1 << 15
_TCP_BIND = 1 << 0
_TCP_CONNECT = 1 << 1
_MAKE_ALL = (
    _MAKE_CHAR
    | _MAKE_DIR
    | _MAKE_REG
    | _MAKE_SOCK
    | _MAKE_FIFO
    | _MAKE_BLOCK
    | _MAKE_SYM
)
_DEFAULT_LIMITS = MappingProxyType(
    {
        "address_space_bytes": 1_073_741_824,
        "cpu_ms": 30_000,
        "file_size_bytes": 67_108_864,
        "nofile": 64,
        "pids": 1,
        "wall_ms": 30_000,
    }
)


class _RulesetAttr(ctypes.Structure):
    _fields_ = [
        ("handled_access_fs", ctypes.c_uint64),
        ("handled_access_net", ctypes.c_uint64),
        ("scoped", ctypes.c_uint64),
    ]


class _PathBeneathAttr(ctypes.Structure):
    _fields_ = [
        ("allowed_access", ctypes.c_uint64),
        ("parent_fd", ctypes.c_int32),
        ("reserved", ctypes.c_uint32),
    ]


class _NetPortAttr(ctypes.Structure):
    _fields_ = [("allowed_access", ctypes.c_uint64), ("port", ctypes.c_uint64)]


class _OpenHow(ctypes.Structure):
    _fields_ = [
        ("flags", ctypes.c_uint64),
        ("mode", ctypes.c_uint64),
        ("resolve", ctypes.c_uint64),
    ]


@dataclass(frozen=True, slots=True)
class RuleLowering:
    """One grant rule's conservative Landlock lowering verdict."""

    rule_id: str
    support: SupportLevel
    reason: str


@dataclass(frozen=True, slots=True)
class LandlockRuleset:
    """Parent-built ruleset descriptor plus per-rule lowering evidence."""

    fd: int
    abi: int
    lowering: tuple[RuleLowering, ...]

    def close(self) -> None:
        """Close the ruleset descriptor in its trusted owner."""
        os.close(self.fd)


@dataclass(slots=True)
class _PooledLandlockWorker:
    """Single-use confined worker waiting without an authorized broker."""

    pool_key: str
    process: subprocess.Popen[bytes]
    pidfd: int | None
    cgroup: CgroupV2Scope | None
    private_tmp: tempfile.TemporaryDirectory
    artifact_tmp: tempfile.TemporaryDirectory
    spec: Any
    parent_channel: socket.socket
    broker_fd: int
    created_at: float


@dataclass(slots=True)
class _LandlockWorkerPoolState:
    workers: dict[str, deque[_PooledLandlockWorker]]
    lock: RLock
    hits: int = 0
    misses: int = 0

    @classmethod
    def create(cls) -> _LandlockWorkerPoolState:
        return cls({}, RLock())


class LandlockSandboxExecutor:
    """Run one fresh namespace-free worker under Landlock, seccomp, and limits."""

    def __init__(
        self,
        profiles: ProfileDocument,
        tools: Mapping[str, Any],
        *,
        runtime_roots: Sequence[str | Path],
        principal_bindings: Mapping[str, Mapping[str, object]] | None = None,
        policy_backend: MandatoryPolicyBackend | None = None,
        python_executable: str | Path | None = None,
        startup_timeout_s: float = 5.0,
        default_wall_timeout_s: float = 30.0,
        default_limits: Mapping[str, int] | None = None,
        attestation_key: bytes | None = None,
        credential_broker: CredentialBroker | None = None,
        lifecycle_checker: LeanLifecycleChecker | None = None,
        worker_pool_capacity: int = 0,
        worker_pool_idle_s: float = 300.0,
        _worker_pool_state: _LandlockWorkerPoolState | None = None,
    ) -> None:
        from langgraph.prebuilt.security.linux import (
            _canonical_existing_path,
            _file_digest,
        )

        abi = probe_landlock_abi()
        if abi < 1:
            raise RuntimeError("Landlock ABI 1 or later is required")
        try:
            ctypes.CDLL("libseccomp.so.2")
        except OSError as exc:
            raise RuntimeError("libseccomp.so.2 is required") from exc
        python = Path(python_executable or sys.executable).resolve()
        if not python.is_file():
            raise ValueError("python_executable must resolve to a file")
        python_runtime_root = python.parent.parent
        roots = tuple(_canonical_existing_path(item) for item in runtime_roots)
        if not roots:
            raise ValueError("at least one runtime root is required")
        limits = dict(_DEFAULT_LIMITS if default_limits is None else default_limits)
        if set(limits) != set(_DEFAULT_LIMITS) or any(
            type(value) is not int or value <= 0 for value in limits.values()
        ):
            raise ValueError("Landlock default limits are invalid")
        if limits["cpu_ms"] % 1000 or limits["pids"] != 1:
            raise ValueError("cpu_ms must use seconds and pids must be one")
        copied_tools = dict(tools)
        if not copied_tools:
            raise ValueError("Landlock sandbox requires tool manifests")
        if set(copied_tools).difference(profiles.tools):
            raise ValueError("Landlock tool manifests lack profiles")
        if any(profiles.tools[name].runs != "linux" for name in copied_tools):
            raise ValueError("Landlock tool profiles must run on linux")
        if any(
            profiles.tools[name].syscall_sets != frozenset({"minimal"})
            for name in copied_tools
        ):
            raise ValueError("Landlock tool profiles require @minimal syscalls")
        self.profiles = profiles
        self.tools = MappingProxyType(copied_tools)
        self.runtime_roots = roots
        self.principal_bindings = MappingProxyType(
            {
                name: MappingProxyType(dict(values))
                for name, values in (principal_bindings or {}).items()
            }
        )
        self.policy_backend = policy_backend or CedarPolicyBackend()
        self.python_executable = python
        self.python_runtime_root = python_runtime_root
        self.worker_script = Path(__file__).with_name("_linux_worker.py").resolve()
        self.python_digest = _file_digest(python)
        self.worker_digest = _file_digest(self.worker_script)
        self.default_limits = MappingProxyType(limits)
        self.startup_timeout_s = startup_timeout_s
        self.default_wall_timeout_s = default_wall_timeout_s
        self.abi = abi
        self.capabilities = probe_linux_capabilities()
        self._cgroup_root = (
            _current_cgroup_path() if self.capabilities.cgroup_delegated else None
        )
        self._key = attestation_key or secrets.token_bytes(32)
        self.credential_broker = credential_broker
        if (
            lifecycle_checker is not None
            and type(lifecycle_checker) is not LeanLifecycleChecker
        ):
            raise HostExecutionDenied("host:lean_binary_configuration")
        self.lifecycle_checker = lifecycle_checker
        if (
            type(worker_pool_capacity) is not int
            or worker_pool_capacity < 0
            or worker_pool_idle_s <= 0
        ):
            raise ValueError("Landlock worker pool settings must be non-negative")
        self.worker_pool_capacity = worker_pool_capacity
        self.worker_pool_idle_s = float(worker_pool_idle_s)
        self._worker_pool_state = (
            _worker_pool_state or _LandlockWorkerPoolState.create()
        )
        self._prepared_pool_key: str | None = None
        self._receipts: deque[ActivationReceipt] = deque(maxlen=1024)
        self._lifecycle_records: deque[dict[str, Any]] = deque(maxlen=1024)
        self._lifecycle_lock = RLock()

    def validate_tools(self, tool_names: Sequence[str]) -> None:
        """Require one pinned manifest for every reachable tool."""
        missing = set(tool_names).difference(self.tools)
        if missing:
            raise ValueError(
                "Landlock execution missing manifests: " + ", ".join(sorted(missing))
            )

    def activation_receipts(self) -> tuple[ActivationReceipt, ...]:
        """Return the bounded activation receipt history."""
        return tuple(self._receipts)

    def lifecycle_records(self) -> tuple[dict[str, Any], ...]:
        """Return detached successful Lean route traces."""
        with self._lifecycle_lock:
            return tuple(
                json.loads(json.dumps(item)) for item in self._lifecycle_records
            )

    def worker_pool_stats(self) -> Mapping[str, int]:
        """Return prepared-worker occupancy and exact claim counters."""
        state = self._worker_pool_state
        with state.lock:
            return MappingProxyType(
                {
                    "capacity": self.worker_pool_capacity,
                    "idle": sum(len(items) for items in state.workers.values()),
                    "hits": state.hits,
                    "misses": state.misses,
                }
            )

    def prewarm(
        self,
        principal: Principal,
        call: ToolCall,
        constraints: Sequence[PolicyConstraint],
        *,
        count: int = 1,
        asynchronous: bool = False,
    ) -> int:
        """Prepare confined single-use workers without attaching authority."""
        if type(count) is not int or count < 0:
            raise ValueError("prewarm count must be a non-negative integer")
        if asynchronous:
            raise HostExecutionDenied("host:prepared_async_route_unavailable")
        if count and self.worker_pool_capacity == 0:
            raise HostExecutionDenied("host:worker_pool_disabled")
        prepared = 0
        for _ in range(min(count, self.worker_pool_capacity)):
            self._prewarm_one(principal, call, constraints)
            prepared += 1
        return prepared

    def close(self) -> None:
        """Terminate every unclaimed prepared worker."""
        state = self._worker_pool_state
        with state.lock:
            workers = [item for values in state.workers.values() for item in values]
            state.workers.clear()
        for worker in workers:
            self._close_pooled_worker(worker)

    def _pool_key(
        self,
        spec: Any,
        grant: Any,
        landlock_rules: Sequence[GrantRule],
        enforcement: Sequence[Any],
        extras: Mapping[str, Any],
    ) -> str:
        del grant
        return _digest(
            {
                "artifact": spec.artifact_digest,
                "entrypoint": spec.entrypoint,
                "extras": dict(extras),
                "landlock_rules": [dict(rule.canonical()) for rule in landlock_rules],
                "enforcement": [
                    (item.rule_id, item.support.value, item.mechanism)
                    for item in enforcement
                ],
                "runtime_roots": [os.fspath(item) for item in self.runtime_roots],
            }
        )

    def _claim_pooled_worker(self) -> _PooledLandlockWorker | None:
        key = self._prepared_pool_key
        if not self.worker_pool_capacity or key is None:
            return None
        state = self._worker_pool_state
        stale: list[_PooledLandlockWorker] = []
        with state.lock:
            cutoff = time.monotonic() - self.worker_pool_idle_s
            values = state.workers.get(key)
            while values:
                worker = values.popleft()
                if worker.created_at >= cutoff and worker.process.poll() is None:
                    state.hits += 1
                    if not values:
                        state.workers.pop(key, None)
                    return worker
                stale.append(worker)
            state.workers.pop(key, None)
            state.misses += 1
        for worker in stale:
            self._close_pooled_worker(worker)
        return None

    def _close_pooled_worker(self, worker: _PooledLandlockWorker) -> None:
        try:
            worker.parent_channel.close()
        except OSError:
            pass
        try:
            if worker.process.poll() is None:
                worker.process.kill()
            worker.process.wait(timeout=2)
        except (OSError, subprocess.SubprocessError):
            pass
        for stream in (
            worker.process.stdin,
            worker.process.stdout,
            worker.process.stderr,
        ):
            if stream is not None:
                try:
                    stream.close()
                except OSError:
                    pass
        if worker.pidfd is not None:
            try:
                os.close(worker.pidfd)
            except OSError:
                pass
        if worker.cgroup is not None:
            try:
                worker.cgroup.close()
            except Exception:
                pass
        worker.private_tmp.cleanup()
        worker.artifact_tmp.cleanup()

    def _prewarm_one(
        self,
        principal: Principal,
        call: ToolCall,
        constraints: Sequence[PolicyConstraint],
    ) -> None:
        """Lower an exact template and stop a confined worker at its bind barrier."""
        from langgraph.prebuilt.security.linux import (
            _encode_worker_request,
            _file_digest,
            _readline_json,
        )

        configured = self.tools.get(call.tool.name)
        if configured is None:
            raise HostExecutionDenied("host:tool_manifest_missing")
        private_tmp = tempfile.TemporaryDirectory(prefix="slanggraph-worker-")
        artifact_tmp = tempfile.TemporaryDirectory(prefix="slanggraph-artifact-")
        ruleset: LandlockRuleset | None = None
        process: subprocess.Popen[bytes] | None = None
        pidfd: int | None = None
        cgroup: CgroupV2Scope | None = None
        parent_channel: socket.socket | None = None
        worker_channel: socket.socket | None = None
        retained = False
        try:
            source = Path(configured.artifact_path).read_bytes()
            if hashlib.sha256(source).hexdigest() != configured.artifact_digest:
                raise HostExecutionDenied("host:artifact_changed")
            pinned = Path(artifact_tmp.name) / "tool.py"
            pinned.write_bytes(source)
            pinned.chmod(0o400)
            spec = SimpleNamespace(
                entrypoint=configured.entrypoint,
                artifact_path=pinned,
                artifact_digest=configured.artifact_digest,
            )
            if (
                _file_digest(self.python_executable) != self.python_digest
                or _file_digest(self.worker_script) != self.worker_digest
            ):
                raise HostExecutionDenied("host:runtime_changed")
            grant, ledger = self._compile_grant(
                principal, call, spec, Path(private_tmp.name)
            )
            filtered = self.policy_backend.filter(grant, ledger, constraints)
            if not filtered.allowed or filtered.grant is None:
                raise HostExecutionDenied(f"host:{filtered.reason}")
            grant = self._prepare_grant(filtered.grant, filtered.ledger)
            if self.lifecycle_checker is not None:
                record = getattr(self, "record", None)
                lean_ledger = filtered.ledger
                obligations = compile_obligations(grant)
                if record is not None:
                    lean_ledger = RequirementLedger(
                        tuple(
                            RequirementEntry(
                                rule.rule_id,
                                rule.requirement,
                                frozenset({rule.rule_id}),
                            )
                            for rule in grant.rules
                        )
                    )
                    obligations = record.obligations
                self._check_lean_grant(grant, lean_ledger, obligations)
            landlock_rules, enforcement = self._lower(grant)
            ruleset = build_ruleset(landlock_rules, abi=self.abi)
            limits = self._limits(grant)
            extras = self._worker_request_extras(grant)
            pool_key = self._pool_key(spec, grant, landlock_rules, enforcement, extras)
            parent_channel, worker_channel = socket.socketpair(
                socket.AF_UNIX, socket.SOCK_STREAM
            )
            parent_channel.set_inheritable(False)
            worker_channel.set_inheritable(False)
            broker_fd = worker_channel.fileno()
            request = {
                "args": {},
                "artifact_path": os.fspath(spec.artifact_path),
                "asynchronous": False,
                "broker_fd": broker_fd,
                "call_id": "",
                "entrypoint": spec.entrypoint,
                "landlock_ruleset_fd": ruleset.fd,
                "limits": limits,
                "pool_bootstrap": True,
                "pool_key": pool_key,
                "runtime_roots": [os.fspath(item) for item in self.runtime_roots],
                "tool_name": call.tool.name,
            }
            if set(request).intersection(extras):
                raise HostExecutionDenied("host:worker_protocol_extension_conflict")
            request.update(extras)
            environment = {
                "PATH": "/usr/bin",
                "PYTHONCOERCECLOCALE": "0",
                "PYTHONDONTWRITEBYTECODE": "1",
                "PYTHONNOUSERSITE": "1",
                "PYTHONSAFEPATH": "1",
                "PYTHONUNBUFFERED": "1",
                "PYTHONUTF8": "1",
                "SLANGGRAPH_BROKER_FD": str(broker_fd),
                "TMPDIR": private_tmp.name,
            }
            if self._cgroup_root is not None:
                cgroup = CgroupV2Scope.create(self._cgroup_root, limits)
            process = subprocess.Popen(
                (
                    os.fspath(self.python_executable),
                    "-I",
                    "-S",
                    "-B",
                    "-u",
                    "-X",
                    "utf8",
                    os.fspath(self.worker_script),
                ),
                stdin=subprocess.PIPE,
                stdout=subprocess.PIPE,
                stderr=subprocess.PIPE,
                close_fds=True,
                pass_fds=(ruleset.fd, broker_fd),
                cwd=private_tmp.name,
                env=environment,
            )
            if cgroup is not None:
                cgroup.assign(process.pid)
            try:
                pidfd = os.pidfd_open(process.pid)
            except (AttributeError, OSError):
                pidfd = None
            ruleset.close()
            ruleset = None
            worker_channel.close()
            worker_channel = None
            if process.stdin is None or process.stdout is None:
                raise HostExecutionDenied("host:worker_pipe_failed")
            process.stdin.write(_encode_worker_request(request))
            process.stdin.flush()
            if _readline_json(process, self.startup_timeout_s) != {
                "pool_key": pool_key,
                "status": "pooled",
            }:
                raise HostExecutionDenied("host:worker_pool_protocol")
            pooled = _PooledLandlockWorker(
                pool_key,
                process,
                pidfd,
                cgroup,
                private_tmp,
                artifact_tmp,
                spec,
                parent_channel,
                broker_fd,
                time.monotonic(),
            )
            state = self._worker_pool_state
            with state.lock:
                if (
                    sum(len(items) for items in state.workers.values())
                    >= self.worker_pool_capacity
                ):
                    raise HostExecutionDenied("host:worker_pool_full")
                state.workers.setdefault(pool_key, deque()).append(pooled)
            self._prepared_pool_key = pool_key
            retained = True
        finally:
            if not retained:
                if ruleset is not None:
                    try:
                        ruleset.close()
                    except OSError:
                        pass
                if worker_channel is not None:
                    worker_channel.close()
                if parent_channel is not None:
                    parent_channel.close()
                if process is not None:
                    try:
                        process.kill()
                        process.wait(timeout=2)
                    except (OSError, subprocess.SubprocessError):
                        pass
                if pidfd is not None:
                    try:
                        os.close(pidfd)
                    except OSError:
                        pass
                if cgroup is not None:
                    try:
                        cgroup.close()
                    except Exception:
                        pass
                private_tmp.cleanup()
                artifact_tmp.cleanup()

    def invoke(
        self,
        principal: Principal,
        call: ToolCall,
        constraints: Sequence[PolicyConstraint],
    ) -> HostExecutionResult:
        """Compile and run one synchronous confined tool call."""
        return self._invoke(principal, call, constraints, asynchronous=False)

    async def ainvoke(
        self,
        principal: Principal,
        call: ToolCall,
        constraints: Sequence[PolicyConstraint],
    ) -> HostExecutionResult:
        """Compile and run one asynchronous confined tool call."""
        execution = asyncio.create_task(
            asyncio.to_thread(
                self._invoke, principal, call, constraints, asynchronous=True
            )
        )
        try:
            return await asyncio.shield(execution)
        except asyncio.CancelledError:
            # Keep the real worker/broker cleanup inside _invoke alive, including
            # when cancellation is requested again while that cleanup is waiting.
            while not execution.done():
                try:
                    await asyncio.shield(execution)
                except asyncio.CancelledError:
                    continue
                except Exception:
                    break
            try:
                execution.result()
            except HostExecutionError as exc:
                if not exc.termination_confirmed:
                    raise
            except Exception:
                pass
            raise

    def _invoke(
        self,
        principal: Principal,
        call: ToolCall,
        constraints: Sequence[PolicyConstraint],
        *,
        asynchronous: bool,
    ) -> HostExecutionResult:
        from langgraph.prebuilt.security.linux import (
            _encode_worker_request,
            _file_digest,
            _json_value,
            _readline_json,
        )

        configured = self.tools.get(call.tool.name)
        if configured is None:
            raise HostExecutionDenied("host:tool_manifest_missing")
        pooled = self._claim_pooled_worker()
        if self.worker_pool_capacity and pooled is None:
            raise HostExecutionDenied("host:prepared_worker_unavailable")
        private_tmp = (
            pooled.private_tmp
            if pooled is not None
            else tempfile.TemporaryDirectory(prefix="slanggraph-worker-")
        )
        private_tmp_path = Path(private_tmp.name)
        artifact_tmp = (
            pooled.artifact_tmp
            if pooled is not None
            else tempfile.TemporaryDirectory(prefix="slanggraph-artifact-")
        )
        broker_session: BrokerSession | None = None
        worker_broker_fd: int | None = None
        ruleset: LandlockRuleset | None = None
        try:
            source = Path(configured.artifact_path).read_bytes()
            if hashlib.sha256(source).hexdigest() != configured.artifact_digest:
                raise HostExecutionDenied("host:artifact_changed")
            if pooled is None:
                # Execute a verified private snapshot, never the mutable source path.
                pinned = Path(artifact_tmp.name) / "tool.py"
                pinned.write_bytes(source)
                pinned.chmod(0o400)
                spec = SimpleNamespace(
                    entrypoint=configured.entrypoint,
                    artifact_path=pinned,
                    artifact_digest=configured.artifact_digest,
                )
            else:
                spec = pooled.spec
                if (
                    spec.entrypoint != configured.entrypoint
                    or spec.artifact_digest != configured.artifact_digest
                    or hashlib.sha256(Path(spec.artifact_path).read_bytes()).hexdigest()
                    != configured.artifact_digest
                ):
                    raise HostExecutionDenied("host:prepared_artifact_changed")
            if (
                _file_digest(self.python_executable) != self.python_digest
                or _file_digest(self.worker_script) != self.worker_digest
            ):
                raise HostExecutionDenied("host:runtime_changed")
            grant, ledger = self._compile_grant(principal, call, spec, private_tmp_path)
            filtered = self.policy_backend.filter(grant, ledger, constraints)
            if not filtered.allowed or filtered.grant is None:
                raise HostExecutionDenied(f"host:{filtered.reason}")
            grant = filtered.grant
            grant = self._prepare_grant(grant, filtered.ledger)
            if self.lifecycle_checker is not None:
                record = getattr(self, "record", None)
                lean_ledger = filtered.ledger
                lean_obligations = compile_obligations(grant)
                if record is not None:
                    lean_ledger = RequirementLedger(
                        tuple(
                            RequirementEntry(
                                rule.rule_id,
                                rule.requirement,
                                frozenset({rule.rule_id}),
                            )
                            for rule in grant.rules
                        )
                    )
                    lean_obligations = record.obligations
                self._check_lean_grant(
                    grant,
                    lean_ledger,
                    lean_obligations,
                )
            landlock_rules, enforcement = self._lower(grant)
            limits = self._limits(grant)
            extras = self._worker_request_extras(grant)
            pool_key = self._pool_key(spec, grant, landlock_rules, enforcement, extras)
            if pooled is not None:
                if pool_key != pooled.pool_key:
                    raise HostExecutionDenied("host:prepared_policy_changed")
            else:
                ruleset = build_ruleset(landlock_rules, abi=self.abi)
            if any(rule.domain is AuthorityDomain.SERVICE for rule in grant.rules):
                if self.credential_broker is None:
                    raise HostExecutionDenied("host:service_broker_unavailable")
                spawn = SpawnRecord(
                    principal.user_id,
                    call.tool.name,
                    grant.digest,
                    secrets.token_hex(16),
                )
                if pooled is None:
                    broker_session = self.credential_broker.open_session(spawn, grant)
                    worker_broker_fd = broker_session.detach_worker()
                else:
                    broker_session = self.credential_broker.bind_prepared_session(
                        pooled.parent_channel, spawn, grant
                    )
            request = {
                "args": _json_value({**call.args, **call.normalized}),
                "artifact_path": os.fspath(spec.artifact_path),
                "asynchronous": asynchronous,
                "call_id": call.call_id,
                "entrypoint": spec.entrypoint,
                "limits": limits,
                "plan_digest": self._worker_plan_digest(grant, enforcement),
                "runtime_roots": [os.fspath(item) for item in self.runtime_roots],
                "startup_challenge": secrets.token_hex(16),
                "tool_name": call.tool.name,
            }
            if ruleset is not None:
                request["landlock_ruleset_fd"] = ruleset.fd
            if pooled is not None:
                request["pool_key"] = pool_key
            if set(request).intersection(extras):
                raise HostExecutionDenied("host:worker_protocol_extension_conflict")
            request.update(extras)
            if worker_broker_fd is not None:
                request["broker_fd"] = worker_broker_fd
            elif pooled is not None:
                request["broker_fd"] = pooled.broker_fd
            encoded = _encode_worker_request(request)
        except BaseException:
            if pooled is not None and broker_session is None:
                try:
                    pooled.parent_channel.close()
                except OSError:
                    pass
            self._cleanup_worker(
                process=pooled.process if pooled is not None else None,
                ruleset=ruleset,
                worker_broker_fd=worker_broker_fd,
                pidfd=pooled.pidfd if pooled is not None else None,
                cgroup=pooled.cgroup if pooled is not None else None,
                broker_session=broker_session,
                private_tmp=private_tmp,
                artifact_tmp=artifact_tmp,
                receipt=None,
                active_error=sys.exc_info()[1],
            )
            raise

        environment = {
            "PATH": "/usr/bin",
            "PYTHONCOERCECLOCALE": "0",
            "PYTHONDONTWRITEBYTECODE": "1",
            "PYTHONNOUSERSITE": "1",
            "PYTHONSAFEPATH": "1",
            "PYTHONUNBUFFERED": "1",
            "PYTHONUTF8": "1",
            "TMPDIR": os.fspath(private_tmp_path),
        }
        if worker_broker_fd is not None:
            environment["SLANGGRAPH_BROKER_FD"] = str(worker_broker_fd)
        process: subprocess.Popen[bytes] | None = (
            pooled.process if pooled is not None else None
        )
        pidfd: int | None = pooled.pidfd if pooled is not None else None
        cgroup: CgroupV2Scope | None = pooled.cgroup if pooled is not None else None
        receipt: ActivationReceipt | None = None
        lifecycle: LeanLifecycleSession | None = None
        lifecycle_observed: dict[str, Any] | None = None
        result: HostExecutionResult | None = None
        released = False
        try:
            if pooled is None and self._cgroup_root is not None:
                try:
                    cgroup = CgroupV2Scope.create(self._cgroup_root, limits)
                except (OSError, ValueError) as exc:
                    raise HostExecutionDenied("host:cgroup_activation_failed") from exc
            if pooled is None:
                assert ruleset is not None
                passed_fds = (
                    (ruleset.fd, worker_broker_fd)
                    if worker_broker_fd is not None
                    else (ruleset.fd,)
                )
                process = subprocess.Popen(
                    (
                        os.fspath(self.python_executable),
                        "-I",
                        "-S",
                        "-B",
                        "-u",
                        "-X",
                        "utf8",
                        os.fspath(self.worker_script),
                    ),
                    stdin=subprocess.PIPE,
                    stdout=subprocess.PIPE,
                    stderr=subprocess.PIPE,
                    close_fds=True,
                    pass_fds=passed_fds,
                    cwd=private_tmp_path,
                    env=environment,
                )
                if worker_broker_fd is not None:
                    os.close(worker_broker_fd)
                    worker_broker_fd = None
                if cgroup is not None:
                    try:
                        cgroup.assign(process.pid)
                    except OSError as exc:
                        raise HostExecutionDenied(
                            "host:cgroup_assignment_failed"
                        ) from exc
                try:
                    pidfd = os.pidfd_open(process.pid)
                except (AttributeError, OSError):
                    pidfd = None
                ruleset.close()
                ruleset = None
            assert process is not None
            if process.stdin is None or process.stdout is None:
                raise HostExecutionDenied("host:worker_pipe_failed")
            process.stdin.write(encoded)
            process.stdin.flush()
            ready = _readline_json(process, self.startup_timeout_s)
            if ready != {
                "plan_digest": request["plan_digest"],
                "startup_challenge": request["startup_challenge"],
                "status": "ready",
            }:
                raise HostExecutionDenied("host:worker_startup_protocol")
            receipt = self._receipt(grant, process.pid, enforcement)
            self._receipts.append(receipt)
            if self.lifecycle_checker is not None:
                host = self.host_adapter.host
                context = self.host_adapter.context
                plan = self.record.plan
                if host is None or context is None:
                    raise HostExecutionDenied("host:lean_activation_evidence_missing")
                start_time = context.process_identity.rpartition(":")[2]
                expected = {
                    "principal": grant.principal_id,
                    "session": grant.session_id,
                    "call": grant.call_id,
                    "tool": grant.tool_name,
                    "artifact": grant.artifact_digest,
                    "intent": grant.normalized_intent_digest,
                    "policy": grant.policy_digest,
                    "deployment": grant.deployment_digest,
                    "runtime": grant.runtime_digest,
                    "grant": grant.digest,
                    "plan": plan.digest,
                    "nonce": receipt.nonce,
                    "host": host.digest,
                    "context": context.digest,
                    "worker": {
                        "pid": str(process.pid),
                        "startTime": start_time,
                        "bootId": context.boot_id,
                    },
                }
                lifecycle_observed = {
                    **expected,
                    "artifact": receipt.artifact_digest,
                    "grant": receipt.grant_digest,
                    "plan": receipt.plan_digest,
                    "host": receipt.host_digest,
                    "context": receipt.context_digest,
                }
                certificate = _capture_receipt_certificate(
                    plan,
                    receipt,
                    plan_digest=plan.digest,
                    grant=self._lean_grant,
                    obligations=self._lean_obligations,
                )
                lifecycle = LeanLifecycleSession(
                    self.lifecycle_checker,
                    expected,
                    certificate,
                    object_route=getattr(self, "_lean_object_route", False),
                )
                lifecycle.permit_go(
                    lifecycle_observed,
                    supported=not plan.waived_obligations,
                )
            process.stdin.write(b"GO\n")
            process.stdin.flush()
            released = True
            response = _readline_json(
                process, min(limits["wall_ms"] / 1000, self.default_wall_timeout_s)
            )
            return_code = process.wait(timeout=1)
            if response.get("status") == "ok" and return_code == 0:
                result = HostExecutionResult(response["result"], receipt)
            else:
                raise HostExecutionError(
                    f"sandboxed tool failed:{response.get('error_type', 'Exception')}",
                    receipt,
                    ExecutionOutcome.FAILED,
                )
        except TimeoutError as exc:
            if receipt is not None and released:
                raise HostExecutionError(
                    "tool_timeout", receipt, ExecutionOutcome.INDETERMINATE
                ) from exc
            raise HostExecutionDenied("host:worker_startup_timeout") from exc
        except (OSError, ValueError, subprocess.SubprocessError) as exc:
            if receipt is not None:
                raise HostExecutionError(
                    "sandboxed tool outcome is indeterminate",
                    receipt,
                    ExecutionOutcome.INDETERMINATE,
                ) from exc
            raise HostExecutionDenied("host:worker_activation_failed") from exc
        finally:
            self._cleanup_worker(
                process=process,
                ruleset=ruleset,
                worker_broker_fd=worker_broker_fd,
                pidfd=pidfd,
                cgroup=cgroup,
                broker_session=broker_session,
                private_tmp=private_tmp,
                artifact_tmp=artifact_tmp,
                receipt=receipt,
                active_error=sys.exc_info()[1],
            )
        if result is None:
            raise HostExecutionDenied("host:worker_result_missing")
        if lifecycle is not None:
            assert lifecycle_observed is not None
            try:
                lifecycle.permit_success(lifecycle_observed)
            except HostExecutionDenied as exc:
                raise HostExecutionError(
                    "host:lean_result_release_failed",
                    result.receipt,
                    ExecutionOutcome.INDETERMINATE,
                    termination_confirmed=True,
                ) from exc
            with self._lifecycle_lock:
                self._lifecycle_records.append(
                    {
                        "binding": _data(lifecycle._binding),
                        "certificate": _data(lifecycle._certificate),
                        "events": _data(lifecycle._events),
                        "object_route": getattr(self, "_lean_object_route", False),
                        "phase": "ready",
                        "cleanup_confirmed": True,
                        "checker_sha256": self.lifecycle_checker.binary_sha256,
                    }
                )
        return result

    def _check_lean_grant(self, grant, ledger, obligations) -> None:
        """Capture and admit the exact native grant before host effects."""
        from langgraph.prebuilt.security.lean_grant import (
            _capture_filtered_grant,
            _capture_obligations,
        )
        from langgraph.prebuilt.security.policy import PolicyFilterResult

        checker = self.lifecycle_checker
        if type(checker) is not LeanLifecycleChecker:
            raise HostExecutionDenied("host:lean_binary_configuration")
        captured = _capture_filtered_grant(
            PolicyFilterResult(grant, ledger, "allow:captured")
        )
        self._lean_grant = json.loads(captured.projection)
        self._lean_obligations = json.loads(
            _capture_obligations(obligations).projection
        )
        checker.require_grant(
            self._lean_grant,
            self._lean_obligations,
            object_route=getattr(self, "_lean_object_route", False),
        )

    def _cleanup_worker(
        self,
        *,
        process: subprocess.Popen[bytes] | None,
        ruleset: LandlockRuleset | None,
        worker_broker_fd: int | None,
        pidfd: int | None,
        cgroup: CgroupV2Scope | None,
        broker_session: BrokerSession | None,
        private_tmp: tempfile.TemporaryDirectory,
        artifact_tmp: tempfile.TemporaryDirectory,
        receipt: ActivationReceipt | None,
        active_error: BaseException | None,
    ) -> None:
        """Attempt every cleanup and retain uncertainty about live authority.

        Thread completion is not termination evidence. A stopped child, an empty
        owned cgroup when present, and a stopped broker are all required before
        marking termination confirmed. Without a cgroup the production worker's
        fixed minimal seccomp filter forbids all process/thread creation and
        executable replacement before releasing tool code. This lifetime rule
        does not cover the separate exec-enabled evaluation worker. Cleanup
        errors cannot publish success.
        """
        cleanup_failed = False
        if ruleset is not None:
            try:
                ruleset.close()
            except Exception:
                cleanup_failed = True
        if worker_broker_fd is not None:
            try:
                os.close(worker_broker_fd)
            except OSError:
                cleanup_failed = True
        worker_stopped = process is None
        if process is not None:
            try:
                worker_stopped = process.poll() is not None
            except Exception:
                worker_stopped = False
            if not worker_stopped:
                killed_cgroup = False
                if cgroup is not None:
                    try:
                        killed_cgroup = cgroup.kill()
                    except Exception:
                        pass
                signalled = killed_cgroup
                if not signalled and pidfd is not None:
                    try:
                        signal.pidfd_send_signal(pidfd, signal.SIGKILL)
                        signalled = True
                    except Exception:
                        pass
                if not signalled:
                    try:
                        process.kill()
                    except Exception:
                        cleanup_failed = True
                try:
                    process.wait(timeout=2)
                except Exception:
                    cleanup_failed = True
                try:
                    worker_stopped = process.poll() is not None
                except Exception:
                    worker_stopped = False
            for stream in (process.stdin, process.stdout, process.stderr):
                if stream is not None:
                    try:
                        stream.close()
                    except Exception:
                        cleanup_failed = True
        if pidfd is not None:
            try:
                os.close(pidfd)
            except OSError:
                cleanup_failed = True
        if cgroup is not None:
            try:
                cgroup.close()
            except Exception:
                cleanup_failed = True
                worker_stopped = False
        broker_stopped = broker_session is None
        if broker_session is not None:
            try:
                broker_session.close_parent()
            except Exception:
                cleanup_failed = True
            try:
                broker_stopped = broker_session.terminated
            except Exception:
                broker_stopped = False
        try:
            private_tmp.cleanup()
        except Exception:
            cleanup_failed = True
        try:
            artifact_tmp.cleanup()
        except Exception:
            cleanup_failed = True
        termination_confirmed = worker_stopped and broker_stopped
        if isinstance(active_error, HostExecutionError):
            active_error.termination_confirmed = termination_confirmed
            if cleanup_failed or not termination_confirmed:
                active_error.outcome = ExecutionOutcome.INDETERMINATE
            return
        if cleanup_failed or not termination_confirmed:
            if receipt is not None:
                reason = (
                    "host:broker_operation_still_running"
                    if worker_stopped and not broker_stopped and not cleanup_failed
                    else "host:worker_cleanup_unconfirmed"
                )
                raise HostExecutionError(
                    reason,
                    receipt,
                    ExecutionOutcome.INDETERMINATE,
                    termination_confirmed=termination_confirmed,
                ) from None
            raise HostExecutionDenied("host:worker_cleanup_unconfirmed") from None

    def _worker_request_extras(self, grant: Any) -> Mapping[str, Any]:
        """Return trusted worker protocol extensions for specialized subclasses."""
        return {}

    def _compile_grant(
        self, principal: Principal, call: ToolCall, spec: Any, private_tmp: Path
    ):
        profile = self.profiles.principals.get(principal.user_id)
        if (
            profile is None
            or profile.roles != principal.roles
            or profile.scopes != principal.scopes
        ):
            raise HostExecutionDenied("host:principal_profile_mismatch")
        bindings = {**dict(call.args), **dict(call.normalized)}
        try:
            evaluation = self.profiles.evaluate(
                call.tool.name,
                principal.user_id,
                bindings,
                principal_bindings=self.principal_bindings,
            )
        except (KeyError, TypeError, ValueError) as exc:
            raise HostExecutionDenied("host:profile_evaluation_failed") from exc
        if evaluation.denied:
            raise HostExecutionDenied(f"host:dac:{evaluation.reason or 'deny'}")
        compiled = compile_grant(
            evaluation,
            principal_id=principal.user_id,
            session_id=principal.session_id,
            artifact_digest=spec.artifact_digest,
            call_id=call.call_id,
            normalized_intent_digest=_digest(
                {
                    "args": call.args,
                    "normalized": call.normalized,
                    "tool": call.tool.name,
                }
            ),
            policy_digest=_digest({"stage": "pre-mac"}),
            baseline_rules=self._baseline_rules(
                spec,
                private_tmp,
                enable_broker=bool(evaluation.grant.services),
            ),
        )
        return compiled.grant, compiled.ledger

    def _prepare_grant(self, grant: Any, ledger: Any) -> Any:
        """Allow composed backends to negotiate and attenuate before lowering."""
        return grant

    def _worker_plan_digest(self, grant: Any, enforcement: Any) -> str:
        return _digest(
            {
                "grant": grant.digest,
                "enforcement": [
                    (item.rule_id, item.support.value, item.mechanism)
                    for item in enforcement
                ],
            }
        )

    def _baseline_rules(
        self, spec: Any, private_tmp: Path, *, enable_broker: bool
    ) -> tuple[GrantRule, ...]:
        paths = [
            ("runtime:usr", "read", "/usr", True),
            ("runtime:tmp:read", "read", os.fspath(private_tmp), True),
            ("runtime:tmp:write", "write", os.fspath(private_tmp), True),
            ("runtime:tmp:create", "create", os.fspath(private_tmp), True),
            ("runtime:tmp:delete", "delete", os.fspath(private_tmp), True),
            ("runtime:tmp:truncate", "truncate", os.fspath(private_tmp), True),
            ("runtime:urandom", "read", "/dev/urandom", False),
            ("runtime:worker", "read", os.fspath(self.worker_script), False),
            ("runtime:artifact", "read", os.fspath(spec.artifact_path), False),
            ("runtime:interpreter", "read", os.fspath(self.python_executable), False),
            (
                "runtime:interpreter-root",
                "read",
                os.fspath(self.python_runtime_root),
                True,
            ),
        ]
        paths.extend(
            (f"runtime:root:{index}", "read", os.fspath(root), root.is_dir())
            for index, root in enumerate(self.runtime_roots)
        )
        rules = [
            GrantRule(
                rule_id,
                AuthorityDomain.RUNTIME,
                operation,
                selector,
                {"subtree": subtree},
                baseline=True,
            )
            for rule_id, operation, selector, subtree in paths
        ]
        for rule_id, operation, selector in (
            ("runtime:env:path", "environment", "PATH"),
            ("runtime:env:no-bytecode", "environment", "PYTHONDONTWRITEBYTECODE"),
            ("runtime:env:no-user-site", "environment", "PYTHONNOUSERSITE"),
            ("runtime:env:tmpdir", "environment", "TMPDIR"),
            ("runtime:protocol:request", "read", "parent-request-pipe"),
            ("runtime:protocol:response", "write", "parent-response-pipe"),
            ("runtime:protocol:diagnostic", "write", "parent-diagnostic-pipe"),
        ):
            domain = (
                AuthorityDomain.RUNTIME
                if operation == "environment"
                else AuthorityDomain.IPC
            )
            rules.append(
                GrantRule(
                    rule_id,
                    domain,
                    operation,
                    selector,
                    baseline=True,
                )
            )
        if enable_broker and self.credential_broker is not None:
            rules.extend(
                (
                    GrantRule(
                        "runtime:protocol:broker-read",
                        AuthorityDomain.IPC,
                        "read",
                        "broker-channel",
                        baseline=True,
                    ),
                    GrantRule(
                        "runtime:protocol:broker-write",
                        AuthorityDomain.IPC,
                        "write",
                        "broker-channel",
                        baseline=True,
                    ),
                )
            )
        for name, value in self.default_limits.items():
            rules.append(
                GrantRule(
                    f"runtime:limit:{name}",
                    AuthorityDomain.RESOURCE_LIMIT,
                    "limit",
                    name,
                    {"maximum": value},
                    baseline=True,
                )
            )
        return tuple(rules)

    def _lower(
        self, grant: Any
    ) -> tuple[tuple[GrantRule, ...], tuple[RuleEnforcement, ...]]:
        landlock: list[GrantRule] = []
        results: list[RuleEnforcement] = []
        for rule in grant.rules:
            support, mechanism = self._assess_rule(rule)
            if support is SupportLevel.UNSUPPORTED:
                raise HostExecutionDenied(f"host:unsupported_rule:{rule.rule_id}")
            results.append(RuleEnforcement(rule.rule_id, support, mechanism))
            if mechanism.startswith("landlock"):
                landlock.append(rule)
        return tuple(landlock), tuple(results)

    def _assess_rule(self, rule: GrantRule) -> tuple[SupportLevel, str]:
        if rule.domain in {
            AuthorityDomain.FILESYSTEM,
            AuthorityDomain.RUNTIME,
        } and rule.operation in {"read", "write", "create", "delete", "truncate"}:
            if rule.operation == "truncate" and self.abi < 3:
                return SupportLevel.UNSUPPORTED, "landlock:truncate"
            return SupportLevel.EXACT, "landlock:path"
        if rule.domain is AuthorityDomain.NETWORK:
            if self.abi < 4:
                return SupportLevel.UNSUPPORTED, "landlock:network"
            return SupportLevel.TIGHTENED, "landlock:port+seccomp:no-network"
        if rule.domain is AuthorityDomain.PROCESS and rule.operation == "exec":
            return SupportLevel.TIGHTENED, "landlock:execute+seccomp:no-exec"
        if (
            rule.domain is AuthorityDomain.PROCESS
            and rule.operation == "syscall_set"
            and rule.selector == "minimal"
        ):
            return SupportLevel.EXACT, "seccomp:minimal"
        if rule.domain is AuthorityDomain.RUNTIME and rule.operation == "environment":
            return SupportLevel.EXACT, "worker:clearenv"
        if rule.domain is AuthorityDomain.SERVICE:
            if self.credential_broker is None:
                return SupportLevel.UNSUPPORTED, "broker:unavailable"
            return SupportLevel.EXACT, "broker:socketpair+exact-scope"
        if rule.domain is AuthorityDomain.IPC and rule.selector in {
            "parent-request-pipe",
            "parent-response-pipe",
            "parent-diagnostic-pipe",
            "broker-channel",
        }:
            return SupportLevel.EXACT, "worker:protocol-fd"
        if rule.domain is AuthorityDomain.RESOURCE_LIMIT:
            if rule.selector == "aggregate_cpu_ms":
                return (
                    SupportLevel.UNSUPPORTED,
                    "aggregate_cpu_budget_not_enforced_by_cpu_max_or_rlimit",
                )
            if rule.selector == "cpu_ms":
                maximum = rule.conditions.get("maximum")
                if type(maximum) is not int or maximum <= 0 or maximum % 1000:
                    return (
                        SupportLevel.UNSUPPORTED,
                        "rlimit_cpu_requires_positive_whole_seconds",
                    )
            if rule.selector == "nofile":
                return SupportLevel.EXACT, "rlimit:nofile"
            if rule.selector == "wall_ms":
                if self._cgroup_root is not None and self.capabilities.cgroup_kill:
                    return SupportLevel.TIGHTENED, "supervisor:timer+cgroup.kill"
                return SupportLevel.TIGHTENED, "supervisor:timer+pidfd-kill"
            if rule.selector in {
                "cpu_ms",
                "memory_bytes",
                "address_space_bytes",
                "file_size_bytes",
                "pids",
            }:
                if self._cgroup_root is not None and rule.selector in {
                    "cpu_ms",
                    "memory_bytes",
                    "address_space_bytes",
                    "pids",
                }:
                    return (
                        SupportLevel.TIGHTENED,
                        f"cgroup:v2+rlimit:{rule.selector}",
                    )
                return SupportLevel.TIGHTENED, f"rlimit:{rule.selector}"
        return SupportLevel.UNSUPPORTED, "unsupported"

    def _limits(self, grant: Any) -> dict[str, int]:
        limits = dict(self.default_limits)
        aliases = {"memory_bytes": "address_space_bytes"}
        for rule in grant.rules:
            if rule.domain is not AuthorityDomain.RESOURCE_LIMIT:
                continue
            maximum = rule.conditions.get("maximum")
            if type(maximum) is not int:
                raise HostExecutionDenied("host:invalid_limit")
            name = aliases.get(rule.selector, rule.selector)
            prior = limits.get(name)
            limits[name] = maximum if prior is None else min(prior, maximum)
        return limits

    def _receipt(
        self,
        grant: Any,
        pid: int,
        enforcement: tuple[RuleEnforcement, ...],
    ) -> ActivationReceipt:
        now = time.time()
        nonce = secrets.token_hex(16)
        obligations = frozenset(
            item.obligation_id for item in compile_obligations(grant)
        )
        plan_digest = _digest(
            {
                "grant": grant.digest,
                "enforcement": [
                    (item.rule_id, item.support.value, item.mechanism)
                    for item in enforcement
                ],
            }
        )
        context_digest = _digest({"pid": pid, "boot": _boot_id()})
        signature = hmac.new(
            self._key,
            f"{plan_digest}:{context_digest}:{nonce}".encode(),
            hashlib.sha256,
        ).hexdigest()
        evidence = ActivationEvidence(
            "linux-landlock-v1",
            plan_digest,
            context_digest,
            nonce,
            obligations,
            now,
            now + 60,
            signature,
        )
        return ActivationReceipt(
            grant.digest,
            plan_digest,
            _digest({"boot": _boot_id(), "landlock_abi": self.abi}),
            context_digest,
            nonce,
            EnforcementMode.ENFORCED,
            (evidence,),
            obligations,
            now + 60,
            enforcement,
        )


def build_ruleset(
    rules: Sequence[GrantRule], *, abi: int | None = None
) -> LandlockRuleset:
    """Build a complete Landlock ruleset from trusted-parent descriptors."""
    effective_abi = probe_landlock_abi() if abi is None else abi
    if effective_abi < 1:
        raise OSError(errno.ENOSYS, "Landlock ABI is unavailable")
    handled_fs = _handled_fs(effective_abi)
    handled_net = _TCP_BIND | _TCP_CONNECT if effective_abi >= 4 else 0
    attributes = _RulesetAttr(handled_fs, handled_net, 0)
    libc = ctypes.CDLL(None, use_errno=True)
    ctypes.set_errno(0)
    ruleset_fd = int(
        libc.syscall(
            _CREATE_RULESET,
            ctypes.byref(attributes),
            ctypes.sizeof(attributes),
            0,
        )
    )
    if ruleset_fd < 0:
        raise OSError(ctypes.get_errno(), "landlock_create_ruleset failed")
    lowering: list[RuleLowering] = []
    try:
        for rule in rules:
            try:
                lowering.append(_add_rule(libc, ruleset_fd, rule, effective_abi))
            except OSError as exc:
                raise OSError(
                    exc.errno, f"Landlock rule failed:{rule.rule_id}:{exc.strerror}"
                ) from exc
            if lowering[-1].support is SupportLevel.UNSUPPORTED:
                raise ValueError(
                    f"unsupported Landlock rule:{rule.rule_id}:{lowering[-1].reason}"
                )
    except BaseException:
        os.close(ruleset_fd)
        raise
    os.set_inheritable(ruleset_fd, True)
    return LandlockRuleset(ruleset_fd, effective_abi, tuple(lowering))


def open_path_descriptor(path: str, *, no_symlinks: bool = False) -> int:
    """Resolve one absolute path beneath `/` without magic-link traversal."""
    if not path.startswith("/") or posixpath.normpath(path) != path:
        raise ValueError("Landlock paths must be canonical and absolute")
    flags = getattr(os, "O_PATH", 0) | os.O_CLOEXEC
    root_fd = os.open("/", flags)
    try:
        if path == "/":
            return os.dup(root_fd)
        relative = path.lstrip("/").encode()
        resolve = _RESOLVE_BENEATH | _RESOLVE_NO_MAGICLINKS
        if no_symlinks:
            resolve |= _RESOLVE_NO_SYMLINKS
        how = _OpenHow(flags, 0, resolve)
        libc = ctypes.CDLL(None, use_errno=True)
        ctypes.set_errno(0)
        descriptor = int(
            libc.syscall(
                _OPENAT2,
                root_fd,
                ctypes.c_char_p(relative),
                ctypes.byref(how),
                ctypes.sizeof(how),
            )
        )
        if descriptor < 0:
            raise OSError(ctypes.get_errno(), f"openat2 failed:{path}")
        return descriptor
    finally:
        os.close(root_fd)


def _add_rule(
    libc: ctypes.CDLL, ruleset_fd: int, rule: GrantRule, abi: int
) -> RuleLowering:
    if rule.domain in {
        AuthorityDomain.FILESYSTEM,
        AuthorityDomain.RUNTIME,
    } and rule.operation in {
        "read",
        "write",
        "create",
        "delete",
        "truncate",
    }:
        access = _path_access(rule.operation, abi)
        if access == 0:
            return RuleLowering(
                rule.rule_id, SupportLevel.UNSUPPORTED, "ABI lacks access right"
            )
        descriptor = open_path_descriptor(
            rule.selector, no_symlinks=bool(rule.conditions.get("exact_file"))
        )
        try:
            mode = os.fstat(descriptor).st_mode
            if rule.conditions.get("exact_file") and not stat.S_ISREG(mode):
                return RuleLowering(
                    rule.rule_id,
                    SupportLevel.UNSUPPORTED,
                    "exact file authority cannot expose a directory subtree",
                )
            permitted_urandom = (
                stat.S_ISCHR(mode)
                and rule.domain is AuthorityDomain.RUNTIME
                and rule.operation == "read"
                and rule.selector == "/dev/urandom"
            )
            if not (stat.S_ISREG(mode) or stat.S_ISDIR(mode) or permitted_urandom):
                return RuleLowering(
                    rule.rule_id, SupportLevel.UNSUPPORTED, "special file"
                )
            if stat.S_ISREG(mode) and rule.operation == "read":
                access = _READ_FILE
            elif permitted_urandom:
                if abi < 5:
                    return RuleLowering(
                        rule.rule_id,
                        SupportLevel.UNSUPPORTED,
                        "device baseline requires ABI 5",
                    )
                access = _READ_FILE | _IOCTL_DEV
            if rule.operation in {"create", "delete"} and not stat.S_ISDIR(mode):
                return RuleLowering(
                    rule.rule_id,
                    SupportLevel.UNSUPPORTED,
                    "mutation requires directory",
                )
            attribute = _PathBeneathAttr(access, descriptor, 0)
            _syscall_ok(
                libc, _ADD_RULE, ruleset_fd, _PATH_BENEATH, ctypes.byref(attribute), 0
            )
        finally:
            os.close(descriptor)
        return RuleLowering(rule.rule_id, SupportLevel.EXACT, "Landlock path-beneath")
    if rule.domain is AuthorityDomain.PROCESS and rule.operation == "exec":
        descriptor = open_path_descriptor(rule.selector)
        try:
            attribute = _PathBeneathAttr(_EXECUTE, descriptor, 0)
            _syscall_ok(
                libc, _ADD_RULE, ruleset_fd, _PATH_BENEATH, ctypes.byref(attribute), 0
            )
        finally:
            os.close(descriptor)
        return RuleLowering(rule.rule_id, SupportLevel.EXACT, "Landlock EXECUTE")
    if rule.domain is AuthorityDomain.NETWORK and rule.operation in {"bind", "connect"}:
        if abi < 4:
            return RuleLowering(
                rule.rule_id, SupportLevel.UNSUPPORTED, "network requires ABI 4"
            )
        try:
            port = int(rule.selector)
        except ValueError:
            return RuleLowering(
                rule.rule_id, SupportLevel.UNSUPPORTED, "port is not numeric"
            )
        access = _TCP_BIND if rule.operation == "bind" else _TCP_CONNECT
        attribute = _NetPortAttr(access, port)
        _syscall_ok(libc, _ADD_RULE, ruleset_fd, _NET_PORT, ctypes.byref(attribute), 0)
        return RuleLowering(rule.rule_id, SupportLevel.EXACT, "Landlock TCP port")
    return RuleLowering(
        rule.rule_id, SupportLevel.UNSUPPORTED, "rule belongs to another enforcer"
    )


def _handled_fs(abi: int) -> int:
    access = (
        _EXECUTE
        | _WRITE_FILE
        | _READ_FILE
        | _READ_DIR
        | _REMOVE_DIR
        | _REMOVE_FILE
        | _MAKE_ALL
    )
    if abi >= 2:
        access |= _REFER
    if abi >= 3:
        access |= _TRUNCATE
    if abi >= 5:
        access |= _IOCTL_DEV
    return access


def _path_access(operation: str, abi: int) -> int:
    if operation == "read":
        return _READ_FILE | _READ_DIR
    if operation == "write":
        return _WRITE_FILE
    if operation == "create":
        return _MAKE_ALL | (_REFER if abi >= 2 else 0)
    if operation == "delete":
        return _REMOVE_FILE | _REMOVE_DIR
    if operation == "truncate":
        return _TRUNCATE if abi >= 3 else 0
    return 0


def _syscall_ok(libc: ctypes.CDLL, number: int, *arguments: object) -> None:
    ctypes.set_errno(0)
    if libc.syscall(number, *arguments) != 0:
        raise OSError(ctypes.get_errno(), f"Landlock syscall {number} failed")


def _digest(value: object) -> str:
    encoded = json.dumps(
        value, sort_keys=True, default=repr, separators=(",", ":")
    ).encode()
    return hashlib.sha256(encoded).hexdigest()


def _boot_id() -> str:
    try:
        return Path("/proc/sys/kernel/random/boot_id").read_text().strip()
    except OSError:
        return "unavailable"
