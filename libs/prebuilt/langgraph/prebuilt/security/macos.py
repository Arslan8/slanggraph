"""Read-only macOS host execution using a fresh Seatbelt worker per call.

Seatbelt is a path policy, not a syscall filter or mount namespace. Unsupported
obligations are denied; in particular this adapter never advertises @minimal.
"""

from __future__ import annotations

import asyncio
import base64
import ctypes
import hashlib
import hmac
import json
import math
import os
import platform
import re
import secrets
import selectors
import subprocess
import sys
import time
from collections import deque
from collections.abc import Mapping, Sequence
from dataclasses import dataclass, replace
from pathlib import Path
from threading import RLock
from types import MappingProxyType
from typing import Any

from langgraph.prebuilt.security.enforcement import (
    ActivationEvidence,
    ActivationReceipt,
    AdapterPlan,
    AuthorityDomain,
    EnforcementCoordinator,
    EnforcementObligation,
    ExecutionContext,
    Grant,
    GrantRule,
    HostAttestation,
    ObligationKind,
    SupportAssessment,
    SupportLevel,
    compile_grant,
    compile_obligations,
)
from langgraph.prebuilt.security.execution import (
    HostExecutionDenied,
    HostExecutionError,
    HostExecutionResult,
    TerminationRecovery,
)
from langgraph.prebuilt.security.macos_native import (
    MacOSNativeLauncher,
    MacOSWorkerProcess,
)
from langgraph.prebuilt.security.policy import (
    MandatoryPolicyBackend,
    TypedPolicyBackend,
)
from langgraph.prebuilt.security.profile import ProfileDocument
from langgraph.prebuilt.security.types import (
    ExecutionOutcome,
    PolicyConstraint,
    Principal,
    ToolCall,
)

_ADAPTER_ID = "macos-seatbelt-v1"
_MAX_FRAME = 1_048_576
_LIMITS = {"cpu_ms": 10_000, "nofile": 64, "wall_ms": 30_000}
_RUNTIME_SYSCTLS = (
    "hw.ncpu",
    "hw.logicalcpu",
    "hw.activecpu",
    "hw.physicalcpu",
    "hw.memsize",
    "hw.machine",
    "kern.ostype",
    "kern.osrelease",
    "kern.version",
    "kern.hostname",
)


@dataclass(frozen=True, slots=True)
class MacOSToolSpec:
    """Operator-pinned Python source and plain callable entrypoint."""

    entrypoint: str
    artifact_path: Path
    artifact_digest: str

    def __post_init__(self) -> None:
        module, separator, attribute = self.entrypoint.partition(":")
        if not separator or any(
            not part.isidentifier()
            for part in (*module.split("."), *attribute.split("."))
        ):
            raise ValueError("macOS entrypoint must be module:attribute")
        path = Path(self.artifact_path).resolve(strict=True)
        if not path.is_file() or _file_digest(path) != self.artifact_digest:
            raise ValueError("macOS artifact digest does not match file")
        object.__setattr__(self, "artifact_path", path)


class MacOSSandboxExecutor:
    """Compile grants and release tools only after native sandbox activation.

    Requires an unsandboxed trusted controller and a trusted CPython runtime.
    Runtime roots are explicit read authority and are visible to mandatory policy.
    No mutable filesystem, service, network, credential, or delegation authority
    is supported. Async cancellation waits for worker termination.
    """

    authorizes_dac = True

    def __init__(
        self,
        profiles: ProfileDocument,
        tools: Mapping[str, MacOSToolSpec],
        *,
        launcher: MacOSNativeLauncher,
        experimental: bool = False,
        recovery_directory: Path,
        runtime_roots: Sequence[str | Path] = (),
        principal_bindings: Mapping[str, Mapping[str, object]] | None = None,
        policy_backend: MandatoryPolicyBackend | None = None,
        startup_timeout_s: float = 5.0,
        default_limits: Mapping[str, int] | None = None,
        executable_roots: Sequence[str | Path] = (),
        lifecycle_checker: Any = None,
        runtime_aliases: Mapping[str, str] | None = None,
        runtime_libraries: Sequence[Mapping[str, str]] = (),
    ) -> None:
        if experimental is not True:
            raise HostExecutionDenied("macos:experimental_route_disabled")
        if platform.system() != "Darwin":
            raise RuntimeError("MacOSSandboxExecutor requires macOS")
        if not math.isfinite(startup_timeout_s) or startup_timeout_s <= 0:
            raise ValueError("startup timeout must be finite and positive")
        limits = dict(_LIMITS if default_limits is None else default_limits)
        if (
            set(limits) != set(_LIMITS)
            or any(type(value) is not int or value <= 0 for value in limits.values())
            or limits["cpu_ms"] % 1000
            or limits["nofile"] < 16
        ):
            raise ValueError(
                "provide positive cpu_ms (whole seconds), nofile >= 16, and wall_ms"
            )
        copied = dict(tools)
        if not copied or set(copied).difference(profiles.tools):
            raise ValueError("macOS tools require matching profiles")
        if any(profiles.tools[name].runs != "macos" for name in copied):
            raise ValueError("macOS profiles must declare 'runs macos'")
        launcher.verify()
        self.launcher = launcher
        self.recovery_directory = recovery_directory.resolve()
        self.recovery_directory.mkdir(parents=True, exist_ok=True, mode=0o700)
        self.profiles = profiles
        self.tools = MappingProxyType(copied)
        self.runtime_roots = tuple(
            Path(root).resolve(strict=True) for root in runtime_roots
        )
        self.executable_roots = tuple(
            Path(root).resolve(strict=True) for root in executable_roots
        )
        self.lifecycle_checker = lifecycle_checker
        self.runtime_aliases = MappingProxyType(dict(runtime_aliases or {}))
        self.runtime_libraries = tuple(
            MappingProxyType(dict(item)) for item in runtime_libraries
        )
        for item in self.runtime_libraries:
            if (
                set(item) != {"path", "sha256"}
                or _file_digest(Path(item["path"])) != item["sha256"]
            ):
                raise ValueError("runtime library changed or invalid")
        self._broker_handler = None
        self._broker_nonce = "no-broker"
        if any(not root.is_dir() for root in self.runtime_roots):
            raise ValueError("runtime roots must be directories")
        self.principal_bindings = MappingProxyType(
            {
                name: MappingProxyType(dict(values))
                for name, values in (principal_bindings or {}).items()
            }
        )
        self.policy_backend = policy_backend or TypedPolicyBackend()
        self.startup_timeout_s = startup_timeout_s
        self.default_limits = MappingProxyType(limits)
        self._python = launcher.library
        self._worker = Path(__file__).with_name("_macos_worker.py").resolve(strict=True)
        self._python_digest = _file_digest(self._python)
        self._worker_digest = _file_digest(self._worker)
        self._key = secrets.token_bytes(32)
        self._boot = _boot_id()
        self._lock = RLock()
        self._receipts: deque[ActivationReceipt] = deque(maxlen=1024)
        self._lifecycle_records: deque[dict[str, Any]] = deque(maxlen=1024)
        self._unresolved: dict[str, TerminationRecovery] = {}
        for record in self.recovery_directory.glob("*.json"):
            if record.is_symlink() or not re.fullmatch(
                r"[0-9a-f]{32}\.json", record.name
            ):
                raise ValueError("invalid macOS recovery record")
            value = json.loads(record.read_text())
            if (
                set(value) != {"recovery_id", "pid", "start_time", "boot_id"}
                or value["recovery_id"] != record.stem
                or type(value["pid"]) is not int
                or value["pid"] <= 0
                or any(
                    type(value[key]) is not str or not value[key]
                    for key in ("start_time", "boot_id")
                )
            ):
                raise ValueError("invalid macOS recovery identity")
            recovery = TerminationRecovery(**value)
            self._unresolved[recovery.recovery_id] = recovery
        self._adapter = _MacOSSeatbeltAdapter(
            self._key,
            self._boot,
            limits["wall_ms"] / 1000 + startup_timeout_s + 5,
            evidence={
                "launcher_digest": launcher.digest,
                "libpython_digest": launcher.library_digest,
                "shim_digest": self._worker_digest,
                "os_build": _sysctl_text("kern.osversion"),
                "runtime_libraries": _digest(
                    [dict(item) for item in self.runtime_libraries]
                ),
            },
        )
        self._coordinator = EnforcementCoordinator(
            [self._adapter], host_verifier=self._adapter
        )
        # Test real kernel activation in a disposable trusted shim. Never apply a
        # profile to the controller, and never accept a mocked capability claim.
        self._preflight()

    def validate_tools(self, tool_names: Sequence[str]) -> None:
        """Require a manifest for every reachable tool."""
        missing = set(tool_names).difference(self.tools)
        if missing:
            raise ValueError(
                "macOS execution missing manifests: " + ", ".join(sorted(missing))
            )

    def activation_receipts(self) -> tuple[ActivationReceipt, ...]:
        """Return the most recent 1,024 receipts; use durable audit for retention."""
        with self._lock:
            return tuple(self._receipts)

    def unresolved_terminations(self) -> tuple[TerminationRecovery, ...]:
        with self._lock:
            return tuple(self._unresolved.values())

    def lifecycle_records(self) -> tuple[dict[str, Any], ...]:
        with self._lock:
            return tuple(
                json.loads(json.dumps(item)) for item in self._lifecycle_records
            )

    def confirm_termination(self, recovery: TerminationRecovery) -> bool:
        """Confirm absence of a retained PID/start-time identity without PID reuse kills."""
        with self._lock:
            if self._unresolved.get(recovery.recovery_id) != recovery:
                return False
        try:
            confirmed = (
                recovery.boot_id != _boot_id()
                or _process_identity(recovery.pid) != recovery.start_time
            )
        except OSError:
            return False
        if confirmed:
            with self._lock:
                self._unresolved.pop(recovery.recovery_id, None)
            self._clear_recovery(recovery)
        return confirmed

    def _retain_recovery(self, recovery: TerminationRecovery) -> None:
        payload = {
            "recovery_id": recovery.recovery_id,
            "pid": recovery.pid,
            "start_time": recovery.start_time,
            "boot_id": recovery.boot_id,
        }
        path = self.recovery_directory / (recovery.recovery_id + ".json")
        descriptor = os.open(
            path, os.O_WRONLY | os.O_CREAT | os.O_EXCL | os.O_NOFOLLOW, 0o600
        )
        with os.fdopen(descriptor, "w") as output:
            output.write(json.dumps(payload, sort_keys=True) + "\n")
            output.flush()
            os.fsync(output.fileno())
        self._sync_recovery_directory()
        with self._lock:
            self._unresolved[recovery.recovery_id] = recovery

    def _sync_recovery_directory(self) -> None:
        descriptor = os.open(self.recovery_directory, os.O_RDONLY | os.O_DIRECTORY)
        try:
            os.fsync(descriptor)
        finally:
            os.close(descriptor)

    def _clear_recovery(self, recovery: TerminationRecovery) -> None:
        (self.recovery_directory / (recovery.recovery_id + ".json")).unlink(
            missing_ok=True
        )
        self._sync_recovery_directory()
        with self._lock:
            self._unresolved.pop(recovery.recovery_id, None)

    def assess_grant(self, grant: Grant) -> tuple[SupportAssessment, ...]:
        """Generate the obligation census from this lowerer without executing tools."""
        host = self._adapter.attest(secrets.token_hex(16))
        return tuple(
            self._adapter.assess(item, host) for item in compile_obligations(grant)
        )

    def invoke(
        self,
        principal: Principal,
        call: ToolCall,
        constraints: Sequence[PolicyConstraint],
    ) -> HostExecutionResult:
        return self._invoke(principal, call, constraints, asynchronous=False)

    async def ainvoke(
        self,
        principal: Principal,
        call: ToolCall,
        constraints: Sequence[PolicyConstraint],
    ) -> HostExecutionResult:
        execution = asyncio.create_task(
            asyncio.to_thread(
                self._invoke, principal, call, constraints, asynchronous=True
            )
        )
        try:
            return await asyncio.shield(execution)
        except asyncio.CancelledError:
            # Further cancellation requests must not release caller-owned flow
            # reservations while the supervisor is still waiting for cleanup.
            while True:
                try:
                    await asyncio.shield(execution)
                    break
                except asyncio.CancelledError:
                    continue
                except HostExecutionError as exc:
                    if not exc.termination_confirmed:
                        raise
                    break
                except Exception:
                    break
            raise

    def _runtime_paths(self) -> tuple[tuple[str, bool], ...]:
        return tuple(
            (str(path.resolve()), True)
            for path in (
                self.launcher.library.parent,
                self.launcher.stdlib,
                Path("/System/Library"),
                Path("/usr/lib"),
                *self.executable_roots,
            )
        )

    def _baseline(self) -> tuple[GrantRule, ...]:
        # No broad home, /tmp, Keychain or /usr baseline. Frameworks and Python
        # files are explicit, read-only runtime authority, never startup roots.
        paths = {Path(path) for path, _ in self._runtime_paths()} | set(
            self.runtime_roots
        )
        paths.update(
            Path(path).resolve()
            for path in ("/System/Library", "/usr/lib")
            if Path(path).exists()
        )
        rules = [
            GrantRule(
                f"runtime:read:{index}",
                AuthorityDomain.RUNTIME,
                "read",
                str(path),
                {"subtree": True},
                baseline=True,
            )
            for index, path in enumerate(sorted(paths))
        ]
        for index, (path, subtree) in enumerate(self._runtime_paths()):
            rules.append(
                GrantRule(
                    f"runtime:map:{index}",
                    AuthorityDomain.RUNTIME,
                    "map_executable",
                    path,
                    {"subtree": subtree},
                    baseline=True,
                )
            )
        for name in (
            "task-self",
            "thread-self",
            "host-self",
            "bootstrap",
            "task-inspect-self",
            "task-name-self",
            "task-read-self",
            "worker-local",
            "system-clock",
            "calendar-clock",
            "clock-semaphore",
        ):
            rules.append(
                GrantRule(
                    f"runtime:mach:{name}",
                    AuthorityDomain.IPC,
                    "retain",
                    name,
                    baseline=True,
                )
            )
        for index, name in enumerate(
            ("parent-request-pipe", "parent-response-pipe", "parent-diagnostic-pipe")
        ):
            rules.append(
                GrantRule(
                    f"runtime:pipe:{index}",
                    AuthorityDomain.IPC,
                    "read" if index == 0 else "write",
                    name,
                    baseline=True,
                )
            )
        rules.append(
            GrantRule(
                "runtime:devnull",
                AuthorityDomain.RUNTIME,
                "read",
                "/dev/null",
                {"subtree": False},
                baseline=True,
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
        rules.extend(
            GrantRule(
                f"runtime:sysctl:{name}",
                AuthorityDomain.RUNTIME,
                "inspect_system",
                name,
                baseline=True,
            )
            for name in _RUNTIME_SYSCTLS
        )
        rules.extend(
            GrantRule(
                f"runtime:alias:{index}",
                AuthorityDomain.RUNTIME,
                "dyld_alias",
                alias,
                {"target": target, "subtree": True},
                baseline=True,
            )
            for index, (alias, target) in enumerate(
                sorted(self.runtime_aliases.items())
            )
        )
        return tuple(rules)

    def _invoke(
        self,
        principal: Principal,
        call: ToolCall,
        constraints: Sequence[PolicyConstraint],
        *,
        asynchronous: bool,
    ) -> HostExecutionResult:
        spec = self.tools.get(call.tool.name)
        if spec is None:
            raise HostExecutionDenied("macos:tool_manifest_missing")
        self._validate_principal_profile(principal)
        try:
            # Capture JSON input once so policy compilation, intent identity and
            # the released worker cannot observe different nested arguments.
            captured = json.loads(
                json.dumps(
                    {"args": dict(call.args), "normalized": dict(call.normalized)},
                    allow_nan=False,
                )
            )
            _validate_json(captured)
            call = replace(
                call, args=captured["args"], normalized=captured["normalized"]
            )
            source = spec.artifact_path.read_bytes()
            if hashlib.sha256(source).hexdigest() != spec.artifact_digest:
                raise HostExecutionDenied("macos:artifact_changed")
            compiled = self._compile_grant(principal, call, spec)
            filtered = self.policy_backend.filter(
                compiled.grant, compiled.ledger, constraints
            )
            if self.lifecycle_checker is not None:
                from langgraph.prebuilt.security.lean_grant import (
                    _capture_filtered_grant,
                )

                captured = _capture_filtered_grant(filtered)
                filtered = captured.filtered
                self._lean_grant = json.loads(captured.projection)
            if not filtered.allowed or filtered.grant is None:
                raise HostExecutionDenied(f"macos:{filtered.reason}")
            grant, host, plan = self._prepare_execution(filtered.grant, filtered.ledger)
            native = next(
                item
                for item in plan.adapter_plans
                if item.adapter_id == self._adapter.adapter_id
            )
            request = self._request(
                dict(native.payload["limits"]),
                str(native.payload["profile"]),
                plan.digest,
                source,
                spec,
                dict(call.args),
                asynchronous,
            )
        except HostExecutionDenied:
            raise
        except (OSError, KeyError, TypeError, ValueError, RecursionError) as exc:
            raise HostExecutionDenied("macos:grant_compilation_failed") from exc
        return self._run(request, grant, host, plan)

    def _validate_principal_profile(self, principal):
        profile = self.profiles.principals.get(principal.user_id)
        if (
            profile is None
            or profile.roles != principal.roles
            or profile.scopes != principal.scopes
        ):
            raise HostExecutionDenied("macos:principal_profile_mismatch")

    def _compile_grant(self, principal, call, spec):
        evaluation = self.profiles.evaluate(
            call.tool.name,
            principal.user_id,
            {**call.args, **call.normalized},
            principal_bindings=self.principal_bindings,
        )
        if evaluation.denied:
            raise HostExecutionDenied(f"macos:dac:{evaluation.reason}")
        compiled = compile_grant(
            evaluation,
            principal_id=principal.user_id,
            session_id=principal.session_id,
            artifact_digest=spec.artifact_digest,
            call_id=call.call_id,
            normalized_intent_digest=_digest(
                {"args": dict(call.args), "normalized": dict(call.normalized)}
            ),
            policy_digest=_digest({"stage": "pre-mac"}),
            baseline_rules=self._baseline(),
        )
        return compiled

    def _prepare_execution(self, grant, ledger):
        challenge = secrets.token_hex(16)
        host = self._adapter.attest(challenge)
        obligations = compile_obligations(grant)
        if self.lifecycle_checker is not None:
            self._check_lean_grant(grant, ledger, obligations)
        self._execution_obligations = obligations
        negotiation = self._coordinator.negotiate(
            grant,
            ledger,
            obligations,
            host,
            expected_nonce=challenge,
        )
        if not negotiation.allowed or negotiation.plan is None:
            raise HostExecutionDenied(f"macos:{negotiation.reason}")
        return grant, host, negotiation.plan

    def _check_lean_grant(self, grant, ledger, obligations):
        from langgraph.prebuilt.security.lean_grant import (
            _capture_filtered_grant,
            _capture_obligations,
        )
        from langgraph.prebuilt.security.policy import PolicyFilterResult

        captured = _capture_filtered_grant(
            PolicyFilterResult(grant, ledger, "allow:captured")
        )
        self._lean_grant = json.loads(captured.projection)
        self._lean_obligations = json.loads(
            _capture_obligations(obligations).projection
        )
        self.lifecycle_checker.require_grant(
            self._lean_grant,
            self._lean_obligations,
            object_route=getattr(self, "_lean_object_route", False),
        )

    def _request(
        self,
        limits: dict[str, Any],
        profile: str,
        digest: str,
        source: bytes,
        spec: MacOSToolSpec | None,
        args: dict[str, Any],
        asynchronous: bool,
    ) -> dict[str, Any]:
        return {
            "limits": limits,
            "profile": profile,
            "plan_digest": digest,
            "challenge": secrets.token_hex(16),
            "source": base64.b64encode(source).decode(),
            "artifact_digest": hashlib.sha256(source).hexdigest(),
            "artifact_path": str(spec.artifact_path) if spec else "<probe>",
            "entrypoint": spec.entrypoint if spec else "probe:run",
            "args": args,
            "asynchronous": asynchronous,
            "runtime_roots": [str(root) for root in self.runtime_roots],
            "probe": spec is None,
            "broker": self._broker_handler is not None,
            "runtime_libraries": [dict(item) for item in self.runtime_libraries],
        }

    def _spawn(self, request: Mapping[str, Any]) -> MacOSWorkerProcess:
        if (
            _file_digest(self._python) != self._python_digest
            or _file_digest(self._worker) != self._worker_digest
        ):
            raise HostExecutionDenied("macos:trusted_runtime_changed")
        encoded = (
            json.dumps(request, separators=(",", ":"), allow_nan=False).encode() + b"\n"
        )
        if len(encoded) > _MAX_FRAME:
            raise HostExecutionDenied("macos:request_too_large")
        process = MacOSWorkerProcess(
            self.launcher,
            request["profile"],
            self._worker.read_bytes(),
            dict(request["limits"]),
            self.startup_timeout_s,
        )
        try:
            spawned = _read_frame(process.guardian, self.startup_timeout_s)
            if (
                set(spawned) != {"status", "pid"}
                or spawned["status"] != "spawned"
                or type(spawned["pid"]) is not int
            ):
                raise HostExecutionDenied("macos:guardian_startup_protocol")
            process.pid = spawned["pid"]
            _write_all(process.stdin, encoded)
            return process
        except BaseException:
            _reap(process)
            raise

    def _arm(self, process: MacOSWorkerProcess) -> None:
        if process.guardian.stdin is None:
            raise HostExecutionDenied("macos:guardian_unavailable")
        _write_all(process.guardian.stdin, b"ARM\n")
        if _read_frame(process.guardian, self.startup_timeout_s) != {"status": "armed"}:
            raise HostExecutionDenied("macos:guardian_not_armed")

    def _ready(
        self, process: subprocess.Popen[bytes], request: Mapping[str, Any]
    ) -> str:
        identity = _process_identity(process.pid)
        if identity is None:
            raise HostExecutionDenied("macos:worker_identity_missing")
        ready = _read_frame(process, self.startup_timeout_s)
        ports = ready.pop("startup_ports", None)
        if (
            type(ports) is not list
            or len(ports) > 64
            or any(
                type(port) is not dict
                or set(port) != {"name", "rights", "kind"}
                or type(port["name"]) is not int
                or type(port["rights"]) is not int
                or port["kind"]
                not in {
                    "task-self",
                    "thread-self",
                    "host-self",
                    "bootstrap",
                    "task-inspect-self",
                    "task-name-self",
                    "task-read-self",
                    "worker-local",
                    "system-clock",
                    "calendar-clock",
                    "clock-semaphore",
                    "dead-name",
                    "removed",
                }
                for port in ports
            )
        ):
            raise HostExecutionDenied(f"macos:startup_authority_unclassified:{ports!r}")
        process.startup_ports = ports
        expected = {
            "status": "ready",
            "challenge": request["challenge"],
            "plan_digest": request["plan_digest"],
            "limits": {name: request["limits"][name] for name in ("cpu_ms", "nofile")},
            "isolated": True,
            "site_loaded": False,
            **(
                {"runtime_libraries": request["runtime_libraries"]}
                if request.get("runtime_libraries")
                else {}
            ),
        }
        if ready != expected:
            raise HostExecutionDenied("macos:worker_startup_protocol")
        library = sandbox_library()
        if library.sandbox_check(process.pid, None, 0) != 1:
            raise HostExecutionDenied("macos:worker_not_sandboxed")
        if _process_identity(process.pid) != identity:
            raise HostExecutionDenied("macos:worker_identity_changed")
        return identity

    def _preflight(self) -> None:
        profile = (
            _seatbelt_profile(self._runtime_paths())
            + "\n"
            + "\n".join(
                _runtime_map(path, subtree) for path, subtree in self._runtime_paths()
            )
        )
        profile += "\n" + "\n".join(
            f"(allow sysctl-read (sysctl-name {json.dumps(name)}))"
            for name in _RUNTIME_SYSCTLS
        )
        request = self._request(
            dict(self.default_limits), profile, _digest(profile), b"", None, {}, False
        )
        process = self._spawn(request)
        try:
            self._ready(process, request)
            assert process.stdin is not None
            self._arm(process)
            _write_all(process.stdin, b"GO\n")
            if _read_frame(process, self.startup_timeout_s) != {
                "status": "ok",
                "result": True,
            } or not _await_exit(process, self.startup_timeout_s):
                raise RuntimeError("macOS Seatbelt preflight failed")
        except (OSError, ValueError, TimeoutError, subprocess.SubprocessError) as exc:
            raise RuntimeError("macOS Seatbelt is unavailable or unusable") from exc
        finally:
            _reap(process)

    def _run(
        self, request: Mapping[str, Any], grant: Grant, host: HostAttestation, plan: Any
    ) -> HostExecutionResult:
        process = self._spawn(request)
        receipt: ActivationReceipt | None = None
        identity: str | None = None
        error: BaseException | None = None
        recovery: TerminationRecovery | None = None
        lifecycle = None
        observed = None
        try:
            identity = self._ready(process, request)
            context = ExecutionContext(
                f"macos-worker:{process.pid}:{identity}",
                f"{process.pid}:{identity}",
                self._boot,
                {
                    "seatbelt": str(request["plan_digest"]),
                    "startup_authority": _digest(process.startup_ports),
                },
                _digest({"uid": os.getuid(), "gid": os.getgid()}),
                "not-applicable",
                self._broker_nonce,
            )
            native = next(
                item
                for item in plan.adapter_plans
                if item.adapter_id == self._adapter.adapter_id
            )
            self._adapter.register(native, context)
            receipt = self._coordinator.activate(
                grant, plan, host, context, nonce=secrets.token_hex(16)
            )
            if not self._coordinator.validate_receipt(
                receipt, grant, plan, host, context
            ):
                raise HostExecutionDenied("macos:activation_receipt_invalid")
            with self._lock:
                self._receipts.append(receipt)
            recovery = TerminationRecovery(
                secrets.token_hex(16), process.pid, identity, self._boot
            )
            self._retain_recovery(recovery)
            assert process.stdin is not None
            self._arm(process)
            if self.lifecycle_checker is not None:
                from langgraph.prebuilt.security.lean_lifecycle import (
                    LeanLifecycleSession,
                    _capture_receipt_certificate,
                )

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
                        "startTime": identity,
                        "bootId": host.boot_id,
                    },
                }
                observed = {
                    **expected,
                    "grant": receipt.grant_digest,
                    "plan": receipt.plan_digest,
                    "artifact": receipt.artifact_digest,
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
                lifecycle.permit_go(observed, supported=not plan.waived_obligations)
            _write_all(process.stdin, b"GO\n")
            deadline = time.monotonic() + request["limits"]["wall_ms"] / 1000
            while True:
                response = _read_frame(process, max(0, deadline - time.monotonic()))
                if response.get("status") != "broker":
                    break
                if self._broker_handler is None or set(response) != {
                    "status",
                    "request",
                }:
                    raise ValueError("unexpected broker request")
                answer = self._broker_handler(response["request"])
                try:
                    encoded = json.dumps(answer, allow_nan=False).encode()
                    if len(encoded) + 1 > _MAX_FRAME:
                        raise ValueError("broker response too large")
                except (TypeError, ValueError, RecursionError):
                    encoded = b'{"status":"denied","error":"broker:invalid_response"}'
                _write_all(process.stdin, encoded + b"\n")
            if response.get("status") != "ok" or "result" not in response:
                raise HostExecutionError(
                    "macos:tool_failed",
                    receipt,
                    ExecutionOutcome.FAILED,
                )
            return HostExecutionResult(response["result"], receipt)
        except BaseException as exc:
            error = exc
            if isinstance(
                exc,
                (
                    HostExecutionError,
                    HostExecutionDenied,
                    KeyboardInterrupt,
                    SystemExit,
                ),
            ):
                raise
            if receipt is not None:
                error = HostExecutionError(
                    "macos:tool_outcome_indeterminate",
                    receipt,
                    ExecutionOutcome.INDETERMINATE,
                )
                raise error from exc
            raise HostExecutionDenied("macos:worker_activation_failed") from exc
        finally:
            confirmed = _reap(process)
            if isinstance(error, HostExecutionError):
                error.termination_confirmed = confirmed
            if confirmed and recovery is not None:
                self._clear_recovery(recovery)
            if confirmed and error is None and lifecycle is not None:
                try:
                    lifecycle.permit_success(observed)
                    with self._lock:
                        self._lifecycle_records.append(
                            {
                                "binding": json.loads(lifecycle._binding),
                                "certificate": json.loads(lifecycle._certificate),
                                "events": json.loads(lifecycle._events),
                                "object_route": getattr(
                                    self, "_lean_object_route", False
                                ),
                                "phase": "ready",
                                "cleanup_confirmed": True,
                                "checker_sha256": self.lifecycle_checker.binary_sha256,
                            }
                        )
                except HostExecutionDenied as exc:
                    raise HostExecutionError(
                        "host:lean_result_release_failed",
                        receipt,
                        ExecutionOutcome.INDETERMINATE,
                        termination_confirmed=True,
                    ) from exc
            if not confirmed:
                recovery = recovery or TerminationRecovery(
                    secrets.token_hex(16),
                    process.pid,
                    identity or "unknown",
                    self._boot,
                )
                if recovery.recovery_id not in self._unresolved:
                    self._retain_recovery(recovery)
                if receipt is not None:
                    raise HostExecutionError(
                        "macos:termination_unconfirmed",
                        receipt,
                        ExecutionOutcome.INDETERMINATE,
                        recovery=recovery,
                    )
                raise HostExecutionDenied("macos:activation_termination_unconfirmed")


class _MacOSSeatbeltAdapter:
    adapter_id = _ADAPTER_ID

    def __init__(
        self,
        key: bytes,
        boot: str,
        lease: float,
        *,
        evidence: Mapping[str, str] | None = None,
    ) -> None:
        self._key, self._boot, self._lease = key, boot, lease
        self._evidence = dict(evidence or {})
        self._pending: dict[str, str] = {}
        self._lock = RLock()

    def _sign(self, material: str) -> str:
        return hmac.new(self._key, material.encode(), hashlib.sha256).hexdigest()

    def attest(self, nonce: str) -> HostAttestation:
        now = time.time()
        host = HostAttestation(
            "slanggraph-local-macos",
            nonce,
            self._boot,
            "macos",
            now,
            now + self._lease,
            frozenset({"seatbelt", "read-only", "rlimit"}),
            {},
            {
                "kernel": platform.release(),
                "adapter": self.adapter_id,
                **self._evidence,
            },
            "pending",
        )
        return replace(host, signature=self._sign(host.digest))

    def verify(self, host: HostAttestation) -> bool:
        return (
            host.platform == "macos"
            and host.boot_id == self._boot
            and hmac.compare_digest(host.signature, self._sign(host.digest))
        )

    def assess(
        self, obligation: EnforcementObligation, host: HostAttestation
    ) -> SupportAssessment:
        support, reason = SupportLevel.UNSUPPORTED, "macos:unsupported_obligation"
        if not self.verify(host):
            return SupportAssessment(
                self.adapter_id,
                obligation.obligation_id,
                support,
                "macos:untrusted_host",
            )
        if (
            obligation.kind is ObligationKind.DENY_COMPLEMENT
            and obligation.operation == "deny_unlisted"
            and obligation.selector == "*"
            and not obligation.conditions
        ):
            support, reason = (
                SupportLevel.EXACT,
                "seatbelt+native:closed-startup-authority",
            )
        elif (
            obligation.kind is ObligationKind.OPERATE
            and obligation.domain is AuthorityDomain.RUNTIME
            and obligation.operation == "dyld_alias"
            and set(obligation.conditions) == {"target", "subtree"}
            and obligation.conditions["subtree"] is True
        ):
            alias = Path(obligation.selector)
            try:
                if (
                    alias.is_absolute()
                    and alias.is_dir()
                    and str(alias.resolve(strict=True))
                    == obligation.conditions["target"]
                ):
                    support, reason = SupportLevel.EXACT, "dyld:pinned-runtime-alias"
            except OSError:
                pass
        elif (
            obligation.kind is ObligationKind.OPERATE
            and obligation.domain is AuthorityDomain.RUNTIME
            and obligation.operation == "inspect_system"
            and obligation.selector in _RUNTIME_SYSCTLS
            and not obligation.conditions
        ):
            support, reason = SupportLevel.EXACT, "seatbelt:runtime-sysctl"
        elif (
            obligation.kind is ObligationKind.OPERATE
            and obligation.domain
            in {AuthorityDomain.FILESYSTEM, AuthorityDomain.RUNTIME}
            and (
                obligation.operation == "read"
                or (
                    obligation.domain is AuthorityDomain.RUNTIME
                    and obligation.operation == "map_executable"
                )
            )
            and set(obligation.conditions) == {"subtree"}
            and type(obligation.conditions["subtree"]) is bool
        ):
            try:
                path = Path(obligation.selector)
                canonical = path.resolve(strict=True)
                if (
                    str(canonical) == obligation.selector
                    and (
                        canonical.is_file()
                        or canonical.is_dir()
                        or str(canonical) == "/dev/null"
                    )
                    and (not obligation.conditions["subtree"] or canonical.is_dir())
                ):
                    support, reason = SupportLevel.EXACT, "seatbelt:file-read"
            except (OSError, ValueError):
                pass
        elif (
            obligation.kind is ObligationKind.OPERATE
            and obligation.domain is AuthorityDomain.IPC
            and obligation.operation == "retain"
            and obligation.selector
            in {
                "task-self",
                "thread-self",
                "host-self",
                "bootstrap",
                "task-inspect-self",
                "task-name-self",
                "task-read-self",
                "worker-local",
                "system-clock",
                "calendar-clock",
                "clock-semaphore",
            }
            and not obligation.conditions
        ):
            support, reason = SupportLevel.EXACT, "native:startup-port-inventory"
        elif (
            obligation.kind is ObligationKind.OPERATE
            and obligation.domain is AuthorityDomain.IPC
            and not obligation.conditions
            and (obligation.operation, obligation.selector)
            in {
                ("read", "parent-request-pipe"),
                ("write", "parent-response-pipe"),
                ("write", "parent-diagnostic-pipe"),
            }
        ):
            support, reason = SupportLevel.EXACT, "spawn:closed-descriptors"
        elif (
            obligation.kind is ObligationKind.RESOURCE_LIMIT
            and obligation.domain is AuthorityDomain.RESOURCE_LIMIT
            and obligation.operation == "limit"
            and set(obligation.conditions) == {"maximum"}
        ):
            value = obligation.conditions["maximum"]
            if (
                type(value) is int
                and value > 0
                and obligation.selector in _LIMITS
                and (obligation.selector != "cpu_ms" or value % 1000 == 0)
                and (obligation.selector != "nofile" or value >= 16)
            ):
                support, reason = (
                    SupportLevel.EXACT,
                    "supervisor:wall"
                    if obligation.selector == "wall_ms"
                    else "rlimit:hard",
                )
        return SupportAssessment(
            self.adapter_id, obligation.obligation_id, support, reason
        )

    def lower(
        self,
        grant: Grant,
        obligations: Sequence[EnforcementObligation],
        host: HostAttestation,
    ) -> AdapterPlan:
        del grant
        if any(
            self.assess(item, host).support is SupportLevel.UNSUPPORTED
            for item in obligations
        ):
            raise ValueError("unsupported macOS obligation")
        paths = [
            (item.selector, item.conditions["subtree"])
            for item in obligations
            if item.kind is ObligationKind.OPERATE
            and item.domain in {AuthorityDomain.FILESYSTEM, AuthorityDomain.RUNTIME}
            and item.operation in {"read", "map_executable"}
        ]
        limits: dict[str, int] = {}
        for item in obligations:
            if item.kind is ObligationKind.RESOURCE_LIMIT:
                limits[item.selector] = min(
                    limits.get(item.selector, item.conditions["maximum"]),
                    item.conditions["maximum"],
                )
        payload = {
            "profile": _seatbelt_profile(paths)
            + "\n"
            + "\n".join(
                _runtime_map(item.selector, item.conditions["subtree"])
                for item in obligations
                if item.kind is ObligationKind.OPERATE
                and item.domain is AuthorityDomain.RUNTIME
                and item.operation == "map_executable"
            ),
            "limits": limits,
        }
        # An object route may omit a CPU-budget promise (qualification deferred).
        # Keep installing a conservative hard rlimit without certifying that it
        # establishes an aggregate CPU ceiling on Darwin.
        payload["limits"].setdefault("cpu_ms", _LIMITS["cpu_ms"])
        payload["profile"] += "\n" + "\n".join(
            f"(allow sysctl-read (sysctl-name {json.dumps(item.selector)}))"
            for item in obligations
            if item.operation == "inspect_system"
            and item.domain is AuthorityDomain.RUNTIME
        )
        for item in obligations:
            if (
                item.operation != "dyld_alias"
                or item.domain is not AuthorityDomain.RUNTIME
            ):
                continue
            target = item.conditions["target"]
            if not all(
                any(
                    candidate.domain is AuthorityDomain.RUNTIME
                    and candidate.operation == operation
                    and candidate.selector == target
                    and candidate.conditions.get("subtree") is True
                    for candidate in obligations
                )
                for operation in ("read", "map_executable")
            ):
                raise ValueError(
                    "runtime alias target lacks explicit read/map authority"
                )
            payload["profile"] += (
                "\n" + _seatbelt_profile(((item.selector, True),)).splitlines()[-1]
            )
            payload["profile"] += "\n" + _runtime_map(item.selector, True)
        return AdapterPlan(
            self.adapter_id,
            frozenset(item.obligation_id for item in obligations),
            _digest(payload),
            payload,
        )

    def register(self, plan: AdapterPlan, context: ExecutionContext) -> None:
        with self._lock:
            self._pending[context.digest] = plan.native_plan_digest

    def activate(
        self, plan: AdapterPlan, context: ExecutionContext, nonce: str
    ) -> ActivationEvidence:
        with self._lock:
            if self._pending.pop(context.digest, None) != plan.native_plan_digest:
                raise ValueError("macOS worker was not verified for this plan")
        now = time.time()
        evidence = ActivationEvidence(
            self.adapter_id,
            plan.native_plan_digest,
            context.digest,
            nonce,
            plan.obligation_ids,
            now,
            now + self._lease,
            "pending",
        )
        return replace(evidence, signature=self._sign(_evidence_payload(evidence)))

    def verify_activation(self, evidence: ActivationEvidence) -> bool:
        return evidence.adapter_id == self.adapter_id and hmac.compare_digest(
            evidence.signature, self._sign(_evidence_payload(evidence))
        )


def _seatbelt_profile(paths: Sequence[tuple[str, bool]]) -> str:
    lines = ["(version 1)", "(deny default)"]
    for path, subtree in sorted(set(paths)):
        # SBPL strings use backslash escapes; reject controls rather than rely
        # on JSON's additional Unicode escapes being understood by Seatbelt.
        if any(ord(character) < 32 or ord(character) == 127 for character in path):
            raise ValueError("control characters are not supported in selectors")
        quoted = '"' + path.replace("\\", "\\\\").replace('"', '\\"') + '"'
        lines.append(
            f"(allow file-read-data file-read-metadata ({'subpath' if subtree else 'literal'} {quoted}))"
        )
    return "\n".join(lines)


def _runtime_map(path: str, subtree: bool) -> str:
    rule = _seatbelt_profile(((path, subtree),)).splitlines()[-1]
    return rule.replace("file-read-data file-read-metadata", "file-map-executable")


def _read_frame(process: subprocess.Popen[bytes], timeout: float) -> dict[str, Any]:
    assert process.stdout is not None
    deadline = time.monotonic() + timeout
    data = bytearray()
    with selectors.DefaultSelector() as selector:
        selector.register(process.stdout, selectors.EVENT_READ)
        while True:
            remaining = deadline - time.monotonic()
            if remaining <= 0 or not selector.select(remaining):
                raise TimeoutError("worker frame timeout")
            chunk = os.read(
                process.stdout.fileno(), min(65536, _MAX_FRAME + 1 - len(data))
            )
            if not chunk:
                raise ValueError("worker protocol closed")
            data.extend(chunk)
            if len(data) > _MAX_FRAME:
                raise ValueError("worker frame too large")
            if b"\n" in chunk:
                if not data.endswith(b"\n") or data.count(b"\n") != 1:
                    raise ValueError("invalid worker frame")
                value = json.loads(
                    data,
                    object_pairs_hook=_unique_pairs,
                    parse_constant=_invalid_constant,
                )
                _validate_json(value)
                if not isinstance(value, dict):
                    raise ValueError("worker frame must be an object")
                return value


def _invalid_constant(value: str) -> Any:
    raise ValueError("non-finite JSON value")


def _unique_pairs(pairs: list[tuple[str, Any]]) -> dict[str, Any]:
    result: dict[str, Any] = {}
    for key, value in pairs:
        if key in result:
            raise ValueError("duplicate JSON field")
        result[key] = value
    return result


def _validate_json(value: Any, depth: int = 0, budget: list[int] | None = None) -> None:
    if budget is None:
        budget = [65536]
    budget[0] -= 1
    if depth > 64 or budget[0] < 0:
        raise ValueError("JSON complexity limit")
    if type(value) is float and not math.isfinite(value):
        raise ValueError("non-finite JSON value")
    if type(value) is dict:
        for item in value.values():
            _validate_json(item, depth + 1, budget)
    elif type(value) is list:
        for item in value:
            _validate_json(item, depth + 1, budget)


def _write_all(stream: Any, data: bytes) -> None:
    offset = 0
    while offset < len(data):
        written = stream.write(data[offset:])
        if not written:
            raise OSError("worker pipe closed")
        offset += written


def _await_exit(process: MacOSWorkerProcess, timeout: float) -> bool:
    status = _read_frame(process.guardian, timeout)
    process.guardian.wait(timeout=timeout)
    process.reaped = (
        status.get("status") == "reaped"
        and status.get("pid") == process.pid
        and type(status.get("wait_status")) is int
    )
    return process.reaped and status["wait_status"] == 0


def _reap(process: MacOSWorkerProcess) -> bool:
    confirmed = False
    try:
        process.close()
        if getattr(process, "reaped", False):
            return True
        _await_exit(process, 2.0)
        confirmed = process.reaped
    except (OSError, ValueError, TimeoutError, subprocess.SubprocessError):
        # Guardian death is not cleanup evidence. No unsafe numeric-PID kill
        # fallback: preserve recovery information and refuse the invocation.
        confirmed = False
    finally:
        for stream in (process.stdin, process.stdout, process.guardian.stdout):
            if stream is not None:
                stream.close()
    return confirmed


def sandbox_library() -> Any:
    library = ctypes.CDLL("/usr/lib/libsandbox.dylib", use_errno=True)
    library.sandbox_check.argtypes = [ctypes.c_int, ctypes.c_char_p, ctypes.c_int]
    library.sandbox_check.restype = ctypes.c_int
    return library


def _process_identity(pid: int) -> str | None:
    # PROC_PIDTBSDINFO layout from the macOS SDK's sys/proc_info.h.
    library = ctypes.CDLL("/usr/lib/libproc.dylib", use_errno=True)
    library.proc_pidinfo.argtypes = [
        ctypes.c_int,
        ctypes.c_int,
        ctypes.c_uint64,
        ctypes.c_void_p,
        ctypes.c_int,
    ]
    library.proc_pidinfo.restype = ctypes.c_int
    buffer = ctypes.create_string_buffer(136)
    size = library.proc_pidinfo(pid, 3, 0, buffer, len(buffer))
    if size == 0 and ctypes.get_errno() == 3:  # ESRCH, never treat EPERM as gone.
        return None
    if size != len(buffer):
        raise OSError(ctypes.get_errno(), "cannot inspect macOS worker identity")
    return f"{int.from_bytes(buffer.raw[120:128], sys.byteorder)}.{int.from_bytes(buffer.raw[128:136], sys.byteorder)}"


def _sysctl_text(name: str) -> str:
    library = ctypes.CDLL(None, use_errno=True)
    library.sysctlbyname.argtypes = [
        ctypes.c_char_p,
        ctypes.c_void_p,
        ctypes.POINTER(ctypes.c_size_t),
        ctypes.c_void_p,
        ctypes.c_size_t,
    ]
    buffer = ctypes.create_string_buffer(128)
    size = ctypes.c_size_t(len(buffer))
    if library.sysctlbyname(name.encode(), buffer, ctypes.byref(size), None, 0) != 0:
        raise OSError(ctypes.get_errno(), "cannot read boot identity")
    return buffer.value.decode()


def _file_digest(path: Path) -> str:
    return hashlib.sha256(path.read_bytes()).hexdigest()


def _digest(value: object) -> str:
    return hashlib.sha256(
        json.dumps(
            value, sort_keys=True, separators=(",", ":"), allow_nan=False
        ).encode()
    ).hexdigest()


def _evidence_payload(evidence: ActivationEvidence) -> str:
    return _digest(
        {
            "adapter": evidence.adapter_id,
            "plan": evidence.native_plan_digest,
            "context": evidence.context_digest,
            "nonce": evidence.nonce,
            "obligations": sorted(evidence.obligation_ids),
            "activated": evidence.activated_at,
            "expires": evidence.expires_at,
        }
    )


def _boot_id() -> str:
    return _sysctl_text("kern.bootsessionuuid")
