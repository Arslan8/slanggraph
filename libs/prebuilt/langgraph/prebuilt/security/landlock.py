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
import stat
import subprocess
import sys
import tempfile
import time
from collections import deque
from collections.abc import Mapping, Sequence
from dataclasses import dataclass
from pathlib import Path
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
        self._receipts: deque[ActivationReceipt] = deque(maxlen=1024)

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

        spec = self.tools.get(call.tool.name)
        if spec is None:
            raise HostExecutionDenied("host:tool_manifest_missing")
        private_tmp = tempfile.TemporaryDirectory(prefix="slanggraph-worker-")
        private_tmp_path = Path(private_tmp.name)
        artifact_tmp = tempfile.TemporaryDirectory(prefix="slanggraph-artifact-")
        broker_session: BrokerSession | None = None
        worker_broker_fd: int | None = None
        ruleset: LandlockRuleset | None = None
        try:
            source = Path(spec.artifact_path).read_bytes()
            if hashlib.sha256(source).hexdigest() != spec.artifact_digest:
                raise HostExecutionDenied("host:artifact_changed")
            # The source path may change after authorization. Execute only the
            # verified bytes, in a separate directory with no worker write grant.
            pinned = Path(artifact_tmp.name) / "tool.py"
            pinned.write_bytes(source)
            pinned.chmod(0o400)
            spec = SimpleNamespace(
                entrypoint=spec.entrypoint,
                artifact_path=pinned,
                artifact_digest=spec.artifact_digest,
            )
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
            landlock_rules, enforcement = self._lower(grant)
            ruleset = build_ruleset(landlock_rules, abi=self.abi)
            limits = self._limits(grant)
            if any(rule.domain is AuthorityDomain.SERVICE for rule in grant.rules):
                if self.credential_broker is None:
                    raise HostExecutionDenied("host:service_broker_unavailable")
                spawn = SpawnRecord(
                    principal.user_id,
                    call.tool.name,
                    grant.digest,
                    secrets.token_hex(16),
                )
                broker_session = self.credential_broker.open_session(spawn, grant)
                worker_broker_fd = broker_session.detach_worker()
            request = {
                "args": _json_value({**call.args, **call.normalized}),
                "artifact_path": os.fspath(spec.artifact_path),
                "asynchronous": asynchronous,
                "call_id": call.call_id,
                "entrypoint": spec.entrypoint,
                "landlock_ruleset_fd": ruleset.fd,
                "limits": limits,
                "plan_digest": self._worker_plan_digest(grant, enforcement),
                "runtime_roots": [os.fspath(item) for item in self.runtime_roots],
                "startup_challenge": secrets.token_hex(16),
                "tool_name": call.tool.name,
            }
            extras = self._worker_request_extras(grant)
            if set(request).intersection(extras):
                raise HostExecutionDenied("host:worker_protocol_extension_conflict")
            request.update(extras)
            if worker_broker_fd is not None:
                request["broker_fd"] = worker_broker_fd
            encoded = _encode_worker_request(request)
        except BaseException:
            self._cleanup_worker(
                process=None,
                ruleset=ruleset,
                worker_broker_fd=worker_broker_fd,
                pidfd=None,
                cgroup=None,
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
        process: subprocess.Popen[bytes] | None = None
        pidfd: int | None = None
        cgroup: CgroupV2Scope | None = None
        receipt: ActivationReceipt | None = None
        released = False
        try:
            if self._cgroup_root is not None:
                try:
                    cgroup = CgroupV2Scope.create(self._cgroup_root, limits)
                except (OSError, ValueError) as exc:
                    raise HostExecutionDenied("host:cgroup_activation_failed") from exc
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
                    raise HostExecutionDenied("host:cgroup_assignment_failed") from exc
            try:
                pidfd = os.pidfd_open(process.pid)
            except (AttributeError, OSError):
                pidfd = None
            ruleset.close()
            ruleset = None
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
            process.stdin.write(b"GO\n")
            process.stdin.flush()
            released = True
            response = _readline_json(
                process, min(limits["wall_ms"] / 1000, self.default_wall_timeout_s)
            )
            return_code = process.wait(timeout=1)
            if response.get("status") == "ok" and return_code == 0:
                return HostExecutionResult(response["result"], receipt)
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
