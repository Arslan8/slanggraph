"""Linux bubblewrap executor for host-confined tool entry points."""

from __future__ import annotations

import asyncio
import ctypes
import hashlib
import hmac
import json
import os
import platform
import secrets
import select
import shutil
import stat
import subprocess
import sys
import tempfile
import time
from collections import deque
from collections.abc import Mapping, Sequence
from dataclasses import dataclass, field, replace
from enum import Enum
from pathlib import Path
from threading import RLock
from types import MappingProxyType
from typing import Any

from langgraph.prebuilt.security.capabilities import probe_linux_capabilities
from langgraph.prebuilt.security.cedar import CedarPolicyBackend
from langgraph.prebuilt.security.deployment import (
    DeploymentBinding,
    DeploymentError,
    DeploymentLease,
    OstreeDeploymentManager,
    RuntimeBinding,
    RuntimeDeployment,
    ToolDeployment,
)
from langgraph.prebuilt.security.enforcement import (
    ActivationEvidence,
    ActivationReceipt,
    AdapterPlan,
    AuthorityDomain,
    EnforcementCoordinator,
    EnforcementMode,
    EnforcementObligation,
    EnforcementPlan,
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
from langgraph.prebuilt.security.landlock import open_path_descriptor
from langgraph.prebuilt.security.lean_grant import (
    _capture_filtered_grant,
    _capture_obligations,
)
from langgraph.prebuilt.security.lean_lifecycle import (
    LeanLifecycleChecker,
    LeanLifecycleSession,
    _capture_receipt_certificate,
)
from langgraph.prebuilt.security.policy import MandatoryPolicyBackend
from langgraph.prebuilt.security.profile import ProfileDocument
from langgraph.prebuilt.security.types import (
    ExecutionOutcome,
    PolicyConstraint,
    Principal,
    ToolCall,
)

_ADAPTER_ID = "linux-bubblewrap-v1"
_MAX_FRAME = 1_048_576
_MAX_PROTOCOL_DEPTH = 64
_MAX_PROTOCOL_NODES = 100_000
_SUPPORTED_LIMITS = frozenset(
    {
        "address_space_bytes",
        "cpu_ms",
        "file_size_bytes",
        "nofile",
        "pids",
        "tmpfs_bytes",
        "wall_ms",
    }
)
_WRITE_OPERATIONS = frozenset({"write", "create", "delete", "truncate"})
_DEFAULT_LIMITS = MappingProxyType(
    {
        "address_space_bytes": 1_073_741_824,
        "cpu_ms": 30_000,
        "file_size_bytes": 67_108_864,
        "nofile": 64,
        "pids": 1,
        "tmpfs_bytes": 67_108_864,
        "wall_ms": 30_000,
    }
)


class IntegrityRecheckMode(str, Enum):
    """Runtime integrity work performed after the preflight full hash."""

    FULL = "full"
    MERKLE_SAMPLE = "merkle-sample"
    PREFLIGHT_ONLY = "preflight-only"


@dataclass(frozen=True, slots=True)
class _MerkleCommitment:
    """Preflight commitment to fixed-size, position-bound file chunks."""

    size: int
    chunk_bytes: int
    levels: tuple[tuple[bytes, ...], ...]

    @property
    def root(self) -> str:
        return self.levels[-1][0].hex()


@dataclass(frozen=True, slots=True)
class LinuxToolSpec:
    """Trusted manifest entry for one tool imported inside the sandbox.

    `entrypoint` has the form `package.module:attribute`. `artifact_path` and
    `artifact_digest` identify the exact operator-verified module file bound
    into the per-call grant. Every other module needed to import the entry
    point must live under an explicit runtime root.
    """

    entrypoint: str
    artifact_path: Path
    artifact_digest: str
    deployment: ToolDeployment | None = None
    deployment_manager: OstreeDeploymentManager | None = None
    deployment_selection: str | None = None

    def __post_init__(self) -> None:
        module, separator, attribute = self.entrypoint.partition(":")
        if (
            not separator
            or not module
            or not attribute
            or "<locals>" in attribute
            or any(not part.isidentifier() for part in module.split("."))
            or any(not part.isidentifier() for part in attribute.split("."))
        ):
            raise ValueError(
                "Linux tool entrypoint must be importable module:attribute"
            )
        artifact = _canonical_existing_path(self.artifact_path)
        if not artifact.is_file():
            raise ValueError("Linux tool artifact_path must name a file")
        if (
            len(self.artifact_digest) != 64
            or _file_digest(artifact) != self.artifact_digest
        ):
            raise ValueError("Linux tool artifact digest does not match artifact_path")
        object.__setattr__(self, "artifact_path", artifact)
        if self.deployment is not None:
            if (
                self.entrypoint != self.deployment.manifest.entrypoint
                or artifact != self.deployment.artifact_path
                or self.artifact_digest != self.deployment.binding.artifact_digest
            ):
                raise ValueError("Linux tool spec does not match deployment")
        dynamic = self.deployment_manager is not None
        if dynamic != (self.deployment_selection is not None):
            raise ValueError(
                "deployment_manager and deployment_selection must be provided together"
            )
        if dynamic and self.deployment is None:
            raise ValueError("dynamic deployment specs require a validated seed")

    @classmethod
    def from_deployment(
        cls,
        deployment: ToolDeployment,
        *,
        manager: OstreeDeploymentManager | None = None,
        selection: str | None = None,
    ) -> LinuxToolSpec:
        """Create a trusted tool spec from a validated deployment."""
        return cls(
            deployment.manifest.entrypoint,
            deployment.artifact_path,
            deployment.binding.artifact_digest,
            deployment,
            manager,
            selection,
        )

    @classmethod
    def from_selection(
        cls,
        manager: OstreeDeploymentManager,
        *,
        tool_id: str,
        selection: str,
    ) -> LinuxToolSpec:
        """Create a channel-backed spec whose first per-call choice is retained."""
        deployment = manager.materialize(manager.resolve_ref(selection))
        if deployment.manifest.tool_id != tool_id:
            raise ValueError("Linux deployment selection has the wrong tool_id")
        return cls.from_deployment(deployment, manager=manager, selection=selection)


@dataclass(slots=True)
class _PooledLinuxWorker:
    """A confined, uncredentialed worker waiting for one invocation claim."""

    pool_key: str
    process: subprocess.Popen[bytes]
    status_read: int
    child_pid: int
    child_start_time: str
    boot_id: str
    leases: tuple[tuple[OstreeDeploymentManager, DeploymentLease], ...]
    created_at: float


@dataclass(frozen=True, slots=True)
class _PreparedHostPolicy:
    """Host-specific lowering compiled before an invocation is admitted."""

    authority_key: str
    host_configuration_digest: str
    obligation_digest: str
    mode: EnforcementMode
    assignments: tuple[Any, ...]
    adapter_plans: tuple[AdapterPlan, ...]
    waived_obligations: tuple[str, ...]
    removed_wants: tuple[str, ...]


@dataclass(slots=True)
class _LinuxWorkerPoolState:
    """Pool storage that may be shared by equivalent executor frontends."""

    workers: dict[str, deque[_PooledLinuxWorker]] = field(default_factory=dict)
    prepared_policies: dict[str, _PreparedHostPolicy] = field(default_factory=dict)
    lock: RLock = field(default_factory=RLock)
    hits: int = 0
    misses: int = 0


@dataclass(frozen=True, slots=True)
class _PreparedLinuxExecution:
    principal: Principal
    call: ToolCall
    configured: LinuxToolSpec
    spec: LinuxToolSpec
    grant: Grant
    host: HostAttestation
    plan: EnforcementPlan
    runtime: RuntimeDeployment | None
    adapter: _LinuxBubblewrapAdapter
    coordinator: EnforcementCoordinator
    leases: tuple[tuple[OstreeDeploymentManager, DeploymentLease], ...]
    grant_projection: bytes | None
    obligation_projection: bytes | None


class LinuxSandboxExecutor:
    """Execute manifest tools in a single-use, fail-closed bubblewrap worker.

    The backend currently enforces filesystem grants, an isolated no-network
    namespace, a default-deny seccomp allowlist, and resource ceilings. Optional
    preflight pooling installs those invariant restrictions before a call, while
    authorization and activation remain freshly bound at claim time. Network,
    service, credential, delegation, and executable grants are rejected until a
    broker or a more capable Linux adapter owns their exact obligations.
    """

    _lifecycle_checker: LeanLifecycleChecker | None = None

    def __init__(
        self,
        profiles: ProfileDocument,
        tools: Mapping[str, LinuxToolSpec],
        *,
        runtime_roots: Sequence[str | Path],
        principal_bindings: Mapping[str, Mapping[str, object]] | None = None,
        policy_backend: MandatoryPolicyBackend | None = None,
        bubblewrap_path: str | Path = "bwrap",
        python_executable: str | Path | None = None,
        startup_timeout_s: float = 5.0,
        default_wall_timeout_s: float = 30.0,
        default_limits: Mapping[str, int] | None = None,
        attestation_key: bytes | None = None,
        runtime_deployment: RuntimeDeployment | None = None,
        runtime_manager: OstreeDeploymentManager | None = None,
        runtime_selection: str | None = None,
        lifecycle_checker: LeanLifecycleChecker | None = None,
        worker_pool_capacity: int = 0,
        worker_pool_idle_s: float = 300.0,
        integrity_recheck: IntegrityRecheckMode | str = IntegrityRecheckMode.FULL,
        integrity_chunk_bytes: int = 65_536,
        integrity_samples: int = 4,
        _worker_pool_state: _LinuxWorkerPoolState | None = None,
    ) -> None:
        if (
            lifecycle_checker is not None
            and type(lifecycle_checker) is not LeanLifecycleChecker
        ):
            raise HostExecutionDenied("host:lean_binary_configuration")
        self._lifecycle_checker = lifecycle_checker
        if platform.system() != "Linux":
            raise RuntimeError("LinuxSandboxExecutor requires Linux")
        try:
            ctypes.CDLL("libseccomp.so.2")
        except OSError as exc:
            raise RuntimeError(
                "libseccomp.so.2 is required for Linux host execution"
            ) from exc
        bwrap = shutil.which(os.fspath(bubblewrap_path))
        if bwrap is None:
            raise RuntimeError("bubblewrap is required for Linux host execution")
        if runtime_manager is not None:
            if runtime_selection is None:
                if runtime_deployment is None:
                    raise ValueError(
                        "runtime_selection is required with runtime_manager"
                    )
                runtime_selection = runtime_deployment.binding.runtime_commit
            selected_runtime = runtime_manager.materialize_runtime(
                runtime_manager.resolve_ref(runtime_selection)
            )
            if (
                runtime_deployment is not None
                and selected_runtime.manifest.runtime_id
                != runtime_deployment.manifest.runtime_id
            ):
                raise ValueError("runtime selection has the wrong runtime_id")
            runtime_deployment = selected_runtime
        elif runtime_deployment is not None or runtime_selection is not None:
            raise ValueError("runtime deployments require an OstreeDeploymentManager")
        if runtime_deployment is not None and python_executable is not None:
            raise ValueError(
                "python_executable is supplied by runtime_deployment when configured"
            )
        python = Path(
            runtime_deployment.interpreter_path
            if runtime_deployment is not None
            else python_executable or sys.executable
        ).resolve()
        if not python.is_file():
            raise ValueError("python_executable must resolve to an existing file")
        python_runtime_root = (
            runtime_deployment.checkout_path
            if runtime_deployment is not None
            else python.parent.parent
        )
        if runtime_deployment is not None and runtime_roots:
            raise ValueError(
                "runtime_roots must be empty when runtime_deployment is configured"
            )
        roots = (
            runtime_deployment.guest_import_roots
            if runtime_deployment is not None
            else tuple(_canonical_existing_path(item) for item in runtime_roots)
        )
        if not roots:
            raise ValueError("at least one explicit runtime root is required")
        if runtime_deployment is None and any(
            not _is_supported_mount_type(root) for root in roots
        ):
            raise ValueError("runtime roots must be regular files or directories")
        if startup_timeout_s <= 0 or default_wall_timeout_s <= 0:
            raise ValueError("Linux sandbox timeouts must be positive")
        if (
            type(worker_pool_capacity) is not int
            or worker_pool_capacity < 0
            or worker_pool_idle_s <= 0
        ):
            raise ValueError("Linux worker pool settings must be non-negative")
        try:
            recheck_mode = IntegrityRecheckMode(integrity_recheck)
        except ValueError as exc:
            raise ValueError("unknown Linux integrity recheck mode") from exc
        if (
            type(integrity_chunk_bytes) is not int
            or not 4_096 <= integrity_chunk_bytes <= 1_048_576
            or type(integrity_samples) is not int
            or not 1 <= integrity_samples <= 64
        ):
            raise ValueError(
                "integrity chunks must be 4096..1048576 bytes and samples 1..64"
            )
        _verify_bubblewrap_host(bwrap, startup_timeout_s)
        limits = dict(_DEFAULT_LIMITS if default_limits is None else default_limits)
        if (
            set(limits) != _SUPPORTED_LIMITS
            or any(type(value) is not int or value <= 0 for value in limits.values())
            or limits["cpu_ms"] % 1000
            or limits["pids"] != 1
        ):
            raise ValueError(
                "default_limits must provide positive address_space_bytes, "
                "cpu_ms, file_size_bytes, nofile, pids, tmpfs_bytes, and "
                "wall_ms values; cpu_ms must use whole-second RLIMIT_CPU granularity"
                " and pids must be 1 for the no-process-creation profile"
            )
        copied_tools = dict(tools)
        if not copied_tools:
            raise ValueError("Linux sandbox requires at least one tool manifest")
        unknown = set(copied_tools).difference(profiles.tools)
        if unknown:
            raise ValueError(
                "Linux tool manifests lack profiles: " + ", ".join(sorted(unknown))
            )
        wrong_locus = {
            name for name in copied_tools if profiles.tools[name].runs != "linux"
        }
        if wrong_locus:
            raise ValueError(
                "Linux tool profiles must declare 'runs linux': "
                + ", ".join(sorted(wrong_locus))
            )
        wrong_syscalls = {
            name
            for name in copied_tools
            if profiles.tools[name].syscall_sets != frozenset({"minimal"})
        }
        if wrong_syscalls:
            raise ValueError(
                "Linux tool profiles require exactly 'syscalls @minimal': "
                + ", ".join(sorted(wrong_syscalls))
            )
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
        self.bubblewrap_path = bwrap
        self.python_executable = python
        self.python_runtime_root = python_runtime_root
        self.runtime_deployment = runtime_deployment
        self.runtime_manager = runtime_manager
        self.runtime_selection = runtime_selection
        self._worker_script = Path(__file__).with_name("_linux_worker.py").resolve()
        self._python_digest = _file_digest(self.python_executable)
        self._worker_digest = _file_digest(self._worker_script)
        self.startup_timeout_s = startup_timeout_s
        self.default_wall_timeout_s = default_wall_timeout_s
        self.default_limits = MappingProxyType(limits)
        self._attestation_key = attestation_key or secrets.token_bytes(32)
        self._adapter_lease_s = (
            startup_timeout_s
            + max(default_wall_timeout_s, limits["wall_ms"] / 1000)
            + 5.0
        )
        self._adapter = _LinuxBubblewrapAdapter(
            bwrap,
            self._attestation_key,
            self.python_executable,
            self._worker_script,
            self._adapter_lease_s,
            recheck_mode,
            integrity_chunk_bytes,
            integrity_samples,
        )
        self._coordinator = EnforcementCoordinator([self._adapter], self._adapter)
        self._receipts: deque[ActivationReceipt] = deque(maxlen=1024)
        self._receipt_lock = RLock()
        self._unresolved: dict[str, TerminationRecovery] = {}
        self._recovery_leases: dict[
            str, tuple[tuple[OstreeDeploymentManager, DeploymentLease], ...]
        ] = {}
        self._termination_lock = RLock()
        self.worker_pool_capacity = worker_pool_capacity
        self.worker_pool_idle_s = worker_pool_idle_s
        self.integrity_recheck = recheck_mode
        self.integrity_chunk_bytes = integrity_chunk_bytes
        self.integrity_samples = integrity_samples
        self._worker_pool_state = _worker_pool_state or _LinuxWorkerPoolState()

    def validate_tools(self, tool_names: Sequence[str]) -> None:
        """Require a closed manifest and Linux profile for every reachable tool."""
        missing = set(tool_names).difference(self.tools)
        if missing:
            raise ValueError(
                "Linux execution missing tool manifests: " + ", ".join(sorted(missing))
            )

    def activation_receipts(self) -> tuple[ActivationReceipt, ...]:
        """Return a bounded snapshot of worker-specific activation evidence."""
        with self._receipt_lock:
            return tuple(self._receipts)

    def worker_pool_stats(self) -> Mapping[str, int]:
        """Return pool occupancy and claim counters for evaluation telemetry."""
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

    def close(self) -> None:
        """Terminate idle workers and release their retained deployment leases."""
        state = self._worker_pool_state
        with state.lock:
            workers = [
                worker for entries in state.workers.values() for worker in entries
            ]
            state.workers.clear()
            state.prepared_policies.clear()
        for worker in workers:
            try:
                if worker.process.poll() is None:
                    worker.process.kill()
                worker.process.wait(timeout=2.0)
            except (OSError, subprocess.SubprocessError):
                continue
            try:
                os.close(worker.status_read)
            except OSError:
                pass
            self._release_deployment_leases(worker.leases)

    def prewarm(
        self,
        principal: Principal,
        call: ToolCall,
        constraints: Sequence[PolicyConstraint],
        *,
        count: int = 1,
        asynchronous: bool = False,
    ) -> int:
        """Prepare exact-policy, uncredentialed workers outside invocation timing.

        Each worker is confined before it enters the pool and can service exactly
        one later invocation whose native enforcement fingerprint is identical.
        Authorization and activation receipts are still fresh per invocation.
        """
        if type(count) is not int or count < 0:
            raise ValueError("prewarm count must be a non-negative integer")
        if count and self.worker_pool_capacity == 0:
            raise HostExecutionDenied("host:worker_pool_disabled")
        prepared_count = 0
        for _ in range(min(count, self.worker_pool_capacity)):
            prepared = self._prepare_execution(
                principal,
                call,
                constraints,
                asynchronous=asynchronous,
                preflight=True,
            )
            try:
                self._spawn_pooled_worker(prepared, asynchronous=asynchronous)
            except BaseException:
                self._release_unretained_deployment_leases(prepared.leases)
                raise
            prepared_count += 1
        return prepared_count

    def bind_call(self, principal: Principal, call: ToolCall) -> ToolCall:
        """Select executable content before policy preparation and approval."""
        spec = self.tools.get(call.tool.name)
        if spec is None:
            raise HostExecutionDenied("host:tool_manifest_missing")
        deployment = spec.deployment
        if spec.deployment_manager is not None:
            assert spec.deployment_selection is not None
            assert deployment is not None
            try:
                deployment = spec.deployment_manager.bind_invocation(
                    tool_id=deployment.manifest.tool_id,
                    selection=spec.deployment_selection,
                    principal_id=principal.user_id,
                    session_id=principal.session_id,
                    call_id=call.call_id,
                )
            except DeploymentError as exc:
                raise HostExecutionDenied("host:deployment_selection_failed") from exc
        binding = dict(call.execution_binding)
        if deployment is not None:
            binding.update(deployment.binding.canonical())
        if self.runtime_deployment is not None:
            assert self.runtime_manager is not None
            assert self.runtime_selection is not None
            try:
                runtime = self.runtime_manager.bind_runtime_selection(
                    runtime_id=self.runtime_deployment.manifest.runtime_id,
                    selection=self.runtime_selection,
                    principal_id=principal.user_id,
                    session_id=principal.session_id,
                    call_id=call.call_id,
                )
            except DeploymentError as exc:
                raise HostExecutionDenied("host:runtime_selection_failed") from exc
            binding.update(runtime.binding.canonical())
        if not binding:
            return call
        return replace(call, execution_binding=binding)

    def unresolved_terminations(self) -> tuple[TerminationRecovery, ...]:
        """Return workers still awaiting reliable termination evidence."""
        with self._termination_lock:
            return tuple(self._unresolved.values())

    def invoke(
        self,
        principal: Principal,
        call: ToolCall,
        constraints: Sequence[PolicyConstraint],
    ) -> HostExecutionResult:
        """Compile, activate, and execute one call in a fresh Linux worker."""
        return self._invoke(principal, call, constraints, asynchronous=False)

    async def ainvoke(
        self,
        principal: Principal,
        call: ToolCall,
        constraints: Sequence[PolicyConstraint],
    ) -> HostExecutionResult:
        """Compile, activate, and execute one async call off the event loop."""
        if self._lifecycle_checker is not None:
            raise HostExecutionDenied("host:lean_async_route_unavailable")
        execution = asyncio.create_task(
            asyncio.to_thread(
                self._invoke,
                principal,
                call,
                constraints,
                asynchronous=True,
            )
        )
        try:
            return await asyncio.shield(execution)
        except asyncio.CancelledError:
            # The worker's finally block owns termination and resource release.
            # Every repeated cancellation must leave that work running and wait
            # for its result before the caller can release its flow reservation.
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

    def confirm_termination(self, recovery: TerminationRecovery) -> bool:
        """Confirm or force termination for one retained Linux worker identity."""
        with self._termination_lock:
            retained = self._unresolved.get(recovery.recovery_id)
            if retained is not None and retained != recovery:
                return False
        current_boot = Path("/proc/sys/kernel/random/boot_id").read_text().strip()
        confirmed = recovery.boot_id != current_boot or _confirm_worker_terminated(
            recovery.pid, recovery.start_time, timeout_s=2.0
        )
        if confirmed:
            with self._termination_lock:
                self._unresolved.pop(recovery.recovery_id, None)
                leases = self._recovery_leases.pop(recovery.recovery_id, ())
            self._release_deployment_leases(leases)
        return confirmed

    def _invoke(
        self,
        principal: Principal,
        call: ToolCall,
        constraints: Sequence[PolicyConstraint],
        *,
        asynchronous: bool,
    ) -> HostExecutionResult:
        prepared = self._prepare_execution(
            principal,
            call,
            constraints,
            asynchronous=asynchronous,
            preflight=False,
        )
        try:
            return self._run_worker(
                prepared.principal,
                prepared.call,
                prepared.spec,
                prepared.grant,
                prepared.host,
                prepared.plan,
                prepared.runtime,
                prepared.adapter,
                prepared.coordinator,
                prepared.leases,
                asynchronous=asynchronous,
                grant_projection=prepared.grant_projection,
                obligation_projection=prepared.obligation_projection,
            )
        except BaseException:
            self._release_unretained_deployment_leases(prepared.leases)
            raise

    def _prepare_execution(
        self,
        principal: Principal,
        call: ToolCall,
        constraints: Sequence[PolicyConstraint],
        *,
        asynchronous: bool,
        preflight: bool,
    ) -> _PreparedLinuxExecution:
        """Authorize and lower one invocation without creating an effect."""
        checker = self._lifecycle_checker
        if checker is not None and (
            type(checker) is not LeanLifecycleChecker or asynchronous
        ):
            raise HostExecutionDenied("host:lean_route_configuration")
        configured = self.tools.get(call.tool.name)
        if configured is None:
            raise HostExecutionDenied("host:tool_manifest_missing")
        spec = self._bound_spec(principal, call, configured)
        runtime = self._bound_runtime(principal, call)
        grant, ledger = self._compile_grant(principal, call, spec, runtime)
        filtered = self.policy_backend.filter(grant, ledger, constraints)
        grant_projection: bytes | None = None
        obligation_projection: bytes | None = None
        if checker is not None:
            # Admit raw filter/record storage before calling generic conversion
            # or digest helpers on it. Subsequent compilation and lowering use
            # the detached native reconstruction, not mutable original aliases.
            captured_grant = _capture_filtered_grant(filtered)
            filtered = captured_grant.filtered
            grant_projection = captured_grant.projection
        if not filtered.allowed or filtered.grant is None:
            raise HostExecutionDenied(f"host:{filtered.reason}")
        grant = filtered.grant
        obligations = compile_obligations(grant)
        if checker is not None:
            captured_obligations = _capture_obligations(obligations)
            obligations = captured_obligations.obligations
            obligation_projection = captured_obligations.projection
            if grant_projection is None:
                raise HostExecutionDenied("host:lean_grant_missing")
            checker.require_grant(
                json.loads(grant_projection), json.loads(obligation_projection)
            )
        adapter = self._adapter_for_runtime(runtime)
        coordinator = EnforcementCoordinator([adapter], adapter)
        authority_key = _prepared_authority_key(grant, obligations)
        if preflight or not self.worker_pool_capacity:
            challenge = secrets.token_hex(16)
            host = adapter.attest(challenge)
            negotiation = coordinator.negotiate(
                grant,
                filtered.ledger,
                obligations,
                host,
                expected_nonce=challenge,
            )
            if not negotiation.allowed or negotiation.plan is None:
                raise HostExecutionDenied(f"host:{negotiation.reason}")
            plan = negotiation.plan
            if preflight:
                prepared_policy = _PreparedHostPolicy(
                    authority_key,
                    _host_configuration_digest(host),
                    plan.obligation_digest,
                    plan.mode,
                    plan.assignments,
                    plan.adapter_plans,
                    plan.waived_obligations,
                    plan.removed_wants,
                )
                state = self._worker_pool_state
                with state.lock:
                    prior = state.prepared_policies.get(authority_key)
                    if prior is not None and prior != prepared_policy:
                        raise HostExecutionDenied("host:prepared_policy_conflict")
                    state.prepared_policies[authority_key] = prepared_policy
        else:
            state = self._worker_pool_state
            with state.lock:
                prepared_policy = state.prepared_policies.get(authority_key)
            if prepared_policy is None:
                raise HostExecutionDenied("host:prepared_policy_missing")
            challenge = secrets.token_hex(16)
            host = adapter.attest(challenge)
            if prepared_policy.host_configuration_digest != _host_configuration_digest(
                host
            ):
                raise HostExecutionDenied("host:prepared_host_changed")
            obligation_digest = _digest(
                [
                    item.canonical()
                    for item in sorted(
                        obligations, key=lambda value: value.obligation_id
                    )
                ]
            )
            if obligation_digest != prepared_policy.obligation_digest:
                raise HostExecutionDenied("host:prepared_obligations_changed")
            plan = EnforcementPlan(
                grant.digest,
                host.digest,
                obligation_digest,
                prepared_policy.mode,
                prepared_policy.assignments,
                prepared_policy.adapter_plans,
                prepared_policy.waived_obligations,
                prepared_policy.removed_wants,
            )
        leases = self._acquire_deployment_leases(
            principal, call, configured, spec, runtime
        )
        return _PreparedLinuxExecution(
            principal,
            call,
            configured,
            spec,
            grant,
            host,
            plan,
            runtime,
            adapter,
            coordinator,
            leases,
            grant_projection,
            obligation_projection,
        )

    def _acquire_deployment_leases(
        self,
        principal: Principal,
        call: ToolCall,
        configured: LinuxToolSpec,
        spec: LinuxToolSpec,
        runtime: RuntimeDeployment | None,
    ) -> tuple[tuple[OstreeDeploymentManager, DeploymentLease], ...]:
        commits: dict[OstreeDeploymentManager, list[str]] = {}
        if configured.deployment_manager is not None and spec.deployment is not None:
            commits.setdefault(configured.deployment_manager, []).append(
                spec.deployment.binding.tool_commit
            )
        if self.runtime_manager is not None and runtime is not None:
            commits.setdefault(self.runtime_manager, []).append(
                runtime.binding.runtime_commit
            )
        leases: list[tuple[OstreeDeploymentManager, DeploymentLease]] = []
        try:
            for manager, selected in commits.items():
                leases.append(
                    (
                        manager,
                        manager.acquire_lease(
                            selected,
                            principal_id=principal.user_id,
                            session_id=principal.session_id,
                            call_id=call.call_id,
                        ),
                    )
                )
        except DeploymentError as exc:
            self._release_deployment_leases(leases)
            raise HostExecutionDenied("host:deployment_lease_failed") from exc
        return tuple(leases)

    @staticmethod
    def _release_deployment_leases(
        leases: Sequence[tuple[OstreeDeploymentManager, DeploymentLease]],
    ) -> None:
        for manager, lease in leases:
            try:
                manager.release_lease(lease)
            except DeploymentError:
                pass

    def _release_unretained_deployment_leases(
        self,
        leases: Sequence[tuple[OstreeDeploymentManager, DeploymentLease]],
    ) -> None:
        with self._termination_lock:
            retained_ids = {
                lease.lease_id
                for recovery_leases in self._recovery_leases.values()
                for _, lease in recovery_leases
            }
        self._release_deployment_leases(
            tuple(item for item in leases if item[1].lease_id not in retained_ids)
        )

    def _bound_spec(
        self, principal: Principal, call: ToolCall, configured: LinuxToolSpec
    ) -> LinuxToolSpec:
        """Recover the exact deployment selected before authorization."""
        if configured.deployment is None:
            if any(
                key in call.execution_binding
                for key in {
                    "artifact_digest",
                    "format_version",
                    "manifest_digest",
                    "tool_commit",
                    "tool_id",
                }
            ):
                raise HostExecutionDenied("host:unexpected_execution_binding")
            return configured
        try:
            binding = DeploymentBinding(
                int(call.execution_binding["format_version"]),
                str(call.execution_binding["tool_id"]),
                str(call.execution_binding["tool_commit"]),
                str(call.execution_binding["manifest_digest"]),
                str(call.execution_binding["artifact_digest"]),
            )
        except (KeyError, TypeError, ValueError) as exc:
            raise HostExecutionDenied("host:invalid_deployment_binding") from exc
        if configured.deployment_manager is None:
            deployment = configured.deployment
            if deployment.binding != binding:
                raise HostExecutionDenied("host:deployment_substitution")
        else:
            try:
                deployment = configured.deployment_manager.recover_invocation(
                    binding,
                    principal_id=principal.user_id,
                    session_id=principal.session_id,
                    call_id=call.call_id,
                )
            except DeploymentError as exc:
                raise HostExecutionDenied("host:missing_deployment") from exc
        return LinuxToolSpec.from_deployment(deployment)

    def _bound_runtime(
        self, principal: Principal, call: ToolCall
    ) -> RuntimeDeployment | None:
        """Require the configured runtime to match the pre-authorization binding."""
        runtime = self.runtime_deployment
        keys = {
            "runtime_commit",
            "runtime_format_version",
            "runtime_id",
            "runtime_manifest_digest",
        }
        present = keys.intersection(call.execution_binding)
        if runtime is None:
            if present:
                raise HostExecutionDenied("host:unexpected_runtime_binding")
            return None
        if present != keys:
            raise HostExecutionDenied("host:invalid_runtime_binding")
        try:
            binding = RuntimeBinding(
                int(call.execution_binding["runtime_format_version"]),
                str(call.execution_binding["runtime_id"]),
                str(call.execution_binding["runtime_commit"]),
                str(call.execution_binding["runtime_manifest_digest"]),
            )
        except (KeyError, TypeError, ValueError) as exc:
            raise HostExecutionDenied("host:invalid_runtime_binding") from exc
        if binding.runtime_id != runtime.binding.runtime_id:
            raise HostExecutionDenied("host:runtime_substitution")
        assert self.runtime_manager is not None
        try:
            return self.runtime_manager.recover_runtime_invocation(
                binding,
                principal_id=principal.user_id,
                session_id=principal.session_id,
                call_id=call.call_id,
            )
        except DeploymentError as exc:
            raise HostExecutionDenied("host:missing_runtime") from exc

    def _adapter_for_runtime(
        self, runtime: RuntimeDeployment | None
    ) -> _LinuxBubblewrapAdapter:
        if runtime is None or runtime.binding == self.runtime_deployment.binding:
            return self._adapter
        return _LinuxBubblewrapAdapter(
            self.bubblewrap_path,
            self._attestation_key,
            runtime.interpreter_path,
            self._worker_script,
            self._adapter_lease_s,
            self.integrity_recheck,
            self.integrity_chunk_bytes,
            self.integrity_samples,
        )

    def _compile_grant(
        self,
        principal: Principal,
        call: ToolCall,
        spec: LinuxToolSpec,
        runtime: RuntimeDeployment | None,
    ) -> tuple[Grant, Any]:
        profile = self.profiles.principals.get(principal.user_id)
        if profile is None:
            raise HostExecutionDenied("host:principal_profile_missing")
        if profile.roles != principal.roles or profile.scopes != principal.scopes:
            raise HostExecutionDenied("host:principal_profile_mismatch")
        bindings: dict[str, object] = dict(call.args)
        bindings.update(call.normalized)
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
                    "args": _json_value(call.args),
                    "normalized": _json_value(call.normalized),
                    "tool": call.tool.name,
                }
            ),
            policy_digest=_digest({"stage": "pre-mac"}),
            baseline_rules=self._baseline_rules(spec, runtime),
            deployment_digest=(
                spec.deployment.binding.tool_commit
                if spec.deployment is not None
                else ""
            ),
            runtime_digest=(
                runtime.binding.runtime_commit if runtime is not None else ""
            ),
        )
        return compiled.grant, compiled.ledger

    def _baseline_rules(
        self, spec: LinuxToolSpec, runtime: RuntimeDeployment | None
    ) -> tuple[GrantRule, ...]:
        rules = [
            GrantRule(
                "runtime:tmp:read",
                AuthorityDomain.RUNTIME,
                "read",
                "/tmp",
                {"subtree": True, "ephemeral": True},
                baseline=True,
            ),
            GrantRule(
                "runtime:tmp:write",
                AuthorityDomain.RUNTIME,
                "write",
                "/tmp",
                {"subtree": True, "ephemeral": True},
                baseline=True,
            ),
            GrantRule(
                "runtime:tmp:create",
                AuthorityDomain.RUNTIME,
                "create",
                "/tmp",
                {"subtree": True, "ephemeral": True},
                baseline=True,
            ),
            GrantRule(
                "runtime:tmp:delete",
                AuthorityDomain.RUNTIME,
                "delete",
                "/tmp",
                {"subtree": True, "ephemeral": True},
                baseline=True,
            ),
            GrantRule(
                "runtime:tmp:truncate",
                AuthorityDomain.RUNTIME,
                "truncate",
                "/tmp",
                {"subtree": True, "ephemeral": True},
                baseline=True,
            ),
            GrantRule(
                "runtime:urandom",
                AuthorityDomain.RUNTIME,
                "read",
                "/dev/urandom",
                baseline=True,
            ),
            GrantRule(
                "runtime:worker",
                AuthorityDomain.RUNTIME,
                "read",
                os.fspath(self._worker_script),
                {"sha256": self._worker_digest},
                baseline=True,
            ),
            GrantRule(
                "runtime:artifact",
                AuthorityDomain.RUNTIME,
                "read",
                os.fspath(spec.artifact_path),
                {"sha256": spec.artifact_digest},
                baseline=True,
            ),
            GrantRule(
                "runtime:interpreter",
                AuthorityDomain.RUNTIME,
                "read",
                os.fspath(
                    runtime.interpreter_path
                    if runtime is not None
                    else self.python_executable
                ),
                {
                    "sha256": _file_digest(
                        runtime.interpreter_path
                        if runtime is not None
                        else self.python_executable
                    )
                },
                baseline=True,
            ),
            GrantRule(
                "runtime:interpreter-root",
                AuthorityDomain.RUNTIME,
                "read",
                os.fspath(
                    runtime.checkout_path
                    if runtime is not None
                    else self.python_runtime_root
                ),
                {"subtree": True},
                baseline=True,
            ),
            GrantRule(
                "runtime:env:path",
                AuthorityDomain.RUNTIME,
                "environment",
                "PATH",
                {"value": "/usr/bin"},
                baseline=True,
            ),
            GrantRule(
                "runtime:env:no-bytecode",
                AuthorityDomain.RUNTIME,
                "environment",
                "PYTHONDONTWRITEBYTECODE",
                {"value": "1"},
                baseline=True,
            ),
            GrantRule(
                "runtime:env:no-locale-coercion",
                AuthorityDomain.RUNTIME,
                "environment",
                "PYTHONCOERCECLOCALE",
                {"value": "0"},
                baseline=True,
            ),
            GrantRule(
                "runtime:env:no-user-site",
                AuthorityDomain.RUNTIME,
                "environment",
                "PYTHONNOUSERSITE",
                {"value": "1"},
                baseline=True,
            ),
            GrantRule(
                "runtime:env:safe-path",
                AuthorityDomain.RUNTIME,
                "environment",
                "PYTHONSAFEPATH",
                {"value": "1"},
                baseline=True,
            ),
            GrantRule(
                "runtime:env:unbuffered",
                AuthorityDomain.RUNTIME,
                "environment",
                "PYTHONUNBUFFERED",
                {"value": "1"},
                baseline=True,
            ),
            GrantRule(
                "runtime:env:utf8",
                AuthorityDomain.RUNTIME,
                "environment",
                "PYTHONUTF8",
                {"value": "1"},
                baseline=True,
            ),
            GrantRule(
                "runtime:protocol:request",
                AuthorityDomain.IPC,
                "read",
                "parent-request-pipe",
                {"descriptor": 0},
                baseline=True,
            ),
            GrantRule(
                "runtime:protocol:response",
                AuthorityDomain.IPC,
                "write",
                "parent-response-pipe",
                {"descriptor": 1},
                baseline=True,
            ),
            GrantRule(
                "runtime:protocol:diagnostic",
                AuthorityDomain.IPC,
                "write",
                "parent-diagnostic-pipe",
                {"descriptor": 2},
                baseline=True,
            ),
        ]
        if runtime is None:
            rules.append(
                GrantRule(
                    "runtime:usr",
                    AuthorityDomain.RUNTIME,
                    "read",
                    "/usr",
                    {"subtree": True},
                    baseline=True,
                )
            )
        else:
            rules.append(
                GrantRule(
                    "runtime:deployment-root",
                    AuthorityDomain.RUNTIME,
                    "read",
                    os.fspath(runtime.checkout_path),
                    {
                        "ostree_commit": runtime.binding.runtime_commit,
                        "subtree": True,
                    },
                    baseline=True,
                )
            )
        if spec.deployment is not None:
            rules.append(
                GrantRule(
                    "runtime:deployment",
                    AuthorityDomain.RUNTIME,
                    "read",
                    os.fspath(spec.deployment.checkout_path),
                    {
                        "ostree_commit": spec.deployment.binding.tool_commit,
                        "subtree": True,
                    },
                    baseline=True,
                )
            )
        for index, root in enumerate(self.runtime_roots if runtime is None else ()):
            if root == Path("/usr") or Path("/usr") in root.parents:
                continue
            rules.append(
                GrantRule(
                    f"runtime:root:{index}",
                    AuthorityDomain.RUNTIME,
                    "read",
                    os.fspath(root),
                    {"subtree": root.is_dir()},
                    baseline=True,
                )
            )
        for name, maximum in self.default_limits.items():
            rules.append(
                GrantRule(
                    f"runtime:limit:{name}",
                    AuthorityDomain.RESOURCE_LIMIT,
                    "limit",
                    name,
                    {"maximum": maximum},
                    baseline=True,
                )
            )
        return tuple(rules)

    def _worker_pool_key(
        self,
        adapter_plan: AdapterPlan,
        spec: LinuxToolSpec,
        runtime: RuntimeDeployment | None,
        adapter: _LinuxBubblewrapAdapter,
        *,
        asynchronous: bool,
    ) -> str:
        del runtime
        return _digest(
            {
                "adapter": adapter_plan.adapter_id,
                "native_plan": adapter_plan.native_plan_digest,
                "artifact": spec.artifact_digest,
                "entrypoint": spec.entrypoint,
                "interpreter": adapter.python_digest,
                "integrity_recheck": self.integrity_recheck.value,
                "integrity_chunk_bytes": self.integrity_chunk_bytes,
                "integrity_samples": self.integrity_samples,
                "worker": self._worker_digest,
                "asynchronous": asynchronous,
            }
        )

    def _spawn_pooled_worker(
        self,
        prepared: _PreparedLinuxExecution,
        *,
        asynchronous: bool,
    ) -> None:
        adapter_plan = next(
            item
            for item in prepared.plan.adapter_plans
            if item.adapter_id == _ADAPTER_ID
        )
        pool_key = self._worker_pool_key(
            adapter_plan,
            prepared.spec,
            prepared.runtime,
            prepared.adapter,
            asynchronous=asynchronous,
        )
        state = self._worker_pool_state
        with state.lock:
            self._reap_worker_pool_locked()
            if sum(len(items) for items in state.workers.values()) >= (
                self.worker_pool_capacity
            ):
                raise HostExecutionDenied("host:worker_pool_full")
        command, inherited_fds, status_read, status_write, artifact_directory = (
            self._worker_command(adapter_plan, prepared.spec, prepared.runtime)
        )
        process: subprocess.Popen[bytes] | None = None
        child_pid: int | None = None
        child_start_time: str | None = None
        try:
            process = subprocess.Popen(
                command,
                stdin=subprocess.PIPE,
                stdout=subprocess.PIPE,
                stderr=subprocess.PIPE,
                bufsize=0,
                close_fds=True,
                pass_fds=(*inherited_fds, status_write),
            )
            os.close(status_write)
            status_write = -1
            for descriptor in inherited_fds:
                os.close(descriptor)
            inherited_fds = ()
            if process.stdin is None or process.stdout is None:
                raise HostExecutionDenied("host:worker_pipe_failed")
            process.stdin.write(
                _encode_worker_request(
                    {
                        "args": {},
                        "artifact_path": os.fspath(prepared.spec.artifact_path),
                        "asynchronous": asynchronous,
                        "call_id": "",
                        "entrypoint": prepared.spec.entrypoint,
                        "limits": _plain_mapping(
                            adapter_plan.payload.get("limits", {})
                        ),
                        "pool_bootstrap": True,
                        "pool_key": pool_key,
                        "runtime_roots": [
                            os.fspath(item)
                            for item in (
                                prepared.runtime.guest_import_roots
                                if prepared.runtime is not None
                                else self.runtime_roots
                            )
                        ],
                        "tool_import_roots": (
                            [
                                os.fspath(item)
                                for item in prepared.spec.deployment.import_roots
                            ]
                            if prepared.spec.deployment is not None
                            else []
                        ),
                        "tool_name": prepared.call.tool.name,
                    }
                )
            )
            process.stdin.flush()
            status = _read_fd_json(status_read, self.startup_timeout_s)
            sandbox_init_pid = int(status["child-pid"])
            pooled = _readline_json(process, self.startup_timeout_s)
            if pooled != {"pool_key": pool_key, "status": "pooled"}:
                raise HostExecutionDenied("host:worker_pool_protocol")
            child_pid = _sandbox_payload_pid(
                sandbox_init_pid, timeout_s=self.startup_timeout_s
            )
            context = _execution_context(child_pid)
            child_start_time = context.process_identity.rpartition(":")[2]
            _remove_private_artifact(artifact_directory)
            artifact_directory = None
            worker = _PooledLinuxWorker(
                pool_key,
                process,
                status_read,
                child_pid,
                child_start_time,
                context.boot_id,
                prepared.leases,
                time.monotonic(),
            )
            status_read = -1
            with state.lock:
                state.workers.setdefault(pool_key, deque()).append(worker)
            process = None
        finally:
            for descriptor in (status_read, status_write, *inherited_fds):
                if descriptor >= 0:
                    try:
                        os.close(descriptor)
                    except OSError:
                        pass
            if artifact_directory is not None:
                _remove_private_artifact(artifact_directory)
            if process is not None:
                try:
                    process.kill()
                    process.wait(timeout=2.0)
                except (OSError, subprocess.SubprocessError):
                    pass

    def _claim_pooled_worker(self, pool_key: str) -> _PooledLinuxWorker | None:
        state = self._worker_pool_state
        with state.lock:
            self._reap_worker_pool_locked()
            workers = state.workers.get(pool_key)
            while workers:
                worker = workers.popleft()
                if worker.process.poll() is None:
                    state.hits += 1
                    if not workers:
                        state.workers.pop(pool_key, None)
                    return worker
                try:
                    os.close(worker.status_read)
                except OSError:
                    pass
                self._release_deployment_leases(worker.leases)
            state.workers.pop(pool_key, None)
            state.misses += 1
            return None

    def _reap_worker_pool_locked(self) -> None:
        cutoff = time.monotonic() - self.worker_pool_idle_s
        stale: list[_PooledLinuxWorker] = []
        state = self._worker_pool_state
        for key, workers in tuple(state.workers.items()):
            retained = deque(
                worker
                for worker in workers
                if worker.created_at >= cutoff and worker.process.poll() is None
            )
            stale.extend(worker for worker in workers if worker not in retained)
            if retained:
                state.workers[key] = retained
            else:
                state.workers.pop(key, None)
        for worker in stale:
            try:
                if worker.process.poll() is None:
                    worker.process.kill()
                worker.process.wait(timeout=2.0)
            except (OSError, subprocess.SubprocessError):
                continue
            try:
                os.close(worker.status_read)
            except OSError:
                pass
            self._release_deployment_leases(worker.leases)

    def _run_worker(
        self,
        principal: Principal,
        call: ToolCall,
        spec: LinuxToolSpec,
        grant: Grant,
        host: HostAttestation,
        plan: EnforcementPlan,
        runtime: RuntimeDeployment | None,
        adapter: _LinuxBubblewrapAdapter,
        coordinator: EnforcementCoordinator,
        leases: tuple[tuple[OstreeDeploymentManager, DeploymentLease], ...],
        *,
        asynchronous: bool,
        grant_projection: bytes | None = None,
        obligation_projection: bytes | None = None,
    ) -> HostExecutionResult:
        checker = self._lifecycle_checker
        if checker is not None and (
            type(checker) is not LeanLifecycleChecker or asynchronous
        ):
            raise HostExecutionDenied("host:lean_route_configuration")
        if checker is not None:
            if (
                type(grant_projection) is not bytes
                or type(obligation_projection) is not bytes
                or len(grant_projection) > _MAX_FRAME
                or len(obligation_projection) > _MAX_FRAME
            ):
                raise HostExecutionDenied("host:lean_grant_missing")
            try:
                grant_data = json.loads(grant_projection)
                obligation_data = json.loads(obligation_projection)
            except (UnicodeError, ValueError, RecursionError):
                raise HostExecutionDenied("host:lean_grant_shape") from None
            # Recheck at the worker boundary before command setup or process
            # creation. _invoke also checks before attestation and lowering.
            checker.require_grant(grant_data, obligation_data)
        # Only these immutable snapshots are reused after activation. Local
        # checker arguments may be observed by instrumentation and are not a
        # source of authority for a later gate.
        captured_grant_bytes = grant_projection if grant_projection is not None else b""
        captured_obligation_bytes = (
            obligation_projection if obligation_projection is not None else b""
        )
        adapter_plan = next(
            item for item in plan.adapter_plans if item.adapter_id == _ADAPTER_ID
        )
        pool_key = self._worker_pool_key(
            adapter_plan, spec, runtime, adapter, asynchronous=asynchronous
        )
        pooled = (
            self._claim_pooled_worker(pool_key)
            if getattr(self, "worker_pool_capacity", 0)
            else None
        )
        if pooled is None and getattr(self, "worker_pool_capacity", 0):
            raise HostExecutionDenied("host:prepared_worker_unavailable")
        if pooled is None:
            interpreter = (
                runtime.interpreter_path
                if runtime is not None
                else self.python_executable
            )
            if _file_digest(interpreter) != adapter.python_digest:
                raise HostExecutionDenied("host:interpreter_changed")
            if _file_digest(self._worker_script) != self._worker_digest:
                raise HostExecutionDenied("host:worker_shim_changed")
        startup_challenge = secrets.token_hex(16)
        try:
            request = {
                "args": _json_value(call.args),
                "artifact_path": os.fspath(spec.artifact_path),
                "asynchronous": asynchronous,
                "call_id": call.call_id,
                "entrypoint": spec.entrypoint,
                "limits": _plain_mapping(adapter_plan.payload.get("limits", {})),
                "plan_digest": adapter_plan.native_plan_digest,
                "runtime_roots": [
                    os.fspath(item)
                    for item in (
                        runtime.guest_import_roots
                        if runtime is not None
                        else self.runtime_roots
                    )
                ],
                "tool_import_roots": (
                    [os.fspath(item) for item in spec.deployment.import_roots]
                    if spec.deployment is not None
                    else []
                ),
                "startup_challenge": startup_challenge,
                "tool_name": call.tool.name,
            }
            if pooled is not None:
                request["pool_key"] = pool_key
            encoded_request = _encode_worker_request(request)
        except (RecursionError, TypeError, ValueError) as exc:
            raise HostExecutionDenied("host:request_not_serializable") from exc
        artifact_directory: Path | None = None
        command: list[str] = []
        inherited_fds: tuple[int, ...] = ()
        status_read = pooled.status_read if pooled is not None else -1
        status_write = -1
        process: subprocess.Popen[bytes] | None = (
            pooled.process if pooled is not None else None
        )
        receipt: ActivationReceipt | None = None
        released = False
        child_pid: int | None = pooled.child_pid if pooled is not None else None
        child_start_time: str | None = (
            pooled.child_start_time if pooled is not None else None
        )
        cleanup_leases = leases + (() if pooled is None else pooled.leases)
        lifecycle: LeanLifecycleSession | None = None
        lifecycle_observed: dict | None = None
        result: HostExecutionResult | None = None
        # Exception state inherited from a caller's except block does not belong
        # to this worker. Capture only an exception escaping this invocation,
        # including translated errors and BaseException cancellation paths.
        active_error: BaseException | None = None
        try:
            try:
                if pooled is None:
                    (
                        command,
                        inherited_fds,
                        status_read,
                        status_write,
                        artifact_directory,
                    ) = self._worker_command(adapter_plan, spec, runtime)
                    process = subprocess.Popen(
                        command,
                        stdin=subprocess.PIPE,
                        stdout=subprocess.PIPE,
                        stderr=subprocess.PIPE,
                        bufsize=0,
                        close_fds=True,
                        pass_fds=(*inherited_fds, status_write),
                    )
                    os.close(status_write)
                    status_write = -1
                    for descriptor in inherited_fds:
                        os.close(descriptor)
                    inherited_fds = ()
                assert process is not None
                if process.stdin is None or process.stdout is None:
                    raise HostExecutionDenied("host:worker_pipe_failed")
                process.stdin.write(encoded_request)
                process.stdin.flush()
                if pooled is None:
                    status = _read_fd_json(status_read, self.startup_timeout_s)
                    sandbox_init_pid = int(status["child-pid"])
                ready = _readline_json(process, self.startup_timeout_s)
                if artifact_directory is not None:
                    _remove_private_artifact(artifact_directory)
                    artifact_directory = None
                if ready != {
                    "plan_digest": adapter_plan.native_plan_digest,
                    "startup_challenge": startup_challenge,
                    "status": "ready",
                }:
                    raise HostExecutionDenied("host:worker_startup_protocol")
                if pooled is None:
                    child_pid = _sandbox_payload_pid(
                        sandbox_init_pid, timeout_s=self.startup_timeout_s
                    )
                assert child_pid is not None
                context = _execution_context(child_pid)
                child_start_time = context.process_identity.rpartition(":")[2]
                if pooled is not None and (
                    context.boot_id != pooled.boot_id
                    or child_start_time != pooled.child_start_time
                ):
                    raise HostExecutionDenied("host:worker_pool_identity_changed")
                adapter.register_pending(adapter_plan, context)
                activation_nonce = secrets.token_hex(16)
                receipt = coordinator.activate(
                    grant,
                    plan,
                    host,
                    context,
                    nonce=activation_nonce,
                )
                if not coordinator.validate_receipt(
                    receipt, grant, plan, host, context
                ):
                    raise HostExecutionDenied("host:activation_receipt_invalid")
                with self._receipt_lock:
                    self._receipts.append(receipt)
                if checker is not None:
                    expected = {
                        "principal": principal.user_id,
                        "session": principal.session_id,
                        "call": call.call_id,
                        "tool": call.tool.name,
                        "artifact": spec.artifact_digest,
                        "intent": json.loads(captured_grant_bytes)["intent"],
                        "policy": json.loads(captured_grant_bytes)["policy"],
                        "deployment": grant.deployment_digest,
                        "runtime": grant.runtime_digest,
                        "grant": grant.digest,
                        "plan": plan.digest,
                        "nonce": activation_nonce,
                        "host": host.digest,
                        "context": context.digest,
                        "worker": {
                            "pid": str(child_pid),
                            "startTime": child_start_time,
                            "bootId": host.boot_id,
                        },
                    }
                    lifecycle_observed = {
                        "principal": grant.principal_id,
                        "session": grant.session_id,
                        "call": grant.call_id,
                        "tool": grant.tool_name,
                        "artifact": receipt.artifact_digest,
                        "intent": grant.normalized_intent_digest,
                        "policy": grant.policy_digest,
                        "deployment": receipt.deployment_digest,
                        "runtime": receipt.runtime_digest,
                        "grant": receipt.grant_digest,
                        "plan": receipt.plan_digest,
                        "nonce": receipt.nonce,
                        "host": receipt.host_digest,
                        "context": receipt.context_digest,
                        "worker": {
                            "pid": str(child_pid),
                            "startTime": child_start_time,
                            "bootId": context.boot_id,
                        },
                    }
                    certificate = _capture_receipt_certificate(
                        plan,
                        receipt,
                        plan_digest=expected["plan"],
                        grant=json.loads(captured_grant_bytes),
                        obligations=json.loads(captured_obligation_bytes),
                    )
                    lifecycle = LeanLifecycleSession(
                        checker, expected, certificate=certificate
                    )
                    lifecycle.permit_go(
                        lifecycle_observed,
                        supported=plan.mode is EnforcementMode.ENFORCED
                        and receipt.mode is EnforcementMode.ENFORCED
                        and not plan.waived_obligations,
                    )
                process.stdin.write(b"GO\n")
                process.stdin.flush()
                released = True
                wall_timeout = _wall_timeout(
                    adapter_plan.payload, self.default_wall_timeout_s
                )
                response = _readline_json(process, wall_timeout)
                return_code = process.wait(timeout=1.0)
                if response.get("status") == "ok" and "result" in response:
                    if return_code != 0:
                        raise HostExecutionError(
                            "sandboxed tool outcome is indeterminate",
                            receipt,
                            ExecutionOutcome.INDETERMINATE,
                        )
                    result = HostExecutionResult(response["result"], receipt)
                else:
                    error_type = str(response.get("error_type", "Exception"))
                    raise HostExecutionError(
                        f"sandboxed tool failed:{error_type}",
                        receipt,
                        ExecutionOutcome.FAILED,
                    )
            except HostExecutionError:
                raise
            except HostExecutionDenied:
                raise
            except TimeoutError as exc:
                reason = (
                    "host:worker_startup_timeout" if not released else "tool_timeout"
                )
                if released and receipt is not None:
                    raise HostExecutionError(
                        reason, receipt, ExecutionOutcome.INDETERMINATE
                    ) from exc
                raise HostExecutionDenied(reason) from exc
            except (
                KeyError,
                OSError,
                RecursionError,
                ValueError,
                subprocess.SubprocessError,
            ) as exc:
                if receipt is not None:
                    raise HostExecutionError(
                        "sandboxed tool outcome is indeterminate",
                        receipt,
                        ExecutionOutcome.INDETERMINATE,
                    ) from exc
                raise HostExecutionDenied("host:worker_activation_failed") from exc
        except BaseException as exc:
            active_error = exc
            raise
        finally:
            self._cleanup_worker(
                status_read=status_read,
                status_write=status_write,
                inherited_fds=inherited_fds,
                process=process,
                child_pid=child_pid,
                child_start_time=child_start_time,
                artifact_directory=artifact_directory,
                host=host,
                receipt=receipt,
                leases=cleanup_leases,
                active_error=active_error,
            )
        # Reaching here means this invocation's cleanup returned normally after
        # a valid result. Unknown termination raises; no success check precedes it.
        if result is None:
            raise HostExecutionDenied("host:worker_result_missing")
        if lifecycle is not None:
            assert lifecycle_observed is not None
            try:
                lifecycle.permit_success(lifecycle_observed)
            except HostExecutionDenied as exc:
                # The worker already ran. Blocking release is not a pre-effect
                # refusal, even though termination has now been confirmed.
                raise HostExecutionError(
                    "host:lean_result_release_failed",
                    result.receipt,
                    ExecutionOutcome.INDETERMINATE,
                    termination_confirmed=True,
                ) from exc
        return result

    def _cleanup_worker(
        self,
        *,
        status_read: int,
        status_write: int,
        inherited_fds: Sequence[int],
        process: subprocess.Popen[bytes] | None,
        child_pid: int | None,
        child_start_time: str | None,
        artifact_directory: Path | None,
        host: HostAttestation,
        receipt: ActivationReceipt | None,
        leases: tuple[tuple[OstreeDeploymentManager, DeploymentLease], ...],
        active_error: BaseException | None,
    ) -> None:
        """Clean up independently and retain recovery evidence when uncertain."""
        for descriptor in (status_read, status_write, *inherited_fds):
            if descriptor < 0:
                continue
            try:
                os.close(descriptor)
            except Exception:
                pass

        if process is not None:
            try:
                running = process.poll() is None
            except Exception:
                running = True
            if running:
                try:
                    process.kill()
                except Exception:
                    pass
                try:
                    process.wait(timeout=2.0)
                except Exception:
                    pass

        termination_confirmed = not (
            child_pid is not None and child_start_time is not None
        )
        if child_pid is not None and child_start_time is not None:
            try:
                termination_confirmed = _confirm_worker_terminated(
                    child_pid, child_start_time, timeout_s=2.0
                )
            except Exception:
                termination_confirmed = False

        if artifact_directory is not None:
            try:
                _remove_private_artifact(artifact_directory)
            except Exception:
                pass

        if termination_confirmed:
            self._release_deployment_leases(leases)
            if isinstance(active_error, HostExecutionError):
                active_error.termination_confirmed = True
            return

        # Both values are present whenever confirmation is required.
        assert child_pid is not None
        assert child_start_time is not None
        recovery = TerminationRecovery(
            secrets.token_hex(16),
            child_pid,
            child_start_time,
            host.boot_id,
        )
        with self._termination_lock:
            self._unresolved[recovery.recovery_id] = recovery
            self._recovery_leases[recovery.recovery_id] = leases
        if isinstance(active_error, HostExecutionError):
            active_error.outcome = ExecutionOutcome.INDETERMINATE
            active_error.recovery = recovery
            return
        if receipt is not None:
            raise HostExecutionError(
                f"host:worker_termination_unconfirmed:{recovery.recovery_id}",
                receipt,
                ExecutionOutcome.INDETERMINATE,
                recovery=recovery,
            )
        if active_error is None:
            raise HostExecutionDenied("host:worker_termination_unconfirmed")

    def _worker_command(
        self,
        plan: AdapterPlan,
        spec: LinuxToolSpec,
        runtime: RuntimeDeployment | None,
    ) -> tuple[list[str], tuple[int, ...], int, int, Path]:
        mounts = tuple(plan.payload.get("mounts", ()))
        environment = _plain_mapping(plan.payload.get("environment", {}))
        expected_environment = {
            "PATH": "/usr/bin",
            "PYTHONCOERCECLOCALE": "0",
            "PYTHONDONTWRITEBYTECODE": "1",
            "PYTHONNOUSERSITE": "1",
            "PYTHONSAFEPATH": "1",
            "PYTHONUNBUFFERED": "1",
            "PYTHONUTF8": "1",
        }
        protocol = set(plan.payload.get("protocol", ()))
        limits = _plain_mapping(plan.payload.get("limits", {}))
        if environment != expected_environment or protocol != {
            "parent-request-pipe",
            "parent-response-pipe",
            "parent-diagnostic-pipe",
        }:
            raise HostExecutionDenied("host:invalid_runtime_baseline")
        if set(limits) != _SUPPORTED_LIMITS or any(
            type(value) is not int or value <= 0 for value in limits.values()
        ):
            raise HostExecutionDenied("host:invalid_resource_limits")
        descriptors: list[int] = []
        mount_args: list[str] = []
        destinations: set[str] = set()
        owned_fds: set[int] = set()
        artifact_directory: Path | None = None
        try:
            artifact_descriptor, artifact_directory = _verified_artifact_fd(spec)
            owned_fds.add(artifact_descriptor)
            if runtime is not None:
                runtime_root = runtime.checkout_path
                for child in sorted(runtime_root.iterdir(), key=lambda item: item.name):
                    if child.name == "runtime.json":
                        continue
                    if child.name in {"dev", "proc", "sys", "tmp"}:
                        raise HostExecutionDenied("host:reserved_runtime_root")
                    if not child.is_dir() or child.is_symlink():
                        raise HostExecutionDenied("host:invalid_runtime_root")
                    descriptor = _verified_resource_fd(child)
                    owned_fds.add(descriptor)
                    descriptors.append(descriptor)
                    destination = f"/{child.name}"
                    destinations.add(destination)
                    mount_args.extend(["--ro-bind-fd", str(descriptor), destination])
            ordered_mounts = sorted(
                mounts,
                key=lambda item: (
                    os.fspath(item.get("path", "")).count("/")
                    if isinstance(item, Mapping)
                    else 0,
                    os.fspath(item.get("path", ""))
                    if isinstance(item, Mapping)
                    else "",
                ),
            )
            for raw in ordered_mounts:
                if not isinstance(raw, Mapping):
                    raise HostExecutionDenied("host:invalid_native_plan")
                path = os.fspath(raw.get("path", ""))
                mode = str(raw.get("mode", ""))
                if mode not in {"ro", "rw"}:
                    raise HostExecutionDenied("host:invalid_native_plan")
                if path == "/tmp":
                    continue
                canonical = _canonical_existing_path(path)
                if os.fspath(canonical) != path:
                    raise HostExecutionDenied("host:noncanonical_mount")
                if canonical.is_dir() and _nested_mount_points(canonical):
                    raise HostExecutionDenied("host:nested_mount_changed")
                if path == "/dev/urandom":
                    destinations.add(path)
                    mount_args.extend(["--dev-bind", path, path])
                    continue
                if runtime is not None and (
                    canonical == runtime.checkout_path
                    or runtime.checkout_path in canonical.parents
                ):
                    continue
                descriptor = (
                    artifact_descriptor
                    if canonical == spec.artifact_path
                    else _verified_resource_fd(canonical)
                )
                owned_fds.add(descriptor)
                if descriptor not in descriptors:
                    descriptors.append(descriptor)
                destinations.add(path)
                mount_args.extend(
                    [
                        "--bind-fd" if mode == "rw" else "--ro-bind-fd",
                        str(descriptor),
                        path,
                    ]
                )
            directories = sorted(
                {
                    parent
                    for destination in destinations
                    for parent in _missing_parent_directories(destination)
                },
                key=lambda value: (value.count("/"), value),
            )
            status_read, status_write = os.pipe2(os.O_CLOEXEC)
            owned_fds.update((status_read, status_write))
            command = [
                self.bubblewrap_path,
                "--unshare-all",
                "--unshare-user",
                "--die-with-parent",
                "--new-session",
                "--disable-userns",
                "--assert-userns-disabled",
                "--clearenv",
                "--cap-drop",
                "ALL",
            ]
            if runtime is None:
                command.extend(
                    [
                        "--ro-bind",
                        "/usr",
                        "/usr",
                        "--symlink",
                        "usr/bin",
                        "/bin",
                        "--symlink",
                        "usr/lib",
                        "/lib",
                        "--symlink",
                        "usr/lib64",
                        "/lib64",
                    ]
                )
            command.extend(
                [
                    "--size",
                    str(limits["tmpfs_bytes"]),
                    "--tmpfs",
                    "/tmp",
                ]
            )
            for directory in directories:
                command.extend(["--dir", directory])
            command.extend(mount_args)
            for name, value in sorted(environment.items()):
                command.extend(["--setenv", name, str(value)])
            command.extend(
                [
                    "--chdir",
                    "/tmp",
                    "--json-status-fd",
                    str(status_write),
                    "--",
                    os.fspath(
                        runtime.guest_interpreter_path
                        if runtime is not None
                        else self.python_executable
                    ),
                    "-I",
                    "-S",
                    "-B",
                    "-u",
                    "-X",
                    "utf8",
                    os.fspath(self._worker_script),
                ]
            )
            if artifact_descriptor not in descriptors:
                # Unused copies must not become unnecessary inherited authority.
                owned_fds.remove(artifact_descriptor)
                os.close(artifact_descriptor)
            return (
                command,
                tuple(descriptors),
                status_read,
                status_write,
                artifact_directory,
            )
        except BaseException:
            # Setup has not transferred ownership to _run_worker. Close each
            # acquired handle once, then remove the private copy; an individual
            # cleanup failure must not skip the remaining resources or replace
            # the original setup exception. Never retry a Linux close by number.
            for descriptor in owned_fds:
                try:
                    os.close(descriptor)
                except BaseException:
                    pass
            if artifact_directory is not None:
                try:
                    _remove_private_artifact(artifact_directory)
                except BaseException:
                    pass
            raise


class _LinuxBubblewrapAdapter:
    """Exact-obligation adapter used by `LinuxSandboxExecutor`."""

    def __init__(
        self,
        bwrap_path: str,
        key: bytes,
        python_executable: Path,
        worker_script: Path,
        lease_s: float,
        integrity_recheck: IntegrityRecheckMode,
        integrity_chunk_bytes: int,
        integrity_samples: int,
    ) -> None:
        self.bwrap_path = bwrap_path
        self._key = key
        self._pending: dict[str, str] = {}
        self._lock = RLock()
        self._boot_id = Path("/proc/sys/kernel/random/boot_id").read_text().strip()
        self._binary_digest = _file_digest(Path(bwrap_path))
        self._python_executable = python_executable
        self._python_digest = _file_digest(python_executable)
        self._worker_script = worker_script
        self._worker_digest = _file_digest(worker_script)
        self._integrity_recheck = integrity_recheck
        self._integrity_chunk_bytes = integrity_chunk_bytes
        self._integrity_samples = integrity_samples
        self._merkle_commitments = (
            {
                "bubblewrap": _merkle_commitment(
                    Path(bwrap_path), integrity_chunk_bytes
                ),
                "interpreter": _merkle_commitment(
                    python_executable, integrity_chunk_bytes
                ),
                "worker": _merkle_commitment(worker_script, integrity_chunk_bytes),
            }
            if integrity_recheck is IntegrityRecheckMode.MERKLE_SAMPLE
            else {}
        )
        self._lease_s = lease_s
        self._capability_probe = probe_linux_capabilities()

    @property
    def adapter_id(self) -> str:
        """Return the versioned Linux adapter identity."""
        return _ADAPTER_ID

    @property
    def python_digest(self) -> str:
        """Return the interpreter digest authenticated by this adapter."""
        return self._python_digest

    def attest(self, nonce: str) -> HostAttestation:
        """Return fresh locally authenticated host evidence."""
        artifacts = {
            "bubblewrap": (
                Path(self.bwrap_path),
                self._binary_digest,
                "bubblewrap_changed",
            ),
            "interpreter": (
                self._python_executable,
                self._python_digest,
                "interpreter_changed",
            ),
            "worker": (
                self._worker_script,
                self._worker_digest,
                "worker_shim_changed",
            ),
        }
        if self._integrity_recheck is IntegrityRecheckMode.FULL:
            for _name, (path, expected, reason) in artifacts.items():
                if _file_digest(path) != expected:
                    raise HostExecutionDenied(f"host:{reason}")
        elif self._integrity_recheck is IntegrityRecheckMode.MERKLE_SAMPLE:
            for name, (path, _expected, _reason) in artifacts.items():
                if not _verify_merkle_sample(
                    path,
                    self._merkle_commitments[name],
                    self._integrity_samples,
                ):
                    raise HostExecutionDenied(f"host:{name}_sample_changed")
        now = time.time()
        attestation = HostAttestation(
            "slanggraph-local-linux",
            nonce,
            self._boot_id,
            "linux",
            now,
            now + self._lease_s,
            frozenset(
                {
                    "bubblewrap",
                    "filesystem",
                    "namespace:no-network",
                    "resource-limits",
                    "seccomp:minimal",
                }
                | set(self._capability_probe.capabilities)
            ),
            _namespace_links(os.getpid()),
            {
                "adapter": self.adapter_id,
                "bubblewrap_digest": self._binary_digest,
                "capability_probe": dict(self._capability_probe.evidence),
                "enforcement_mechanism": "bubblewrap+seccomp+rlimit",
                "kernel": platform.release(),
                "landlock_abi": self._capability_probe.landlock_abi,
                "python_digest": self._python_digest,
                "worker_digest": self._worker_digest,
                "integrity_recheck": {
                    "chunk_bytes": self._integrity_chunk_bytes,
                    "merkle_roots": {
                        name: commitment.root
                        for name, commitment in self._merkle_commitments.items()
                    },
                    "merkle_sizes": {
                        name: commitment.size
                        for name, commitment in self._merkle_commitments.items()
                    },
                    "mode": self._integrity_recheck.value,
                    "samples": self._integrity_samples,
                },
            },
            "pending",
        )
        return replace(attestation, signature=self._sign(attestation.digest))

    def verify(self, attestation: HostAttestation) -> bool:
        """Verify local host evidence against this executor's trust key."""
        return (
            attestation.issuer == "slanggraph-local-linux"
            and attestation.boot_id == self._boot_id
            and hmac.compare_digest(
                attestation.signature, self._sign(attestation.digest)
            )
        )

    def assess(
        self, obligation: EnforcementObligation, host: HostAttestation
    ) -> SupportAssessment:
        """Report support only for guarantees this backend actually activates."""
        support = SupportLevel.UNSUPPORTED
        reason = "linux_adapter_unsupported"
        if obligation.kind is ObligationKind.DENY_COMPLEMENT:
            support = SupportLevel.EXACT
            reason = "isolated_empty_authority_domain"
        elif obligation.domain in {AuthorityDomain.FILESYSTEM, AuthorityDomain.RUNTIME}:
            if obligation.operation == "environment":
                support = SupportLevel.EXACT
                reason = "clearenv_explicit_value"
            else:
                support, reason = _assess_path_obligation(obligation)
        elif (
            obligation.domain is AuthorityDomain.IPC
            and obligation.operation in {"read", "write"}
            and obligation.selector
            in {
                "parent-request-pipe",
                "parent-response-pipe",
                "parent-diagnostic-pipe",
            }
        ):
            support = SupportLevel.EXACT
            reason = "explicit_protocol_descriptor"
        elif (
            obligation.domain is AuthorityDomain.PROCESS
            and obligation.operation == "syscall_set"
            and obligation.selector == "minimal"
        ):
            support = SupportLevel.EXACT
            reason = "seccomp_minimal"
        elif (
            obligation.domain is AuthorityDomain.RESOURCE_LIMIT
            and obligation.kind is ObligationKind.RESOURCE_LIMIT
        ):
            support, reason = _assess_limit_obligation(obligation)
        return SupportAssessment(
            self.adapter_id,
            obligation.obligation_id,
            support,
            reason,
            ("worker_namespace", "activation_receipt")
            if support is not SupportLevel.UNSUPPORTED
            else (),
        )

    def lower(
        self,
        grant: Grant,
        obligations: Sequence[EnforcementObligation],
        host: HostAttestation,
    ) -> AdapterPlan:
        """Compile assigned obligations into stable mounts and resource limits."""
        del host
        rules = {rule.rule_id: rule for rule in grant.rules}
        path_rules = [
            rules[item.rule_id]
            for item in obligations
            if item.kind is ObligationKind.OPERATE
            and (
                item.domain is AuthorityDomain.FILESYSTEM
                or (
                    item.domain is AuthorityDomain.RUNTIME
                    and item.operation in {"read", *_WRITE_OPERATIONS}
                )
            )
        ]
        operations: dict[tuple[AuthorityDomain, str], set[str]] = {}
        for rule in path_rules:
            operations.setdefault((rule.domain, rule.selector), set()).add(
                rule.operation
            )
        for (domain, selector), granted in operations.items():
            if domain is AuthorityDomain.RUNTIME:
                continue
            required = {"read", "write", "truncate"}
            path = _canonical_existing_path(selector)
            if path.is_dir():
                required.update({"create", "delete"})
            if granted.intersection(_WRITE_OPERATIONS) and not required.issubset(
                granted
            ):
                raise ValueError(f"inexact_writable_mount:{selector}")
        mounts: dict[str, str] = {}
        subtrees: dict[str, bool] = {}
        for rule in path_rules:
            mode = "rw" if rule.operation in _WRITE_OPERATIONS | {"write"} else "ro"
            prior = mounts.get(rule.selector)
            mounts[rule.selector] = "rw" if "rw" in {prior, mode} else "ro"
            subtrees[rule.selector] = bool(rule.conditions.get("subtree"))
        limits: dict[str, int] = {}
        for item in obligations:
            if item.kind is ObligationKind.RESOURCE_LIMIT:
                maximum = item.conditions.get("maximum")
                if not isinstance(maximum, int) or maximum <= 0:
                    raise ValueError(f"invalid_resource_limit:{item.obligation_id}")
                prior_limit = limits.get(item.selector)
                limits[item.selector] = (
                    maximum if prior_limit is None else min(prior_limit, maximum)
                )
        environment = {
            rules[item.rule_id].selector: str(
                rules[item.rule_id].conditions.get("value", "")
            )
            for item in obligations
            if item.kind is ObligationKind.OPERATE
            and item.domain is AuthorityDomain.RUNTIME
            and item.operation == "environment"
        }
        protocol = sorted(
            rules[item.rule_id].selector
            for item in obligations
            if item.kind is ObligationKind.OPERATE
            and item.domain is AuthorityDomain.IPC
        )
        payload = {
            "environment": environment,
            "limits": limits,
            "mounts": [
                {"mode": mounts[path], "path": path, "subtree": subtrees[path]}
                for path in sorted(mounts)
            ],
            "network": "isolated",
            "protocol": protocol,
            "seccomp": "minimal",
        }
        native_digest = _digest(payload)
        return AdapterPlan(
            self.adapter_id,
            frozenset(item.obligation_id for item in obligations),
            native_digest,
            payload,
        )

    def register_pending(self, plan: AdapterPlan, context: ExecutionContext) -> None:
        """Bind one started-but-blocked worker to its native plan."""
        with self._lock:
            self._pending[context.digest] = plan.native_plan_digest

    def activate(
        self, plan: AdapterPlan, context: ExecutionContext, nonce: str
    ) -> ActivationEvidence:
        """Consume a blocked worker registration and sign activation evidence."""
        with self._lock:
            pending = self._pending.pop(context.digest, None)
        if pending != plan.native_plan_digest:
            raise ValueError("Linux worker was not started with this native plan")
        now = time.time()
        evidence = ActivationEvidence(
            self.adapter_id,
            plan.native_plan_digest,
            context.digest,
            nonce,
            plan.obligation_ids,
            now,
            now + self._lease_s,
            "pending",
        )
        return replace(evidence, signature=self._sign(_activation_payload(evidence)))

    def verify_activation(self, evidence: ActivationEvidence) -> bool:
        """Verify worker-bound activation evidence."""
        return hmac.compare_digest(
            evidence.signature, self._sign(_activation_payload(evidence))
        )

    def _sign(self, value: str) -> str:
        return hmac.new(self._key, value.encode(), hashlib.sha256).hexdigest()


def _assess_path_obligation(
    obligation: EnforcementObligation,
) -> tuple[SupportLevel, str]:
    if obligation.kind is not ObligationKind.OPERATE:
        return SupportLevel.UNSUPPORTED, "path_obligation_kind_unsupported"
    if obligation.operation not in {"read", *_WRITE_OPERATIONS}:
        return SupportLevel.UNSUPPORTED, "path_operation_unsupported"
    if obligation.conditions.get("exclude_paths") or obligation.conditions.get(
        "exclude_subtrees"
    ):
        return SupportLevel.UNSUPPORTED, "path_exclusion_requires_broker"
    try:
        path = _canonical_existing_path(obligation.selector)
    except (OSError, ValueError):
        return SupportLevel.UNSUPPORTED, "path_missing_or_noncanonical"
    if (
        obligation.domain is AuthorityDomain.RUNTIME
        and obligation.operation == "read"
        and path == Path("/dev/urandom")
    ):
        return SupportLevel.EXACT, "stable_urandom_bind_mount"
    if not _is_supported_mount_type(path):
        return SupportLevel.UNSUPPORTED, "special_file_requires_broker"
    if path.is_dir() and not bool(obligation.conditions.get("subtree")):
        return SupportLevel.UNSUPPORTED, "exact_directory_requires_broker"
    if path.is_dir() and _nested_mount_points(path):
        return SupportLevel.UNSUPPORTED, "nested_mount_requires_separate_grants"
    return SupportLevel.EXACT, "stable_bind_mount"


def _assess_limit_obligation(
    obligation: EnforcementObligation,
) -> tuple[SupportLevel, str]:
    maximum = obligation.conditions.get("maximum")
    if type(maximum) is not int or maximum <= 0:
        return SupportLevel.UNSUPPORTED, "invalid_resource_limit"
    if obligation.selector not in _SUPPORTED_LIMITS:
        return SupportLevel.UNSUPPORTED, "resource_limit_mechanism_unsupported"
    if obligation.selector == "cpu_ms" and maximum % 1000:
        return SupportLevel.UNSUPPORTED, "rlimit_cpu_requires_whole_seconds"
    if obligation.selector == "pids" and maximum != 1:
        return SupportLevel.UNSUPPORTED, "minimal_seccomp_supports_pids_one_only"
    mechanism = {
        "address_space_bytes": "rlimit_as",
        "cpu_ms": "rlimit_cpu",
        "file_size_bytes": "rlimit_fsize_per_file",
        "nofile": "rlimit_nofile",
        "pids": "seccomp_no_process_creation",
        "tmpfs_bytes": "private_tmpfs_aggregate_size",
        "wall_ms": "supervisor_deadline_and_termination",
    }[obligation.selector]
    return SupportLevel.EXACT, mechanism


def _verified_artifact_fd(spec: LinuxToolSpec) -> tuple[int, Path]:
    """Copy verified artifact bytes into a sealed, worker-bound file."""
    directory = Path(tempfile.mkdtemp(prefix="slanggraph-artifact-"))
    try:
        directory.chmod(0o700)
        artifact = directory / "artifact.py"
        digest = hashlib.sha256()
        with spec.artifact_path.open("rb") as source, artifact.open("xb") as target:
            for chunk in iter(lambda: source.read(1024 * 1024), b""):
                digest.update(chunk)
                target.write(chunk)
            target.flush()
            os.fsync(target.fileno())
        if digest.hexdigest() != spec.artifact_digest:
            raise HostExecutionDenied("host:artifact_changed")
        artifact.chmod(0o400)
        return (
            os.open(artifact, os.O_PATH | os.O_CLOEXEC | os.O_NOFOLLOW),
            directory,
        )
    except BaseException:
        try:
            _remove_private_artifact(directory)
        except BaseException:
            pass
        raise


def _verified_resource_fd(path: Path) -> int:
    """Open and identity-bind one canonical host resource for a worker mount."""
    # O_NOFOLLOW alone protects only the final component. Resolve every
    # component without symlinks, including after the earlier canonical check.
    descriptor = open_path_descriptor(os.fspath(path), no_symlinks=True)
    try:
        opened = os.fstat(descriptor)
        current = os.stat(path, follow_symlinks=False)
        if (
            opened.st_dev,
            opened.st_ino,
            stat.S_IFMT(opened.st_mode),
        ) != (
            current.st_dev,
            current.st_ino,
            stat.S_IFMT(current.st_mode),
        ):
            raise HostExecutionDenied("host:resource_identity_changed")
        if not (stat.S_ISREG(opened.st_mode) or stat.S_ISDIR(opened.st_mode)):
            raise HostExecutionDenied("host:special_resource_unsupported")
        return descriptor
    except BaseException:
        try:
            os.close(descriptor)
        except BaseException:
            pass
        raise


def _remove_private_artifact(directory: Path) -> None:
    artifact = directory / "artifact.py"
    if artifact.exists():
        artifact.unlink()
    directory.rmdir()


def _wall_timeout(payload: Mapping[str, Any], default: float) -> float:
    limits = payload.get("limits", {})
    if isinstance(limits, Mapping):
        value = limits.get("wall_ms")
        if isinstance(value, int) and value > 0:
            return value / 1000
    return default


def _execution_context(pid: int) -> ExecutionContext:
    status = Path(f"/proc/{pid}/status").read_text()
    fields = {
        name: value.strip()
        for line in status.splitlines()
        if ":" in line
        for name, value in (line.split(":", 1),)
    }
    if (
        fields.get("NoNewPrivs") != "1"
        or fields.get("Seccomp") != "2"
        or fields.get("Threads") != "1"
        or any(
            fields.get(name) != "0000000000000000"
            for name in ("CapAmb", "CapBnd", "CapEff", "CapInh", "CapPrm")
        )
    ):
        raise HostExecutionDenied("host:kernel_activation_state_invalid")
    credential_lines = [
        line
        for line in status.splitlines()
        if line.startswith(
            ("Uid:", "Gid:", "Cap", "NoNewPrivs:", "Seccomp:", "Threads:")
        )
    ]
    start_time = _process_start_time(pid)
    cgroup = Path(f"/proc/{pid}/cgroup").read_text().strip() or "isolated"
    boot_id = Path("/proc/sys/kernel/random/boot_id").read_text().strip()
    namespaces = _namespace_links(pid)
    parent_namespaces = _namespace_links(os.getpid())
    if any(namespaces[name] == parent_namespaces[name] for name in namespaces):
        raise HostExecutionDenied("host:namespace_activation_state_invalid")
    mountinfo_digest = hashlib.sha256(
        Path(f"/proc/{pid}/mountinfo").read_bytes()
    ).hexdigest()
    return ExecutionContext(
        worker_id=f"linux-worker:{pid}:{start_time}",
        process_identity=f"pid:{pid}:start:{start_time}",
        boot_id=boot_id,
        namespaces=namespaces,
        credential_digest=_digest(
            {"mountinfo_digest": mountinfo_digest, "status": credential_lines}
        ),
        cgroup_id=cgroup,
        broker_epoch="no-broker",
    )


def _namespace_links(pid: int) -> Mapping[str, str]:
    namespace_root = Path(f"/proc/{pid}/ns")
    names = ("cgroup", "ipc", "mnt", "net", "pid", "user", "uts")
    return {name: os.readlink(namespace_root / name) for name in names}


def _activation_payload(evidence: ActivationEvidence) -> str:
    return _digest(
        {
            "activated_at": evidence.activated_at,
            "adapter_id": evidence.adapter_id,
            "context_digest": evidence.context_digest,
            "expires_at": evidence.expires_at,
            "native_plan_digest": evidence.native_plan_digest,
            "nonce": evidence.nonce,
            "obligation_ids": sorted(evidence.obligation_ids),
        }
    )


def _read_fd_json(descriptor: int, timeout: float) -> Mapping[str, Any]:
    deadline = time.monotonic() + timeout
    payload = bytearray()
    while len(payload) < 16_384:
        remaining = deadline - time.monotonic()
        if remaining <= 0:
            raise TimeoutError
        ready, _, _ = select.select([descriptor], [], [], remaining)
        if not ready:
            raise TimeoutError
        chunk = os.read(descriptor, 16_384 - len(payload))
        if not chunk:
            break
        payload.extend(chunk)
        try:
            value = json.loads(payload)
        except json.JSONDecodeError:
            continue
        if not isinstance(value, dict):
            raise ValueError("invalid bubblewrap status")
        return value
    raise ValueError("invalid bubblewrap status")


def _readline_json(
    process: subprocess.Popen[bytes], timeout: float
) -> Mapping[str, Any]:
    if process.stdout is None:
        raise ValueError("worker stdout is unavailable")
    # A readable pipe may contain only part of a frame. Keep the deadline
    # across reads so a worker cannot defeat its timeout by sending one byte.
    deadline = time.monotonic() + timeout
    line = bytearray()
    descriptor = process.stdout.fileno()
    while b"\n" not in line and len(line) <= _MAX_FRAME:
        remaining = deadline - time.monotonic()
        if remaining <= 0:
            raise TimeoutError
        ready, _, _ = select.select([descriptor], [], [], remaining)
        if not ready:
            raise TimeoutError
        # Each phase permits one frame; coalesced extra frames fail JSON
        # validation. stdout is an unbuffered pipe created by _run_worker.
        chunk = os.read(descriptor, min(65536, _MAX_FRAME + 1 - len(line)))
        if not chunk:
            break
        line.extend(chunk)
    if not line or len(line) > _MAX_FRAME or not line.endswith(b"\n"):
        raise ValueError("invalid worker protocol frame")
    value = json.loads(line)
    if not isinstance(value, dict):
        raise ValueError("invalid worker protocol frame")
    _validate_protocol_shape(value)
    return value


def _encode_worker_request(request: Mapping[str, Any]) -> bytes:
    encoded = (
        json.dumps(request, sort_keys=True, separators=(",", ":")).encode() + b"\n"
    )
    if len(encoded) > _MAX_FRAME:
        raise ValueError("worker request exceeds protocol limit")
    return encoded


def _validate_protocol_shape(value: object) -> None:
    stack = [(value, 0)]
    nodes = 0
    while stack:
        item, depth = stack.pop()
        nodes += 1
        if depth > _MAX_PROTOCOL_DEPTH or nodes > _MAX_PROTOCOL_NODES:
            raise ValueError("worker response exceeds structural limits")
        if isinstance(item, dict):
            stack.extend((child, depth + 1) for child in item.values())
        elif isinstance(item, list):
            stack.extend((child, depth + 1) for child in item)


def _process_start_time(pid: int) -> str:
    # /proc/PID/stat's comm field is parenthesized but may itself contain spaces,
    # newlines or ')'. The fields after its final ')' have fixed numeric offsets.
    record = Path(f"/proc/{pid}/stat").read_text()
    prefix, separator, tail = record.rpartition(")")
    fields = tail.split()
    if (
        not separator
        or not prefix.startswith(f"{pid} (")
        or len(fields) < 20
        or not fields[19].isascii()
        or not fields[19].isdigit()
    ):
        raise ValueError("host:invalid_process_identity")
    return fields[19]


def _open_worker_pidfd(pid: int) -> int:
    # Some CPython builds omit pidfd wrappers; use the same Linux libc API.
    operation = ctypes.CDLL(None, use_errno=True).pidfd_open
    operation.argtypes = [ctypes.c_int, ctypes.c_uint]
    operation.restype = ctypes.c_int
    descriptor = operation(pid, 0)
    if descriptor < 0:
        error = ctypes.get_errno()
        raise OSError(error, os.strerror(error))
    return descriptor


def _kill_worker_pidfd(descriptor: int) -> None:
    operation = ctypes.CDLL(None, use_errno=True).pidfd_send_signal
    operation.argtypes = [
        ctypes.c_int,
        ctypes.c_int,
        ctypes.c_void_p,
        ctypes.c_uint,
    ]
    operation.restype = ctypes.c_int
    if operation(descriptor, 9, None, 0) < 0:
        error = ctypes.get_errno()
        raise OSError(error, os.strerror(error))


def _confirm_worker_terminated(pid: int, start_time: str, *, timeout_s: float) -> bool:
    """Confirm the observed worker's exit without signaling a reusable PID.

    Acquire a kernel process handle before rechecking the recorded start time.
    A replacement identity is never signaled. After the check, even an exit and
    PID reuse cannot retarget a signal sent through the acquired handle. This
    still relies on the controller's original PID/start-time observation.
    """
    descriptor = None
    deadline = time.monotonic() + timeout_s
    try:
        descriptor = _open_worker_pidfd(pid)
        if _process_start_time(pid) != start_time:
            return True
        _kill_worker_pidfd(descriptor)
        poller = select.poll()
        poller.register(descriptor, select.POLLIN)
        while True:
            remaining = max(0.0, deadline - time.monotonic())
            events = poller.poll(int(remaining * 1000))
            if events:
                # POLLNVAL/POLLERR alone cannot certify process exit.
                return any(
                    fd == descriptor and flags & select.POLLIN for fd, flags in events
                )
            if time.monotonic() >= deadline:
                return False
    except (FileNotFoundError, ProcessLookupError):
        return True
    except (AttributeError, OSError, ValueError):
        # No numeric-PID fallback: missing APIs or uncertain identity/exit retain
        # the caller's recovery lease instead of certifying cleanup.
        return False
    finally:
        if descriptor is not None:
            os.close(descriptor)


def _sandbox_payload_pid(init_pid: int, *, timeout_s: float) -> int:
    children_path = Path(f"/proc/{init_pid}/task/{init_pid}/children")
    deadline = time.monotonic() + timeout_s
    while time.monotonic() < deadline:
        try:
            children = children_path.read_text().split()
        except FileNotFoundError as exc:
            raise HostExecutionDenied("host:sandbox_init_exited") from exc
        if len(children) == 1:
            return int(children[0])
        if len(children) > 1:
            raise HostExecutionDenied("host:ambiguous_worker_identity")
        time.sleep(0.01)
    raise HostExecutionDenied("host:worker_identity_timeout")


def _canonical_existing_path(value: str | Path) -> Path:
    raw = Path(value)
    if not raw.is_absolute():
        raise ValueError("sandbox paths must be absolute")
    resolved = raw.resolve(strict=True)
    if raw != resolved:
        raise ValueError("sandbox paths must be canonical and symlink-free")
    return resolved


def _is_supported_mount_type(path: Path) -> bool:
    mode = path.stat(follow_symlinks=False).st_mode
    return stat.S_ISREG(mode) or stat.S_ISDIR(mode)


def _nested_mount_points(path: Path) -> tuple[Path, ...]:
    nested: list[Path] = []
    for line in Path("/proc/self/mountinfo").read_text().splitlines():
        fields = line.split()
        if len(fields) < 5:
            raise HostExecutionDenied("host:mountinfo_invalid")
        value = fields[4]
        for encoded, decoded in (
            ("\\040", " "),
            ("\\011", "\t"),
            ("\\012", "\n"),
            ("\\134", "\\"),
        ):
            value = value.replace(encoded, decoded)
        mount = Path(value)
        if mount != path and path in mount.parents:
            nested.append(mount)
    return tuple(sorted(nested))


def _verify_bubblewrap_host(bwrap_path: str, timeout: float) -> None:
    """Fail configuration unless the installed host can create our boundary."""
    try:
        help_result = subprocess.run(
            (bwrap_path, "--help"),
            check=True,
            capture_output=True,
            text=True,
            timeout=timeout,
        )
        help_text = help_result.stdout + help_result.stderr
        required = {
            "--assert-userns-disabled",
            "--bind-fd",
            "--disable-userns",
            "--json-status-fd",
            "--ro-bind-fd",
        }
        if not required.issubset(help_text.split()):
            raise RuntimeError("bubblewrap lacks required file-descriptor features")
        probe = subprocess.run(
            (
                bwrap_path,
                "--unshare-all",
                "--unshare-user",
                "--die-with-parent",
                "--new-session",
                "--disable-userns",
                "--assert-userns-disabled",
                "--clearenv",
                "--cap-drop",
                "ALL",
                "--ro-bind",
                "/",
                "/",
                "--",
                "/usr/bin/true",
            ),
            check=False,
            capture_output=True,
            text=True,
            timeout=timeout,
        )
    except (OSError, subprocess.SubprocessError) as exc:
        raise RuntimeError("bubblewrap host preflight failed") from exc
    if probe.returncode != 0:
        raise RuntimeError("bubblewrap isolation is unavailable on this host")


def _missing_parent_directories(value: str) -> tuple[str, ...]:
    path = Path(value)
    parents: list[str] = []
    for parent in reversed(path.parents):
        text = os.fspath(parent)
        if text in {"/", "/usr"} or text.startswith("/usr/"):
            continue
        parents.append(text)
    if path.is_dir():
        parents.append(value)
    return tuple(dict.fromkeys(parents))


def _plain_mapping(value: object) -> dict[str, Any]:
    if not isinstance(value, Mapping):
        raise ValueError("expected mapping")
    return {str(key): _json_value(item) for key, item in value.items()}


def _json_value(value: object) -> Any:
    if value is None or type(value) in {bool, int, float, str}:
        return value
    if isinstance(value, list | tuple) and type(value) in {list, tuple}:
        return [_json_value(item) for item in value]
    if isinstance(value, Mapping) and type(value) in {dict, MappingProxyType}:
        if any(type(key) is not str for key in value):
            raise ValueError("sandbox mappings require string keys")
        return {key: _json_value(item) for key, item in value.items()}
    raise ValueError(f"sandbox protocol cannot encode {type(value).__name__}")


def _file_digest(path: Path) -> str:
    digest = hashlib.sha256()
    with path.open("rb") as stream:
        for chunk in iter(lambda: stream.read(1024 * 1024), b""):
            digest.update(chunk)
    return digest.hexdigest()


def _merkle_leaf(index: int, payload: bytes) -> bytes:
    return hashlib.sha256(
        b"\x00" + index.to_bytes(8, "big") + len(payload).to_bytes(8, "big") + payload
    ).digest()


def _merkle_parent(left: bytes, right: bytes) -> bytes:
    return hashlib.sha256(b"\x01" + left + right).digest()


def _merkle_commitment(path: Path, chunk_bytes: int) -> _MerkleCommitment:
    """Read an immutable candidate once and commit to every positioned chunk."""
    info = path.stat(follow_symlinks=False)
    if not stat.S_ISREG(info.st_mode):
        raise ValueError("Merkle integrity artifacts must be regular files")
    size = info.st_size
    leaves: list[bytes] = []
    with path.open("rb") as stream:
        for index, chunk in enumerate(iter(lambda: stream.read(chunk_bytes), b"")):
            leaves.append(_merkle_leaf(index, chunk))
    if not leaves:
        leaves.append(_merkle_leaf(0, b""))
    levels: list[tuple[bytes, ...]] = [tuple(leaves)]
    current = leaves
    while len(current) > 1:
        parents = [
            _merkle_parent(
                current[index],
                current[index + 1] if index + 1 < len(current) else current[index],
            )
            for index in range(0, len(current), 2)
        ]
        levels.append(tuple(parents))
        current = parents
    return _MerkleCommitment(size, chunk_bytes, tuple(levels))


def _verify_merkle_sample(
    path: Path, commitment: _MerkleCommitment, samples: int
) -> bool:
    """Verify unpredictable chunk samples against the preflight Merkle root.

    This is probabilistic tamper detection. It checks file size on every call,
    but an unsampled, same-size modification is not detected by that call.
    """
    try:
        info = path.stat(follow_symlinks=False)
        if not stat.S_ISREG(info.st_mode) or info.st_size != commitment.size:
            return False
        leaf_count = len(commitment.levels[0])
        selected = secrets.SystemRandom().sample(
            range(leaf_count), min(samples, leaf_count)
        )
        with path.open("rb") as stream:
            for selected_index in selected:
                stream.seek(selected_index * commitment.chunk_bytes)
                payload = stream.read(commitment.chunk_bytes)
                node = _merkle_leaf(selected_index, payload)
                if node != commitment.levels[0][selected_index]:
                    return False
                index = selected_index
                for level in commitment.levels[:-1]:
                    sibling_index = index - 1 if index % 2 else index + 1
                    sibling = (
                        level[sibling_index] if sibling_index < len(level) else node
                    )
                    node = (
                        _merkle_parent(sibling, node)
                        if index % 2
                        else _merkle_parent(node, sibling)
                    )
                    index //= 2
                if node.hex() != commitment.root:
                    return False
    except OSError:
        return False
    return True


def _prepared_authority_key(
    grant: Grant, obligations: Sequence[EnforcementObligation]
) -> str:
    """Identify policy inputs that may affect host-specific lowering.

    Invocation identity, session identity, and normalized intent remain freshly
    bound in the runtime grant. They are deliberately absent here because they
    cannot change the native host restrictions for an otherwise identical
    authority set.
    """
    return _digest(
        {
            "artifact": grant.artifact_digest,
            "deployment": grant.deployment_digest,
            "obligations": [
                item.canonical()
                for item in sorted(obligations, key=lambda value: value.obligation_id)
            ],
            "rules": [
                rule.canonical()
                for rule in sorted(grant.rules, key=lambda value: value.rule_id)
            ],
            "runtime": grant.runtime_digest,
            "tool": grant.tool_name,
        }
    )


def _host_configuration_digest(host: HostAttestation) -> str:
    """Digest stable host capabilities while excluding fresh attestation data."""
    return _digest(
        {
            "boot_id": host.boot_id,
            "capabilities": sorted(host.capabilities),
            "context": dict(host.context),
            "evidence": _plain_mapping(host.evidence),
            "issuer": host.issuer,
            "platform": host.platform,
        }
    )


def _digest(value: object) -> str:
    encoded = json.dumps(
        value, sort_keys=True, separators=(",", ":"), default=repr
    ).encode()
    return hashlib.sha256(encoded).hexdigest()
