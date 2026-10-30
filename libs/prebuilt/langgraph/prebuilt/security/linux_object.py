"""Cedar object grants lowered into the verified Linux sandbox route.

This adapter is deliberately narrow. It accepts only exact, canonical regular
file grants enforced by the kernel and constructs the Linux grant from those
object lines plus the executor's fixed runtime baseline. The tool never sees
the Cedar grant or any broader host path. Optional Lean checking observes the
same lowered grant that is activated before worker `GO`.
"""

from __future__ import annotations

import asyncio
import copy
import hashlib
import json
import os
import stat
import subprocess
from collections import deque
from collections.abc import Mapping, Sequence
from dataclasses import replace
from pathlib import Path
from threading import RLock
from types import MappingProxyType
from typing import Any

from langgraph.prebuilt.security.enforcement import (
    AuthorityDomain,
    Grant,
    GrantRule,
    RequirementEntry,
    RequirementLedger,
)
from langgraph.prebuilt.security.execution import (
    HostExecutionDenied,
    HostExecutionError,
    HostExecutionResult,
    TerminationRecovery,
)
from langgraph.prebuilt.security.lean_lifecycle import LeanLifecycleChecker
from langgraph.prebuilt.security.linux import (
    IntegrityRecheckMode,
    LinuxSandboxExecutor,
    LinuxToolSpec,
    _LinuxWorkerPoolState,
)
from langgraph.prebuilt.security.object_policy import (
    EnforcementKind,
    ObjectClass,
    ObjectGrant,
    ObjectGrantLine,
)
from langgraph.prebuilt.security.policy import TypedPolicyBackend
from langgraph.prebuilt.security.profile import parse_profiles
from langgraph.prebuilt.security.types import Principal, ToolCall


def _digest(value: Any) -> str:
    return hashlib.sha256(
        json.dumps(value, sort_keys=True, separators=(",", ":")).encode()
    ).hexdigest()


def _object_authority_key(grant: ObjectGrant) -> str:
    """Identify the complete static policy lowered into a pooled worker."""
    return _digest(
        {
            "lines": [
                line.canonical()
                for line in sorted(grant.lines, key=lambda item: item.line_id)
            ],
            "policy": grant.policy_digest,
            "tool": grant.tool_name,
            "waivers": dict(grant.enforcement_waivers),
        }
    )


def _exact_file(selector: str, operation: str) -> Path:
    """Return a canonical regular file; mutable grants also require one link."""
    if type(selector) is not str or not selector.startswith("/"):
        raise ValueError("file selector must be absolute")
    path = Path(selector)
    try:
        resolved = path.resolve(strict=True)
        info = path.lstat()
    except OSError as exc:
        raise ValueError("file selector is unavailable") from exc
    if (
        resolved != path
        or not stat.S_ISREG(info.st_mode)
        or (operation != "read" and info.st_nlink != 1)
        or os.fspath(path) != selector
    ):
        raise ValueError("file selector must be canonical and safely linked")
    return path


class _LinuxObjectWorker(LinuxSandboxExecutor):
    """Linux worker whose authority is constructed from one object grant."""

    def __init__(
        self,
        object_grant: ObjectGrant,
        *args: Any,
        prepared_rules: tuple[GrantRule, ...] | None = None,
        **kwargs: Any,
    ) -> None:
        self.object_grant = object_grant
        self.prepared_rules = prepared_rules
        self.lowered_grant: Grant | None = None
        super().__init__(*args, **kwargs)

    def _compile_grant(
        self,
        principal: Principal,
        call: ToolCall,
        spec: LinuxToolSpec,
        runtime: Any,
    ) -> tuple[Grant, RequirementLedger]:
        obj = self.object_grant
        if (
            obj.principal_id != principal.user_id
            or obj.tool_name != call.tool.name
            or obj.call_id != call.call_id
            or obj.enforcement_waivers
        ):
            raise HostExecutionDenied("linux_object:grant_binding")
        rules = self.prepared_rules
        if rules is None:
            rules = tuple(
                GrantRule(
                    line.line_id,
                    AuthorityDomain.FILESYSTEM,
                    line.operation,
                    os.fspath(_exact_file(line.selector, line.operation)),
                    {"exact_file": True},
                    line.requirement,
                    line.provenance,
                )
                for line in obj.lines
            )
            rules += self._baseline_rules(spec, runtime)
        grant = Grant(
            principal.user_id,
            principal.session_id,
            call.tool.name,
            spec.artifact_digest,
            call.call_id,
            _digest(
                {
                    "args": dict(call.args),
                    "normalized": dict(call.normalized),
                    "tool": call.tool.name,
                }
            ),
            obj.digest,
            rules,
            deployment_digest=(
                spec.deployment.binding.tool_commit
                if spec.deployment is not None
                else ""
            ),
            runtime_digest=(
                runtime.binding.runtime_commit if runtime is not None else ""
            ),
        )
        ledger = RequirementLedger(
            tuple(
                RequirementEntry(
                    rule.rule_id, rule.requirement, frozenset({rule.rule_id})
                )
                for rule in rules
            )
        )
        self.lowered_grant = grant
        return grant, ledger


class LinuxObjectDispatcher:
    """Lower exact Cedar filesystem grants into fresh bubblewrap workers.

    Runtime roots and tool artifacts are trusted code and must not contain
    secrets. Object selectors are exact existing regular files; mutable files
    must be unaliased. No network,
    service, credential, directory-subtree, or linked-path authority is
    supported; such configurations fail before tool execution.
    """

    enforcer_id = "linux-bubblewrap-object-v1"

    def __init__(
        self,
        tools: Mapping[str, LinuxToolSpec],
        *,
        runtime_roots: Sequence[str | Path],
        lifecycle_checker: LeanLifecycleChecker | None = None,
        wall_timeout_s: float = 30.0,
        worker_pool_capacity: int = 0,
        worker_pool_idle_s: float = 300.0,
        integrity_recheck: IntegrityRecheckMode | str = IntegrityRecheckMode.FULL,
        integrity_chunk_bytes: int = 65_536,
        integrity_samples: int = 4,
    ) -> None:
        copied = dict(tools)
        if not copied or any(
            type(item) is not LinuxToolSpec for item in copied.values()
        ):
            raise ValueError(
                "Linux object dispatcher requires pinned LinuxToolSpec artifacts"
            )
        if any(item.deployment is not None for item in copied.values()):
            raise ValueError(
                "Linux object dispatcher does not support deployment selection"
            )
        if type(lifecycle_checker) not in {LeanLifecycleChecker, type(None)}:
            raise TypeError("lifecycle_checker must be a LeanLifecycleChecker")
        if type(wall_timeout_s) not in {int, float} or wall_timeout_s <= 0:
            raise ValueError("wall_timeout_s must be positive")
        roots = tuple(Path(item).resolve() for item in runtime_roots)
        if not roots:
            raise ValueError("at least one runtime root is required")
        self.tools = MappingProxyType(copied)
        self.runtime_roots = roots
        self.lifecycle_checker = lifecycle_checker
        self.wall_timeout_s = float(wall_timeout_s)
        if (
            type(worker_pool_capacity) is not int
            or worker_pool_capacity < 0
            or worker_pool_idle_s <= 0
        ):
            raise ValueError("Linux object worker pool settings must be non-negative")
        self.worker_pool_capacity = worker_pool_capacity
        self.worker_pool_idle_s = float(worker_pool_idle_s)
        try:
            self.integrity_recheck = IntegrityRecheckMode(integrity_recheck)
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
        self.integrity_chunk_bytes = integrity_chunk_bytes
        self.integrity_samples = integrity_samples
        self._worker_pool_state = _LinuxWorkerPoolState()
        self._prepared_rules: dict[str, tuple[GrantRule, ...]] = {}
        self._prepared_workers: dict[str, _LinuxObjectWorker] = {}
        self._lock = RLock()
        self._receipts = deque(maxlen=1024)
        self._lowerings = deque(maxlen=1024)
        self._recoveries: dict[str, _LinuxObjectWorker] = {}

    def supports(self, object_class: ObjectClass, line: ObjectGrantLine) -> bool:
        if (
            object_class.name != "fs"
            or line.class_name != "fs"
            or line.operation not in {"read", "write", "truncate"}
            or line.enforcer is not EnforcementKind.KERNEL
            or line.lowering is not None
        ):
            return False
        try:
            _exact_file(line.selector, line.operation)
        except ValueError:
            return False
        return True

    def validate_tools(self, tool_names: Sequence[str]) -> None:
        missing = set(tool_names).difference(self.tools)
        if missing:
            raise ValueError(
                "Linux object dispatcher missing tool artifacts: "
                + ", ".join(sorted(missing))
            )

    def activation_receipts(self) -> tuple[Any, ...]:
        with self._lock:
            return tuple(self._receipts)

    def lowering_records(self) -> tuple[Mapping[str, Any], ...]:
        with self._lock:
            return tuple(MappingProxyType(dict(item)) for item in self._lowerings)

    def worker_pool_stats(self) -> Mapping[str, int]:
        """Return shared pool occupancy and claim counters."""
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
        grant: ObjectGrant,
        *,
        count: int = 1,
        asynchronous: bool = False,
    ) -> int:
        """Create exact-object workers during application preflight."""
        if count == 0:
            return 0
        worker = self._new_worker(principal, call, grant, preflight=True)
        prepared = worker.prewarm(
            principal, call, (), count=count, asynchronous=asynchronous
        )
        lowered = worker.lowered_grant
        if lowered is None:
            raise HostExecutionDenied("linux_object:preflight_lowering_missing")
        with self._lock:
            authority_key = _object_authority_key(grant)
            self._prepared_rules[authority_key] = lowered.rules
            self._prepared_workers[authority_key] = worker
        return prepared

    def close(self) -> None:
        """Terminate all idle shared workers."""
        state = self._worker_pool_state
        with state.lock:
            workers = [
                worker for entries in state.workers.values() for worker in entries
            ]
            state.workers.clear()
            state.prepared_policies.clear()
        with self._lock:
            self._prepared_rules.clear()
            self._prepared_workers.clear()
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

    def invoke(
        self, principal: Principal, call: ToolCall, grant: ObjectGrant
    ) -> HostExecutionResult:
        return self._invoke(principal, call, grant, asynchronous=False)

    def _invoke(
        self,
        principal: Principal,
        call: ToolCall,
        grant: ObjectGrant,
        *,
        asynchronous: bool,
    ) -> HostExecutionResult:
        worker = self._new_worker(principal, call, grant)
        try:
            result = worker._invoke(principal, call, (), asynchronous=asynchronous)
        except HostExecutionError as exc:
            exc.receipt = self._object_receipt(exc.receipt, grant)
            self._record(worker, grant, exc.receipt)
            if exc.recovery is not None:
                with self._lock:
                    self._recoveries[exc.recovery.recovery_id] = worker
            raise
        receipt = self._object_receipt(result.receipt, grant)
        self._record(worker, grant, receipt)
        return HostExecutionResult(result.value, receipt)

    def _new_worker(
        self,
        principal: Principal,
        call: ToolCall,
        grant: ObjectGrant,
        *,
        preflight: bool = False,
    ) -> _LinuxObjectWorker:
        if (
            grant.principal_id != principal.user_id
            or grant.tool_name != call.tool.name
            or grant.call_id != call.call_id
            or grant.enforcement_waivers
        ):
            raise HostExecutionDenied("linux_object:grant_binding")
        if call.tool.name not in self.tools:
            raise HostExecutionDenied("linux_object:tool_missing")
        authority_key = _object_authority_key(grant)
        with self._lock:
            prepared_rules = self._prepared_rules.get(authority_key)
            prepared_worker = self._prepared_workers.get(authority_key)
        identifiers = [line.line_id for line in grant.lines]
        if len(identifiers) != len(set(identifiers)):
            raise HostExecutionDenied("linux_object:unsupported_authority")
        if prepared_rules is None:
            if self.worker_pool_capacity and not preflight:
                raise HostExecutionDenied("linux_object:prepared_policy_missing")
            if any(
                not self.supports(
                    ObjectClass(
                        "fs",
                        frozenset({"read", "write", "truncate"}),
                        "path",
                        "fs.realpath",
                        enforced_by=EnforcementKind.KERNEL,
                    ),
                    line,
                )
                for line in grant.lines
            ):
                raise HostExecutionDenied("linux_object:unsupported_authority")
        elif prepared_worker is not None and not preflight:
            worker = copy.copy(prepared_worker)
            worker.object_grant = grant
            worker.prepared_rules = prepared_rules
            worker.lowered_grant = None
            return worker
        profiles = parse_profiles(
            f"tool {call.tool.name} {{\n owner object_dispatcher\n"
            " runs linux\n syscalls @minimal\n}\n",
            source="<linux-object-dispatcher>",
        )
        return _LinuxObjectWorker(
            grant,
            profiles,
            {call.tool.name: self.tools[call.tool.name]},
            prepared_rules=prepared_rules,
            runtime_roots=self.runtime_roots,
            policy_backend=TypedPolicyBackend(),
            default_wall_timeout_s=self.wall_timeout_s,
            lifecycle_checker=self.lifecycle_checker,
            worker_pool_capacity=self.worker_pool_capacity,
            worker_pool_idle_s=self.worker_pool_idle_s,
            integrity_recheck=self.integrity_recheck,
            integrity_chunk_bytes=self.integrity_chunk_bytes,
            integrity_samples=self.integrity_samples,
            _worker_pool_state=self._worker_pool_state,
        )

    def _record(
        self, worker: _LinuxObjectWorker, grant: ObjectGrant, receipt: Any
    ) -> None:
        lowered = worker.lowered_grant
        if lowered is None:
            raise HostExecutionDenied("linux_object:lowering_missing")
        with self._lock:
            self._receipts.append(receipt)
            self._lowerings.append(
                {
                    "object_grant_digest": grant.digest,
                    "native_grant_digest": lowered.digest,
                    "policy_digest": lowered.policy_digest,
                    "rules": [rule.canonical() for rule in lowered.rules],
                }
            )

    @staticmethod
    def _object_receipt(receipt: Any, grant: ObjectGrant) -> Any:
        identifiers = frozenset(line.line_id for line in grant.lines)
        return replace(
            receipt,
            grant_digest=grant.digest,
            activated_obligations=identifiers,
            rule_enforcement=tuple(
                item for item in receipt.rule_enforcement if item.rule_id in identifiers
            ),
        )

    async def ainvoke(
        self, principal: Principal, call: ToolCall, grant: ObjectGrant
    ) -> HostExecutionResult:
        execution = asyncio.create_task(
            asyncio.to_thread(self._invoke, principal, call, grant, asynchronous=True)
        )
        try:
            return await asyncio.shield(execution)
        except asyncio.CancelledError:
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
        with self._lock:
            worker = self._recoveries.get(recovery.recovery_id)
        if worker is None or not worker.confirm_termination(recovery):
            return False
        with self._lock:
            self._recoveries.pop(recovery.recovery_id, None)
        return True


__all__ = ["LinuxObjectDispatcher"]
