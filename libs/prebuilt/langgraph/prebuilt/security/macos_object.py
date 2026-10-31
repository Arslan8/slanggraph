"""Cedar object grants and semantic resource mediation in native Seatbelt workers."""

from __future__ import annotations

import asyncio
import json
import math
import secrets
import sys
from collections import deque
from collections.abc import Mapping
from dataclasses import fields, is_dataclass, replace
from enum import Enum
from pathlib import Path
from threading import RLock
from types import MappingProxyType, SimpleNamespace

from langgraph.prebuilt.security._object_landlock import _LandlockObjectAdapter
from langgraph.prebuilt.security.broker import SpawnRecord
from langgraph.prebuilt.security.enforcement import (
    AuthorityDomain,
    Grant,
    GrantRule,
    ObligationKind,
    RequirementEntry,
    RequirementLedger,
    SupportAssessment,
    SupportLevel,
)
from langgraph.prebuilt.security.execution import (
    HostExecutionDenied,
    HostExecutionError,
    HostExecutionResult,
)
from langgraph.prebuilt.security.lean_lifecycle import LeanLifecycleChecker
from langgraph.prebuilt.security.macos import (
    MacOSSandboxExecutor,
    MacOSToolSpec,
    _digest,
    _MacOSSeatbeltAdapter,
)
from langgraph.prebuilt.security.object_broker import (
    ObjectBrokerDispatcher,
    _ObjectBroker,
    _ObjectWorker,
    _service,
)
from langgraph.prebuilt.security.object_policy import EnforcementKind
from langgraph.prebuilt.security.profile import parse_profiles
from langgraph.prebuilt.security.resource_mediator import ResourceMediatorAdapter
from langgraph.prebuilt.security.types import ExecutionOutcome, _validate_principal


class _MacOSObjectAdapter(_MacOSSeatbeltAdapter):
    adapter_id = "host:macos-object-v1"
    _protected = _LandlockObjectAdapter._protected

    def __init__(self, worker, grant):
        self.worker, self.grant = worker, grant
        super().__init__(
            worker._key,
            worker._boot,
            worker.default_limits["wall_ms"] / 1000 + worker.startup_timeout_s + 10,
            evidence={
                **worker._adapter._evidence,
                "cpu_budget": "not-promised; qualification deferred",
            },
        )

    def attest(self, nonce):
        host = super().attest(nonce)
        host = replace(
            host,
            capabilities=host.capabilities
            | frozenset(
                {
                    "broker:spawn-bound",
                    "credentials:parent-only",
                    "process:deny",
                    "network:deny",
                }
            ),
        )
        return replace(host, signature=self._sign(host.digest))

    def assess(self, obligation, host):
        item = obligation
        if not self.verify(host):
            return SupportAssessment(
                self.adapter_id,
                item.obligation_id,
                SupportLevel.UNSUPPORTED,
                "macos:untrusted_host",
            )
        if (
            item.kind is ObligationKind.AUTHENTICATED_CHANNEL
            and item.operation == "spawn_bound_broker"
        ):
            return SupportAssessment(
                self.adapter_id,
                item.obligation_id,
                SupportLevel.EXACT,
                "native:private-spawn-bound-pipes",
            )
        if (
            item.kind is ObligationKind.BYPASS_PREVENTION
            and item.operation == "deny_direct_resource_access"
        ):
            supported = frozenset(
                item.conditions.get("required_capabilities", ())
            ).issubset(host.capabilities) and self._protected(
                item.conditions.get("protected_paths", ())
            )
            return SupportAssessment(
                self.adapter_id,
                item.obligation_id,
                SupportLevel.EXACT if supported else SupportLevel.UNSUPPORTED,
                "seatbelt:resource-bypass-closed"
                if supported
                else "resource_bypass_not_closed",
            )
        return super().assess(item, host)


class _MacOSObjectWorker(MacOSSandboxExecutor):
    _host_adapter_type = _MacOSObjectAdapter
    _prepare_grant = _ObjectWorker._prepare_grant
    close_mediators = _ObjectWorker.close_mediators

    def _validate_principal_profile(self, principal):
        _validate_principal(principal)

    def _baseline(self):
        return tuple(
            rule
            for rule in super()._baseline()
            if not (
                rule.domain is AuthorityDomain.RESOURCE_LIMIT
                and rule.selector == "cpu_ms"
            )
        )

    def __init__(self, object_grant, *args, mediators=(), bindings=None, **kwargs):
        self.object_grant = object_grant
        self._lean_object_route = True
        self.mediators, self.bound_mediators = tuple(mediators), ()
        self.record = None
        self.credential_broker = _ObjectBroker(object_grant, bindings)
        super().__init__(*args, **kwargs)

    def _compile_grant(self, principal, call, spec):
        obj = self.object_grant
        if (
            obj.principal_id != principal.user_id
            or obj.tool_name != call.tool.name
            or obj.call_id != call.call_id
            or obj.enforcement_waivers
        ):
            raise HostExecutionDenied("macos_object:grant_binding")
        ids = [line.line_id for line in obj.lines]
        if len(ids) != len(set(ids)) or any(
            name.startswith("runtime:") for name in ids
        ):
            raise HostExecutionDenied("macos_object:ambiguous_grant")
        rules = []
        for line in obj.lines:
            if line.enforcer is EnforcementKind.KERNEL:
                path = Path(line.selector)
                if (
                    line.class_name != "fs"
                    or line.lowering is not None
                    or line.attributes
                    or not path.is_absolute()
                    or str(path.resolve(strict=True)) != line.selector
                    or not path.is_file()
                    or line.operation != "read"
                ):
                    raise HostExecutionDenied(
                        "macos_object:unsupported_filesystem_authority"
                    )
                domain, selector, conditions = (
                    AuthorityDomain.FILESYSTEM,
                    line.selector,
                    {"subtree": False},
                )
            elif line.enforcer is EnforcementKind.BROKER:
                domain, selector, conditions = (
                    AuthorityDomain.SERVICE,
                    _service(line.class_name, line.selector),
                    {"object_grant": obj.digest, "line": line.line_id},
                )
            else:
                raise HostExecutionDenied("macos_object:unsupported_enforcer")
            rules.append(
                GrantRule(
                    line.line_id,
                    domain,
                    line.operation,
                    selector,
                    conditions,
                    line.requirement,
                    line.provenance,
                )
            )
        rules.extend(self._baseline())
        grant = Grant(
            principal.user_id,
            principal.session_id,
            call.tool.name,
            spec.artifact_digest,
            call.call_id,
            _digest({"args": dict(call.args), "normalized": dict(call.normalized)}),
            obj.digest,
            tuple(rules),
        )
        preview_host = _MacOSObjectAdapter(self, grant).attest(secrets.token_hex(16))
        enriched = []
        lines = {line.line_id: line for line in obj.lines}
        for rule in grant.rules:
            if rule.domain is AuthorityDomain.SERVICE:
                line = lines[rule.rule_id]
                candidates = [
                    adapter.assess(line, preview_host) for adapter in self.mediators
                ]
                candidates = [
                    value
                    for value in candidates
                    if value.support is not SupportLevel.UNSUPPORTED
                    and value.required_capabilities.issubset(preview_host.capabilities)
                ]
                if len(candidates) > 1:
                    raise HostExecutionDenied(
                        f"adapter_ownership_conflict:{line.line_id}"
                    )
                support = candidates[0] if candidates else None
                rule = replace(
                    rule,
                    conditions={
                        **rule.conditions,
                        "resource_selector": line.selector,
                        "protected_paths": tuple(support.protected_paths)
                        if support
                        else (),
                        "required_capabilities": tuple(
                            sorted(support.required_capabilities)
                        )
                        if support
                        else (),
                    },
                )
            enriched.append(rule)
        grant = replace(grant, rules=tuple(enriched))
        ledger = RequirementLedger(
            tuple(
                RequirementEntry(
                    rule.rule_id, rule.requirement, frozenset({rule.rule_id})
                )
                for rule in rules
            )
        )
        return SimpleNamespace(grant=grant, ledger=ledger)

    def _prepare_execution(self, grant, ledger):
        grant = self._prepare_grant(grant, ledger)
        final_ledger = RequirementLedger(
            tuple(
                RequirementEntry(
                    rule.rule_id, rule.requirement, frozenset({rule.rule_id})
                )
                for rule in grant.rules
            )
        )
        self._check_lean_grant(grant, final_ledger, self.record.obligations)
        self._adapter, self._coordinator = self.host_adapter, self.coordinator
        if not any(rule.domain is AuthorityDomain.SERVICE for rule in grant.rules):
            return grant, self.record.host, self.record.plan
        spawn = SpawnRecord(
            grant.principal_id, grant.tool_name, grant.digest, secrets.token_hex(16)
        )
        self.credential_broker.bind_spawn(spawn, grant)
        self._broker_nonce = spawn.nonce
        self._broker_handler = lambda request: self.credential_broker._handle_frame(
            json.dumps(request, allow_nan=False).encode() + b"\n", spawn, grant
        )
        return grant, self.record.host, self.record.plan


class MacOSObjectDispatcher:
    """Closed object-policy route over a fresh native worker for every grant.

    Resources and their credentials remain in the controller. Their existing
    typed mediators negotiate and activate against the same worker context as
    the Seatbelt plan. Worker requests use only the inherited protocol pipes.
    """

    enforcer_id = "macos-object-seatbelt-v1"
    requires_host_negotiation = True

    def __init__(
        self,
        tools,
        *,
        launcher,
        recovery_directory,
        lifecycle_checker,
        runtime_roots=(),
        executable_roots=(),
        resources=(),
        mediators=(),
        wall_timeout_s=30,
        integrity_recheck="always",
        runtime_aliases=None,
        runtime_libraries=(),
    ):
        if type(lifecycle_checker) is not LeanLifecycleChecker:
            raise ValueError("macOS object route requires the pinned Lean checker")
        if not math.isfinite(wall_timeout_s) or wall_timeout_s <= 0:
            raise ValueError("wall timeout must be finite and positive")
        if integrity_recheck not in {"always", "preflight-only"}:
            raise ValueError("unknown integrity recheck mode")
        self.tools = MappingProxyType(dict(tools))
        if not self.tools or any(
            type(spec) is not MacOSToolSpec for spec in self.tools.values()
        ):
            raise ValueError("macOS object route requires MacOSToolSpec artifacts")
        from langgraph.prebuilt.security.mediators.contracts import object_bindings

        self.resources = tuple(resources)
        self.bindings = MappingProxyType(object_bindings(self.resources))
        self.mediators = (
            *mediators,
            *(resource.adapter for resource in self.resources),
        )
        if any(type(item) is not ResourceMediatorAdapter for item in self.mediators):
            raise TypeError(
                "macOS object mediators must be ResourceMediatorAdapter instances"
            )
        ids = [item.adapter_id for item in self.mediators]
        if len(ids) != len(set(ids)) or any(name.startswith("host:") for name in ids):
            raise ValueError("mediator identities must be unique and not reserved")
        self.runtime_roots = tuple(
            Path(root).resolve(strict=True) for root in runtime_roots
        )
        self.executable_roots = tuple(
            Path(root).resolve(strict=True) for root in executable_roots
        )
        self.launcher, self.recovery_directory = (
            launcher,
            Path(recovery_directory).resolve(),
        )
        self.lifecycle_checker = lifecycle_checker
        self.runtime_aliases = MappingProxyType(dict(runtime_aliases or {}))
        self.runtime_libraries = tuple(
            MappingProxyType(dict(item)) for item in runtime_libraries
        )
        self.wall_timeout_s = wall_timeout_s
        self._lock = RLock()
        self._lifecycle_records = deque(maxlen=1024)
        self._recoveries = {}
        self._receipts, self._lowerings, self._audit = (
            deque(maxlen=1024),
            deque(maxlen=1024),
            deque(maxlen=4096),
        )

    def validate_tools(self, names):
        if set(names).difference(self.tools):
            raise ValueError("macOS object route missing tool artifacts")

    def supports(self, object_class, line):
        return False  # Concrete grants require host/mediator negotiation.

    def activation_receipts(self):
        with self._lock:
            return tuple(self._receipts)

    def lowering_records(self):
        with self._lock:
            return tuple(self._lowerings)

    def audit_records(self):
        with self._lock:
            return tuple(self._audit)

    def lifecycle_records(self):
        with self._lock:
            return tuple(
                json.loads(json.dumps(item)) for item in self._lifecycle_records
            )

    def invoke(self, principal, call, grant):
        return self._invoke(principal, call, grant, asynchronous=False)

    def _invoke(self, principal, call, grant, *, asynchronous):
        name = call.tool.name
        if (
            grant.principal_id != principal.user_id
            or grant.tool_name != name
            or grant.call_id != call.call_id
            or grant.enforcement_waivers
        ):
            raise HostExecutionDenied("macos_object:grant_binding")
        if name not in self.tools:
            raise HostExecutionDenied("macos_object:tool_missing")
        profiles = parse_profiles(
            f"tool {name} {{\nowner object_dispatcher\nruns macos\n}}"
        )
        # This grant is built from the authorized object lines, not evaluated
        # from the synthetic profile. No syscall-set capability is advertised.
        worker = _MacOSObjectWorker(
            grant,
            profiles,
            {name: self.tools[name]},
            launcher=self.launcher,
            experimental=True,
            recovery_directory=self.recovery_directory,
            runtime_roots=self.runtime_roots,
            executable_roots=self.executable_roots,
            lifecycle_checker=self.lifecycle_checker,
            runtime_aliases=self.runtime_aliases,
            runtime_libraries=self.runtime_libraries,
            mediators=self.mediators,
            bindings=self.bindings,
            default_limits={
                "cpu_ms": 10000,
                "nofile": 128,
                "wall_ms": int(self.wall_timeout_s * 1000),
            },
        )
        call = replace(call, args={**call.args, **call.normalized})
        result = None
        try:
            result = worker._invoke(principal, call, (), asynchronous=asynchronous)
            receipt = self._object_receipt(result.receipt, grant)
            with self._lock:
                self._receipts.append(receipt)
            return HostExecutionResult(result.value, receipt)
        except HostExecutionError as exc:
            exc.receipt = self._object_receipt(exc.receipt, grant)
            raise
        finally:
            with self._lock:
                self._audit.extend(worker.credential_broker.audit_records())
                self._lifecycle_records.extend(worker.lifecycle_records())
                for recovery in worker.unresolved_terminations():
                    self._recoveries[recovery.recovery_id] = worker
                if worker.record is not None:
                    record = worker.record
                    self._lowerings.append(
                        {
                            "object_grant_digest": grant.digest,
                            "native_grant_digest": record.grant.digest,
                            "policy_digest": record.grant.policy_digest,
                            "candidate": _record_data(record.candidate),
                            "grant": _record_data(record.grant),
                            "host": _record_data(record.host),
                            "obligations": [
                                dict(item.canonical()) for item in record.obligations
                            ],
                            "plan": _record_data(record.plan),
                        }
                    )
            active_error = sys.exc_info()[1]
            try:
                worker.close_mediators()
            except Exception as exc:
                receipt = (
                    active_error.receipt
                    if isinstance(active_error, HostExecutionError)
                    else result.receipt
                    if result is not None
                    else None
                )
                if receipt is not None:
                    raise HostExecutionError(
                        "object_lowering:resource_release_failed",
                        receipt,
                        ExecutionOutcome.INDETERMINATE,
                        termination_confirmed=False,
                    ) from exc
                raise

    _object_receipt = staticmethod(ObjectBrokerDispatcher._object_receipt)

    def confirm_termination(self, recovery):
        with self._lock:
            worker = self._recoveries.get(recovery.recovery_id)
        if worker is None or not worker.confirm_termination(recovery):
            return False
        with self._lock:
            self._recoveries.pop(recovery.recovery_id, None)
        return True

    async def ainvoke(self, principal, call, grant):
        task = asyncio.create_task(
            asyncio.to_thread(self._invoke, principal, call, grant, asynchronous=True)
        )
        try:
            return await asyncio.shield(task)
        except asyncio.CancelledError:
            while not task.done():
                try:
                    await asyncio.shield(task)
                except asyncio.CancelledError:
                    continue
                except Exception:
                    break
            if task.done() and not task.cancelled():
                error = task.exception()
                if (
                    isinstance(error, HostExecutionError)
                    and not error.termination_confirmed
                ):
                    raise error
            raise


def _record_data(value):
    if is_dataclass(value):
        return {
            item.name: _record_data(getattr(value, item.name)) for item in fields(value)
        }
    if isinstance(value, Mapping):
        return {key: _record_data(item) for key, item in value.items()}
    if isinstance(value, Enum):
        return value.value
    if isinstance(value, (tuple, list, set, frozenset)):
        return [_record_data(item) for item in value]
    return value
