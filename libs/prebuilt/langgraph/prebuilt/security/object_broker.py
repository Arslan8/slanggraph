"""Open-class capabilities brokered outside a Landlock/seccomp worker.

Adapters are trusted semantic implementations. Workers receive only a channel
bound to their invocation, never adapters or resource credentials.
"""

from __future__ import annotations

import asyncio
import hashlib
import json
import math
import secrets
import sys
from collections import deque
from collections.abc import Callable, Mapping, Sequence
from dataclasses import replace
from pathlib import Path
from threading import RLock
from types import MappingProxyType
from typing import Any

from langgraph.prebuilt.security._object_landlock import _LandlockObjectAdapter
from langgraph.prebuilt.security.broker import (
    BrokerAuditRecord,
    CredentialBroker,
    SpawnRecord,
    broker_request,
)
from langgraph.prebuilt.security.enforcement import (
    ActivationReceipt,
    AuthorityDomain,
    EnforcementObligation,
    Grant,
    GrantRule,
    ObligationKind,
    RequirementEntry,
    RequirementLedger,
    SupportLevel,
    compile_obligations,
)
from langgraph.prebuilt.security.execution import (
    HostExecutionDenied,
    HostExecutionError,
    HostExecutionResult,
    TerminationRecovery,
)
from langgraph.prebuilt.security.landlock import LandlockSandboxExecutor
from langgraph.prebuilt.security.linux import LinuxToolSpec
from langgraph.prebuilt.security.object_policy import (
    EnforcementKind,
    ObjectClass,
    ObjectGrant,
    ObjectGrantLine,
)
from langgraph.prebuilt.security.policy import TypedPolicyBackend
from langgraph.prebuilt.security.profile import parse_profiles
from langgraph.prebuilt.security.resource_mediator import (
    ObjectLoweringRecord,
    ResourceMediatorAdapter,
    _BoundMediator,
    negotiate_object_grant,
)
from langgraph.prebuilt.security.types import ExecutionOutcome, Principal, ToolCall

Handler = Callable[[ObjectGrantLine, Mapping[str, Any]], Any]


def _service(class_name: str, selector: str) -> str:
    return json.dumps([class_name, selector], separators=(",", ":"))


def object_request(
    class_name: str,
    operation: str,
    selector: str,
    payload: Mapping[str, Any] | None = None,
) -> Any:
    """Request an exact capability over the inherited worker channel."""
    return broker_request(_service(class_name, selector), operation, payload)


class _ObjectBroker(CredentialBroker):
    """Reuse bounded spawn-bound transport without credential issuance."""

    def __init__(
        self, grant: ObjectGrant, bindings: Mapping[str, str] | None = None
    ) -> None:
        self.bindings = dict(bindings or {})
        self.grant = grant
        self.routes: dict[str, _BoundMediator] = {}
        self.spawn: SpawnRecord | None = None
        self._audit: deque[BrokerAuditRecord] = deque(maxlen=4096)
        self._lock = RLock()

    def open_session(self, spawn, grant):
        session = super().open_session(spawn, grant)
        self.spawn = spawn
        return session

    def _handle_frame(
        self, frame: bytes, spawn: SpawnRecord, grant: Grant
    ) -> Mapping[str, Any]:
        if len(frame) > 1_048_576 or not frame.endswith(b"\n"):
            return {"status": "denied", "error": "broker:invalid_frame"}
        try:
            request = json.loads(frame)
            if not isinstance(request, dict) or set(request) != {
                "service",
                "operation",
                "payload",
            }:
                raise ValueError("invalid request")
            service, operation, payload = (
                request["service"],
                request["operation"],
                request["payload"],
            )
            if (
                not isinstance(service, str)
                or not isinstance(operation, str)
                or not isinstance(payload, dict)
            ):
                raise ValueError("invalid fields")
        except (ValueError, UnicodeError, RecursionError):
            return {"status": "denied", "error": "broker:invalid_request"}
        service = self.bindings.get(service, service)
        active = {
            rule.rule_id
            for rule in grant.rules
            if rule.domain is AuthorityDomain.SERVICE
            and rule.selector == service
            and rule.operation == operation
        }
        lines = [
            line
            for line in self.grant.lines
            if line.line_id in active
            and _service(line.class_name, line.selector) == service
            and line.operation == operation
        ]
        if len(lines) != 1:
            self._record(spawn, service, operation, "", False, "not_granted")
            return {"status": "denied", "error": "broker:not_granted"}
        line = lines[0]
        try:
            result = self.routes[line.line_id].invoke(line, payload, spawn)
        except Exception:
            self._record(
                spawn, service, operation, line.line_id, False, "adapter_failure"
            )
            return {"status": "denied", "error": "broker:adapter_failure"}
        self._record(
            spawn, service, operation, line.line_id, True, "exact_object_grant"
        )
        return {"status": "ok", "result": result}


class _ObjectWorker(LandlockSandboxExecutor):
    def __init__(
        self,
        object_grant: ObjectGrant,
        *args: Any,
        mediators: Sequence[ResourceMediatorAdapter] = (),
        **kwargs: Any,
    ) -> None:
        self.object_grant = object_grant
        self.mediators = tuple(mediators)
        self.bound_mediators: tuple[_BoundMediator, ...] = ()
        self.record: ObjectLoweringRecord | None = None
        super().__init__(*args, **kwargs)

    def _compile_grant(
        self, principal: Principal, call: ToolCall, spec: Any, private_tmp: Path
    ) -> tuple[Grant, RequirementLedger]:
        obj = self.object_grant
        rules = tuple(
            GrantRule(
                line.line_id,
                AuthorityDomain.FILESYSTEM
                if line.enforcer is EnforcementKind.KERNEL and line.class_name == "fs"
                else AuthorityDomain.SERVICE,
                line.operation,
                line.selector
                if line.enforcer is EnforcementKind.KERNEL and line.class_name == "fs"
                else _service(line.class_name, line.selector),
                {"exact_file": True, "lowering": line.lowering}
                if line.enforcer is EnforcementKind.KERNEL and line.class_name == "fs"
                else {"object": dict(line.canonical())},
                requirement=line.requirement,
            )
            for line in obj.lines
        )
        rules += self._baseline_rules(
            spec,
            private_tmp,
            enable_broker=any(
                line.enforcer is EnforcementKind.BROKER for line in obj.lines
            ),
        )
        rules += (
            GrantRule(
                "runtime:syscalls",
                AuthorityDomain.PROCESS,
                "syscall_set",
                "minimal",
                baseline=True,
            ),
        )
        grant = Grant(
            principal.user_id,
            principal.session_id,
            call.tool.name,
            spec.artifact_digest,
            call.call_id,
            hashlib.sha256(
                json.dumps(dict(call.args), sort_keys=True).encode()
            ).hexdigest(),
            obj.digest,
            rules,
        )
        ledger = RequirementLedger(
            tuple(
                RequirementEntry(
                    rule.rule_id, rule.requirement, frozenset({rule.rule_id})
                )
                for rule in rules
            )
        )
        return grant, ledger

    def _worker_request_extras(self, grant: Grant) -> Mapping[str, Any]:
        imports = []
        if any(
            line.class_name == "db_record"
            and line.lowering == "sqlite.record.v1"
            and line.enforcer is EnforcementKind.BROKER
            for line in self.object_grant.lines
        ):
            imports.append("langgraph.prebuilt.security.mediators.records")
        return {"broker_client_imports": imports} if imports else {}

    def _prepare_grant(self, grant, ledger):
        self.host_adapter = _LandlockObjectAdapter(self, grant)
        host = self.host_adapter.attest(secrets.token_hex(16))
        broker_lines = tuple(
            line
            for line in self.object_grant.lines
            if line.enforcer is EnforcementKind.BROKER
        )
        self.bound_mediators = tuple(
            _BoundMediator(item, broker_lines, host) for item in self.mediators
        )
        routes: dict[str, _BoundMediator] = {}
        additional = []
        dependencies = {}
        try:
            for line in broker_lines:
                candidates = []
                for adapter in self.bound_mediators:
                    support = adapter.assess_line(line)
                    adapter.assessments[line.line_id] = support
                    if support.support is not SupportLevel.UNSUPPORTED:
                        candidates.append((adapter, support))
                if len(candidates) > 1:
                    raise HostExecutionDenied(
                        f"adapter_ownership_conflict:{line.line_id}"
                    )
                support = candidates[0][1] if candidates else None
                if candidates:
                    routes[line.line_id] = candidates[0][0]
                ids = {
                    kind: f"resource:{line.line_id}:{kind}"
                    for kind in ("bypass", "channel", "custody")
                }
                dependencies[f"rule:{line.line_id}:operate"] = frozenset(ids.values())
                additional.extend(
                    (
                        EnforcementObligation(
                            ids["bypass"],
                            line.line_id,
                            ObligationKind.BYPASS_PREVENTION,
                            AuthorityDomain.SERVICE,
                            "deny_direct_resource_access",
                            line.selector,
                            {
                                "protected_paths": support.protected_paths
                                if support
                                else (),
                                "required_capabilities": tuple(
                                    support.required_capabilities
                                )
                                if support
                                else (),
                            },
                            frozenset(
                                {
                                    "domain:filesystem:deny_complement",
                                    "domain:network:deny_complement",
                                    "domain:process:deny_complement",
                                }
                            ),
                        ),
                        EnforcementObligation(
                            ids["channel"],
                            line.line_id,
                            ObligationKind.AUTHENTICATED_CHANNEL,
                            AuthorityDomain.IPC,
                            "spawn_bound_broker",
                            line.selector,
                            dependencies=frozenset({"domain:ipc:deny_complement"}),
                        ),
                        EnforcementObligation(
                            ids["custody"],
                            line.line_id,
                            ObligationKind.CREDENTIAL_CUSTODY,
                            AuthorityDomain.CREDENTIAL,
                            "parent_owned_credentials",
                            line.selector,
                            dependencies=frozenset({ids["bypass"], ids["channel"]}),
                        ),
                    )
                )
            obligations = tuple(
                replace(
                    item,
                    dependencies=dependencies.get(
                        item.obligation_id, item.dependencies
                    ),
                )
                for item in compile_obligations(grant, additional=additional)
            )
            self.record, self.coordinator = negotiate_object_grant(
                grant,
                ledger,
                obligations,
                (self.host_adapter, *self.bound_mediators),
                self.host_adapter,
                host,
                expected_nonce=host.nonce,
            )
            retained = {rule.rule_id for rule in self.record.grant.rules}
            self.credential_broker.routes = {
                key: value for key, value in routes.items() if key in retained
            }
            return self.record.grant
        except HostExecutionDenied:
            raise
        except Exception as exc:
            raise HostExecutionDenied(f"object_lowering:{type(exc).__name__}") from exc

    def _lower(self, grant):
        # Only the host-owned subset becomes kernel rules. Semantic operations
        # are owned by separately negotiated mediator plans.
        return super()._lower(replace(grant, rules=self.host_adapter.rules))

    def _worker_plan_digest(self, grant, enforcement):
        assert self.record is not None
        return self.record.plan.digest

    def _receipt(self, grant, pid, enforcement):
        assert self.record is not None
        broker = self.credential_broker
        context = self.host_adapter.bind_worker(
            pid, broker.spawn.nonce if broker.spawn else "no-broker"
        )
        try:
            receipt = self.coordinator.activate(
                grant,
                self.record.plan,
                self.record.host,
                context,
                nonce=secrets.token_hex(16),
            )
        except Exception as exc:
            raise HostExecutionDenied(
                f"object_lowering:activation_failed:{type(exc).__name__}"
            ) from exc
        if not self.coordinator.validate_receipt(
            receipt, grant, self.record.plan, self.record.host, context
        ):
            raise HostExecutionDenied("object_lowering:activation_receipt_invalid")
        return receipt

    def close_mediators(self):
        failures = []
        for adapter in self.bound_mediators:
            try:
                adapter.close()
            except Exception as exc:
                failures.append(exc)
        if failures:
            raise HostExecutionDenied(
                "object_lowering:resource_release_failed"
            ) from failures[0]


class ObjectBrokerDispatcher:
    """Execute object grants in Linux workers with operator-owned adapters.

    Adapters must use the supplied line's selector and operation, validate
    payloads, and bound their I/O. Runtime roots are readable trusted code;
    they must not contain secrets or broker-protected data. Broker classes and
    exact regular-file `fs` kernel grants are supported; waivers are refused.
    Kernel confinement must activate before any tool import. Handlers are
    synchronous, must bound their I/O, and must not spawn background work.
    """

    enforcer_id = "object-broker-landlock-v2"
    requires_host_negotiation = True

    def __init__(
        self,
        tools: Mapping[str, LinuxToolSpec],
        handlers: Mapping[tuple[str, str], Handler] | None = None,
        *,
        runtime_roots: Sequence[str | Path],
        mediators: Sequence[ResourceMediatorAdapter] = (),
        resources: Sequence[Any] = (),
        wall_timeout_s: float = 30.0,
    ) -> None:
        self.tools = MappingProxyType(dict(tools))
        if handlers:
            raise ValueError(
                "bare handlers have no lowering contract; register ResourceMediatorAdapter via mediators="
            )
        from langgraph.prebuilt.security.mediators.contracts import object_bindings

        self.resources = tuple(resources)
        self.bindings = MappingProxyType(object_bindings(self.resources))
        self.mediators = (
            *mediators,
            *(resource.adapter for resource in self.resources),
        )
        if any(
            not isinstance(item, ResourceMediatorAdapter) for item in self.mediators
        ):
            raise TypeError("mediators must be ResourceMediatorAdapter instances")
        ids = [item.adapter_id for item in self.mediators]
        if len(ids) != len(set(ids)) or any(item.startswith("host:") for item in ids):
            raise ValueError(
                "mediator adapter identities must be unique and not reserved"
            )
        if not self.tools or any(
            not isinstance(spec, LinuxToolSpec) or spec.deployment is not None
            for spec in self.tools.values()
        ):
            raise ValueError("object workers require pinned LinuxToolSpec artifacts")
        if not math.isfinite(wall_timeout_s) or wall_timeout_s <= 0:
            raise ValueError("wall_timeout_s must be finite and positive")
        self.runtime_roots = tuple(runtime_roots)
        self.wall_timeout_s = wall_timeout_s
        self._audit: deque[BrokerAuditRecord] = deque(maxlen=4096)
        self._lock = RLock()
        self._lowering_records: deque[ObjectLoweringRecord] = deque(maxlen=1024)

    def lowering_records(self) -> tuple[ObjectLoweringRecord, ...]:
        """Return negotiated host, baseline, obligations and effective authority."""
        with self._lock:
            return tuple(self._lowering_records)

    def audit_records(self) -> tuple[BrokerAuditRecord, ...]:
        """Return bounded broker decisions bound to worker/grant identities."""
        with self._lock:
            return tuple(self._audit)

    def supports(self, object_class: ObjectClass, line: ObjectGrantLine) -> bool:
        """Host-independent discovery cannot certify concrete enforceability."""
        return False

    def validate_tools(self, tool_names: Sequence[str]) -> None:
        """Reject missing pinned executables at configuration time."""
        missing = set(tool_names).difference(self.tools)
        if missing:
            raise ValueError(
                "object worker missing manifests: " + ", ".join(sorted(missing))
            )

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
        if (
            grant.principal_id != principal.user_id
            or grant.tool_name != call.tool.name
            or grant.call_id != call.call_id
            or grant.enforcement_waivers
        ):
            raise HostExecutionDenied("object_broker:grant_binding")
        if call.tool.name not in self.tools:
            raise HostExecutionDenied("object_broker:tool_manifest_missing")
        ids = [line.line_id for line in grant.lines]
        if len(ids) != len(set(ids)) or any(
            item.startswith("runtime:") for item in ids
        ):
            raise HostExecutionDenied("object_broker:ambiguous_grant")
        # Deliver the same canonical arguments inspected by authorization.
        call = replace(call, args={**call.args, **call.normalized})
        profiles = parse_profiles(
            f"tool {call.tool.name} {{\n owner broker\n runs linux\n syscalls @minimal\n}}"
        )
        broker = _ObjectBroker(grant, self.bindings)
        worker = _ObjectWorker(
            grant,
            profiles,
            {call.tool.name: self.tools[call.tool.name]},
            runtime_roots=self.runtime_roots,
            policy_backend=TypedPolicyBackend(),
            credential_broker=broker,
            mediators=self.mediators,
            default_wall_timeout_s=self.wall_timeout_s,
        )
        result = None
        try:
            result = worker._invoke(principal, call, (), asynchronous=asynchronous)
        except HostExecutionError as exc:
            exc.receipt = self._object_receipt(exc.receipt, grant)
            raise
        finally:
            with self._lock:
                self._audit.extend(broker.audit_records())
                if worker.record is not None:
                    self._lowering_records.append(worker.record)
            active_error = sys.exc_info()[1]
            try:
                worker.close_mediators()
            except Exception as exc:
                receipt = (
                    active_error.receipt
                    if isinstance(active_error, HostExecutionError)
                    else self._object_receipt(result.receipt, grant)
                    if result is not None
                    else None
                )
                if receipt is not None:
                    raise HostExecutionError(
                        "object_lowering:resource_release_failed",
                        receipt,
                        ExecutionOutcome.INDETERMINATE,
                    ) from exc
                raise
        return HostExecutionResult(
            result.value, self._object_receipt(result.receipt, grant)
        )

    @staticmethod
    def _object_receipt(
        receipt: ActivationReceipt, grant: ObjectGrant
    ) -> ActivationReceipt:
        ids = {line.line_id for line in grant.lines}
        # Kernel evidence remains bound to the lower plan, whose policy digest
        # includes the exact object grant. Expose only object lines to the host.
        return replace(
            receipt,
            grant_digest=grant.digest,
            rule_enforcement=tuple(
                item for item in receipt.rule_enforcement if item.rule_id in ids
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
            # Keep the invocation alive until its worker and active broker
            # operation have stopped, or return explicit indeterminate evidence.
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
        return False
