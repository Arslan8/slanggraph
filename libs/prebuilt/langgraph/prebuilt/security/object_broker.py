"""Open-class capabilities brokered outside a Landlock/seccomp worker.

Adapters are trusted semantic implementations. Workers receive only a channel
bound to their invocation, never adapters or resource credentials.
"""

from __future__ import annotations

import asyncio
import copy
import hashlib
import json
import math
import secrets
import sys
from collections import deque
from collections.abc import Callable, Mapping, Sequence
from concurrent.futures import ThreadPoolExecutor
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
    AdapterPlan,
    AuthorityDomain,
    EnforcementCoordinator,
    EnforcementObligation,
    EnforcementPlan,
    Grant,
    GrantRule,
    ObligationKind,
    RequirementEntry,
    RequirementLedger,
    SupportLevel,
    _obligation_digest,
    compile_obligations,
)
from langgraph.prebuilt.security.execution import (
    HostExecutionDenied,
    HostExecutionError,
    HostExecutionResult,
    TerminationRecovery,
)
from langgraph.prebuilt.security.host_controls import host_control_rule
from langgraph.prebuilt.security.landlock import (
    LandlockSandboxExecutor,
    _LandlockWorkerPoolState,
)
from langgraph.prebuilt.security.lean_lifecycle import LeanLifecycleChecker
from langgraph.prebuilt.security.linux import LinuxToolSpec, _host_configuration_digest
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
    ObjectLoweringRefused,
    ResourceMediatorAdapter,
    _BoundMediator,
    _digest,
    negotiate_object_grant,
)
from langgraph.prebuilt.security.types import ExecutionOutcome, Principal, ToolCall

Handler = Callable[[ObjectGrantLine, Mapping[str, Any]], Any]


def _object_authority_key(grant: ObjectGrant) -> tuple[Any, ...]:
    """Compare prepared authority structurally, without serialization or SHA-256.

    Invocation identity is bound separately when the worker is claimed. This
    process-local dictionary key is not a credential or an integrity receipt.
    """
    return (
        grant.policy_digest,
        grant.tool_name,
        tuple(sorted(grant.enforcement_waivers.items())),
        tuple(
            (
                line.line_id,
                line.class_name,
                line.operation,
                line.selector,
                tuple(sorted(line.attributes.items())),
                line.requirement.value,
                line.enforcer.value,
                line.lowering,
                line.provenance,
            )
            for line in sorted(grant.lines, key=lambda item: item.line_id)
        ),
    )


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
        self,
        grant: ObjectGrant,
        bindings: Mapping[str, str] | None = None,
        *,
        server_executor: ThreadPoolExecutor | None = None,
    ) -> None:
        self.bindings = dict(bindings or {})
        self.grant = grant
        self.routes: dict[str, _BoundMediator] = {}
        self._lines_by_request: dict[tuple[str, str], ObjectGrantLine | None] = {}
        self.spawn: SpawnRecord | None = None
        self._audit: deque[BrokerAuditRecord] = deque(maxlen=4096)
        self._lock = RLock()
        self._server_executor = server_executor

    def bind_spawn(self, spawn, grant):
        if (
            spawn.grant_hash != grant.digest
            or spawn.principal_id != grant.principal_id
            or spawn.tool_name != grant.tool_name
        ):
            raise ValueError("object broker spawn does not match grant")
        active: dict[str, set[tuple[str, str]]] = {}
        for rule in grant.rules:
            if rule.domain is AuthorityDomain.SERVICE:
                active.setdefault(rule.rule_id, set()).add(
                    (rule.selector, rule.operation)
                )
        indexed: dict[tuple[str, str], ObjectGrantLine | None] = {}
        for line in self.grant.lines:
            key = (_service(line.class_name, line.selector), line.operation)
            if key not in active.get(line.line_id, set()):
                continue
            indexed[key] = None if key in indexed else line
        self._lines_by_request = indexed
        self.spawn = spawn

    def open_session(self, spawn, grant):
        self.bind_spawn(spawn, grant)
        return super().open_session(spawn, grant)

    def bind_prepared_session(self, parent, spawn, grant):
        self.bind_spawn(spawn, grant)
        return super().bind_prepared_session(parent, spawn, grant)

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
        line = self._lines_by_request.get((service, operation))
        if line is None:
            self._record(spawn, service, operation, "", False, "not_granted")
            return {"status": "denied", "error": "broker:not_granted"}
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
    _host_adapter_type = _LandlockObjectAdapter

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
        self._prepared_record: ObjectLoweringRecord | None = None
        self._prepared_host_configuration: str | None = None
        self._prepared_rule_shape: Any = None
        self._prepared_obligation_shape: Any = None
        self._prepared_mediator_assessments: Mapping[str, Mapping[str, Any]] | None = (
            None
        )
        self._used_prepared_policy = False
        super().__init__(*args, **kwargs)

    def _compile_grant(
        self, principal: Principal, call: ToolCall, spec: Any, private_tmp: Path
    ) -> tuple[Grant, RequirementLedger]:
        obj = self.object_grant
        rules = tuple(
            host_control_rule(line)
            or GrantRule(
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
                else {"object_grant": obj.digest, "line": line.line_id},
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
        self.host_adapter = self._host_adapter_type(self, grant)
        host = self.host_adapter.attest(secrets.token_hex(16))
        broker_lines = tuple(
            line
            for line in self.object_grant.lines
            if line.enforcer is EnforcementKind.BROKER
        )
        self.bound_mediators = tuple(
            _BoundMediator(item, broker_lines, host) for item in self.mediators
        )
        prepared_assessments = self._prepared_mediator_assessments
        if prepared_assessments is not None:
            if set(prepared_assessments) != {
                adapter.adapter_id for adapter in self.bound_mediators
            }:
                raise HostExecutionDenied("object_lowering:prepared_adapter_changed")
            for adapter in self.bound_mediators:
                adapter.assessments.update(prepared_assessments[adapter.adapter_id])
        routes: dict[str, _BoundMediator] = {}
        resource_conditions: dict[str, Mapping[str, Any]] = {}
        additional = []
        dependencies = {}
        try:
            for line in broker_lines:
                candidates = []
                for adapter in self.bound_mediators:
                    if prepared_assessments is None:
                        support = adapter.assess_line(line)
                        adapter.assessments[line.line_id] = support
                    else:
                        support = adapter.assessments.get(line.line_id)
                        if support is None:
                            raise HostExecutionDenied(
                                "object_lowering:prepared_assessment_changed"
                            )
                    if support.support is not SupportLevel.UNSUPPORTED:
                        candidates.append((adapter, support))
                if len(candidates) > 1:
                    raise HostExecutionDenied(
                        f"adapter_ownership_conflict:{line.line_id}"
                    )
                support = candidates[0][1] if candidates else None
                resource_conditions[line.line_id] = {
                    "resource_selector": line.selector,
                    "protected_paths": tuple(support.protected_paths)
                    if support
                    else (),
                    "required_capabilities": tuple(
                        sorted(support.required_capabilities)
                    )
                    if support
                    else (),
                }
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
                                    sorted(support.required_capabilities)
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
            grant = replace(
                grant,
                rules=tuple(
                    replace(
                        rule,
                        conditions={
                            **rule.conditions,
                            **resource_conditions[rule.rule_id],
                        },
                    )
                    if rule.rule_id in resource_conditions
                    else rule
                    for rule in grant.rules
                ),
            )
            self.host_adapter.grant = grant
            obligations = tuple(
                replace(
                    item,
                    dependencies=dependencies.get(
                        item.obligation_id, item.dependencies
                    ),
                )
                for item in compile_obligations(grant, additional=additional)
            )
            self._execution_obligations = obligations
            adapters = (self.host_adapter, *self.bound_mediators)
            if self._prepared_record is None:
                self.record, self.coordinator = negotiate_object_grant(
                    grant,
                    ledger,
                    obligations,
                    adapters,
                    self.host_adapter,
                    host,
                    expected_nonce=host.nonce,
                )
                self._used_prepared_policy = False
            else:
                self.record, self.coordinator = self._bind_prepared_policy(
                    grant, obligations, adapters, host
                )
                self._used_prepared_policy = True
            self._execution_obligations = self.record.obligations
            retained = {rule.rule_id for rule in self.record.grant.rules}
            self.credential_broker.routes = {
                key: value for key, value in routes.items() if key in retained
            }
            return self.record.grant
        except ObjectLoweringRefused as exc:
            self.lowering_refusal = {**exc.record, "object_grant": self.object_grant}
            raise
        except HostExecutionDenied:
            raise
        except Exception as exc:
            raise HostExecutionDenied(f"object_lowering:{type(exc).__name__}") from exc

    @staticmethod
    def _prepared_value(value: Any) -> Any:
        """Return a structural key without invocation-specific grant digests."""
        if isinstance(value, Mapping):
            return tuple(
                sorted(
                    (
                        str(key),
                        _ObjectWorker._prepared_value(item),
                    )
                    for key, item in value.items()
                    if key != "object_grant"
                )
            )
        if isinstance(value, tuple | list):
            return tuple(_ObjectWorker._prepared_value(item) for item in value)
        if isinstance(value, set | frozenset):
            return tuple(
                sorted(
                    (_ObjectWorker._prepared_value(item) for item in value), key=repr
                )
            )
        return value

    @classmethod
    def _prepared_rule_key(cls, rules: Sequence[GrantRule]) -> tuple[Any, ...]:
        return tuple(
            (
                rule.rule_id,
                rule.domain,
                rule.operation,
                "<prepared-runtime-path>"
                if rule.rule_id.startswith(("runtime:artifact", "runtime:tmp"))
                else rule.selector,
                cls._prepared_value(rule.conditions),
                rule.requirement,
                rule.provenance,
                rule.baseline,
            )
            for rule in rules
        )

    @classmethod
    def _prepared_obligation_key(
        cls, obligations: Sequence[EnforcementObligation]
    ) -> tuple[Any, ...]:
        return tuple(
            (
                item.obligation_id,
                item.rule_id,
                item.kind,
                item.domain,
                item.operation,
                "<prepared-runtime-path>"
                if item.rule_id.startswith(("runtime:artifact", "runtime:tmp"))
                else item.selector,
                cls._prepared_value(item.conditions),
                tuple(sorted(item.dependencies)),
                item.waivable,
            )
            for item in obligations
        )

    def _bind_prepared_policy(
        self,
        grant: Grant,
        obligations: tuple[EnforcementObligation, ...],
        adapters: tuple[Any, ...],
        host: Any,
    ) -> tuple[ObjectLoweringRecord, EnforcementCoordinator]:
        """Bind fresh identity and activation state to an exact prepared plan."""
        prepared = self._prepared_record
        if prepared is None:
            raise HostExecutionDenied("object_lowering:prepared_policy_missing")
        prepared_host = self._prepared_host_configuration
        if prepared_host is None:
            prepared_host = _host_configuration_digest(prepared.host)
        if prepared_host != _host_configuration_digest(host):
            raise HostExecutionDenied("object_lowering:prepared_host_changed")
        prepared_rules = self._prepared_rule_shape
        if prepared_rules is None:
            if prepared.candidate.rules != prepared.grant.rules:
                raise HostExecutionDenied(
                    "object_lowering:prepared_attenuation_changed"
                )
            prepared_rules = self._prepared_rule_key(prepared.candidate.rules)
        if prepared_rules != self._prepared_rule_key(grant.rules):
            raise HostExecutionDenied("object_lowering:prepared_authority_changed")
        by_id = {item.obligation_id: item for item in obligations}
        prepared_obligations = self._prepared_obligation_shape
        if prepared_obligations is None:
            prepared_obligations = self._prepared_obligation_key(prepared.obligations)
        if len(by_id) != len(
            obligations
        ) or prepared_obligations != self._prepared_obligation_key(obligations):
            raise HostExecutionDenied("object_lowering:prepared_obligations_changed")
        grouped: dict[str, list[EnforcementObligation]] = {}
        for assignment in prepared.plan.assignments:
            obligation = by_id.get(assignment.obligation_id)
            if obligation is None:
                raise HostExecutionDenied("object_lowering:prepared_assignment_changed")
            grouped.setdefault(assignment.adapter_id, []).append(obligation)
        adapter_by_id = {item.adapter_id: item for item in adapters}
        if set(grouped) != set(adapter_by_id):
            raise HostExecutionDenied("object_lowering:prepared_adapter_changed")
        prior_plans = {item.adapter_id: item for item in prepared.plan.adapter_plans}
        plans = []
        for adapter_id, assigned in sorted(grouped.items()):
            adapter = adapter_by_id[adapter_id]
            prior = prior_plans.get(adapter_id)
            obligation_ids = frozenset(item.obligation_id for item in assigned)
            if prior is None or obligation_ids != prior.obligation_ids:
                raise HostExecutionDenied("object_lowering:prepared_plan_changed")
            # The exact adapter assignments and lowering payload were negotiated
            # before the worker was launched. Bind only the fresh invocation and
            # attestation fields here; activation still rechecks live resource
            # support before the worker crosses its authorization barrier.
            payload = {
                "prepared_plan": prior.native_plan_digest,
                "grant": grant.digest,
            }
            if adapter is self.host_adapter:
                operated = {
                    item.rule_id
                    for item in assigned
                    if item.kind
                    in {ObligationKind.OPERATE, ObligationKind.RESOURCE_LIMIT}
                }
                adapter.rules = tuple(
                    rule for rule in grant.rules if rule.rule_id in operated
                )
                payload["host"] = host.digest
            else:
                adapter.grant = grant
            plan = AdapterPlan(
                adapter_id,
                obligation_ids,
                _digest(payload),
                payload,
            )
            adapter.plan = plan
            plans.append(plan)
        plan = EnforcementPlan(
            grant.digest,
            host.digest,
            _obligation_digest(obligations),
            prepared.plan.mode,
            prepared.plan.assignments,
            tuple(plans),
            prepared.plan.waived_obligations,
            prepared.plan.removed_wants,
        )
        coordinator = EnforcementCoordinator(adapters, self.host_adapter)
        return ObjectLoweringRecord(grant, grant, host, obligations, plan), coordinator

    def _seal_prepared_policy(self) -> None:
        """Cache immutable comparison state after preparation is finalized."""
        prepared = self._prepared_record
        if prepared is None:
            raise HostExecutionDenied("object_lowering:prepared_policy_missing")
        if prepared.candidate.rules != prepared.grant.rules:
            raise HostExecutionDenied("object_lowering:prepared_attenuation_changed")
        self._prepared_host_configuration = _host_configuration_digest(prepared.host)
        self._prepared_rule_shape = self._prepared_rule_key(prepared.candidate.rules)
        self._prepared_obligation_shape = self._prepared_obligation_key(
            prepared.obligations
        )
        self._prepared_mediator_assessments = MappingProxyType(
            {
                adapter.adapter_id: MappingProxyType(dict(adapter.assessments))
                for adapter in self.bound_mediators
            }
        )

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
        lifecycle_checker: LeanLifecycleChecker | None = None,
        worker_pool_capacity: int = 0,
        worker_pool_idle_s: float = 300.0,
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
        if (
            lifecycle_checker is not None
            and type(lifecycle_checker) is not LeanLifecycleChecker
        ):
            raise ValueError(
                "object broker lifecycle checker must be a pinned Lean checker"
            )
        self.lifecycle_checker = lifecycle_checker
        if (
            type(worker_pool_capacity) is not int
            or worker_pool_capacity < 0
            or worker_pool_idle_s <= 0
        ):
            raise ValueError("object broker worker pool settings must be non-negative")
        self.worker_pool_capacity = worker_pool_capacity
        if worker_pool_capacity and lifecycle_checker is not None:
            lifecycle_checker.require_inline()
        self.worker_pool_idle_s = float(worker_pool_idle_s)
        self._worker_pool_state = _LandlockWorkerPoolState.create()
        self._broker_executor = (
            ThreadPoolExecutor(
                max_workers=worker_pool_capacity,
                thread_name_prefix="slanggraph-broker",
            )
            if worker_pool_capacity
            else None
        )
        self._prepared_workers: dict[tuple[Any, ...], _ObjectWorker] = {}
        self._preparation_stats = {
            "preparations": 0,
            "prepared_path_hits": 0,
            "prepared_policy_bindings": 0,
            "policy_lowerings": 0,
            "repreparations": 0,
            "replenishments": 0,
            "fallbacks": 0,
        }
        self._audit: deque[BrokerAuditRecord] = deque(maxlen=4096)
        self._lock = RLock()
        self._lowering_records: deque[ObjectLoweringRecord] = deque(maxlen=1024)
        self._lowering_refusals: deque[Mapping[str, Any]] = deque(maxlen=1024)
        self._receipts: deque[ActivationReceipt] = deque(maxlen=1024)

    def activation_receipts(self) -> tuple[ActivationReceipt, ...]:
        """Retain verified activation evidence, including failed worker outcomes."""
        with self._lock:
            return tuple(self._receipts)

    def lowering_refusals(self) -> tuple[Mapping[str, Any], ...]:
        """Return attributable unsupported decisions without successful plans."""
        with self._lock:
            return tuple(self._lowering_refusals)

    def lowering_records(self) -> tuple[ObjectLoweringRecord, ...]:
        """Return negotiated host, baseline, obligations and effective authority."""
        with self._lock:
            return tuple(self._lowering_records)

    def audit_records(self) -> tuple[BrokerAuditRecord, ...]:
        """Return bounded broker decisions bound to worker/grant identities."""
        with self._lock:
            return tuple(self._audit)

    def worker_pool_stats(self) -> Mapping[str, int]:
        state = self._worker_pool_state
        with state.lock, self._lock:
            return MappingProxyType(
                {
                    "capacity": self.worker_pool_capacity,
                    "idle": sum(len(items) for items in state.workers.values()),
                    "hits": state.hits,
                    "misses": state.misses,
                    **self._preparation_stats,
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
        """Prepare an exact-authority worker with no attached resource grant."""
        call = replace(call, args={**call.args, **call.normalized})
        worker = self._new_worker(principal, call, grant, preflight=True)
        prepared = worker.prewarm(
            principal, call, (), count=count, asynchronous=asynchronous
        )
        worker._prepared_record = worker.record
        worker._seal_prepared_policy()
        key = _object_authority_key(grant)
        with self._lock:
            if key in self._prepared_workers:
                self._preparation_stats["repreparations"] += 1
                self._preparation_stats["replenishments"] += 1
            self._prepared_workers[key] = worker
            self._preparation_stats["preparations"] += 1
            if worker._used_prepared_policy:
                self._preparation_stats["prepared_policy_bindings"] += 1
            else:
                self._preparation_stats["policy_lowerings"] += 1
        worker.close_mediators()
        return prepared

    def close(self) -> None:
        """Terminate all unclaimed prepared workers."""
        with self._lock:
            workers = tuple(self._prepared_workers.values())
            self._prepared_workers.clear()
        if workers:
            workers[0].close()
        if self._broker_executor is not None:
            self._broker_executor.shutdown(wait=True, cancel_futures=True)

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
        worker = self._new_worker(principal, call, grant)
        broker = worker.credential_broker
        result = None
        try:
            result = worker._invoke(principal, call, (), asynchronous=asynchronous)
        except HostExecutionError as exc:
            exc.receipt = self._object_receipt(exc.receipt, grant)
            with self._lock:
                self._receipts.append(exc.receipt)
            raise
        finally:
            with self._lock:
                self._audit.extend(broker.audit_records())
                if worker._used_prepared_policy:
                    self._preparation_stats["prepared_policy_bindings"] += 1
                if getattr(worker, "lowering_refusal", None) is not None:
                    self._lowering_refusals.append(worker.lowering_refusal)
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
        receipt = self._object_receipt(result.receipt, grant)
        with self._lock:
            self._receipts.append(receipt)
        return HostExecutionResult(result.value, receipt)

    def _new_worker(
        self,
        principal: Principal,
        call: ToolCall,
        grant: ObjectGrant,
        *,
        preflight: bool = False,
    ) -> _ObjectWorker:
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
        key = _object_authority_key(grant)
        with self._lock:
            prepared = self._prepared_workers.get(key)
        broker = _ObjectBroker(
            grant, self.bindings, server_executor=self._broker_executor
        )
        if prepared is not None:
            worker = copy.copy(prepared)
            worker.object_grant = grant
            worker.credential_broker = broker
            worker.bound_mediators = ()
            worker.record = None
            worker.lowering_refusal = None
            worker._used_prepared_policy = False
            if not preflight:
                with self._lock:
                    self._preparation_stats["prepared_path_hits"] += 1
            return worker
        if self.worker_pool_capacity and not preflight:
            raise HostExecutionDenied("object_broker:prepared_policy_missing")
        profiles = parse_profiles(
            f"tool {call.tool.name} {{\n owner broker\n runs linux\n syscalls @minimal\n}}"
        )
        worker = _ObjectWorker(
            grant,
            profiles,
            {call.tool.name: self.tools[call.tool.name]},
            runtime_roots=self.runtime_roots,
            policy_backend=TypedPolicyBackend(),
            credential_broker=broker,
            mediators=self.mediators,
            default_wall_timeout_s=self.wall_timeout_s,
            lifecycle_checker=self.lifecycle_checker,
            worker_pool_capacity=self.worker_pool_capacity,
            worker_pool_idle_s=self.worker_pool_idle_s,
            _worker_pool_state=self._worker_pool_state,
        )
        worker._lean_object_route = True
        return worker

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
