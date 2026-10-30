"""Operator-supplied semantic mediators and portable object-grant negotiation.

A mediator is trusted code, not a declaration that an arbitrary callback is
safe. Its assessment must describe the exact resource semantics it implements.
The host remains responsible for closing every direct-access bypass.
"""

from __future__ import annotations

import hashlib
import hmac
import json
import secrets
import time
from collections.abc import Callable, Mapping, Sequence
from dataclasses import dataclass, replace
from pathlib import Path
from threading import RLock
from typing import Any

from langgraph.prebuilt.security.enforcement import (
    ActivationEvidence,
    AdapterPlan,
    EnforcementAdapter,
    EnforcementCoordinator,
    EnforcementObligation,
    EnforcementPlan,
    ExecutionContext,
    Grant,
    HostAttestation,
    HostAttestationVerifier,
    ObligationKind,
    RequirementLedger,
    SupportAssessment,
    SupportLevel,
)
from langgraph.prebuilt.security.execution import HostExecutionDenied
from langgraph.prebuilt.security.object_policy import ObjectGrantLine
from langgraph.prebuilt.security.profile import Requirement
from langgraph.prebuilt.security.types import _DecisionArguments


@dataclass(frozen=True, slots=True)
class ResourceSupport:
    """Exact-line assessment by a trusted semantic adapter.

    `witness` identifies the operator-reviewed contract/conformance tests, not
    an automatically verified proof. `protected_paths` names credentials or
    resource data the worker must never access directly. A stricter assessment
    must still provide useful authority; otherwise report unsupported.
    """

    support: SupportLevel
    reason: str
    witness: str = ""
    protected_paths: tuple[str, ...] = ()
    required_capabilities: frozenset[str] = frozenset()

    def __post_init__(self) -> None:
        if not isinstance(self.support, SupportLevel) or not self.reason:
            raise ValueError("resource support requires a relation and reason")
        if self.support is not SupportLevel.UNSUPPORTED and not self.witness:
            raise ValueError(
                "supported resource semantics require a conformance witness"
            )
        paths = tuple(self.protected_paths)
        if any(not Path(path).is_absolute() for path in paths):
            raise ValueError("protected resource paths must be absolute")
        object.__setattr__(self, "protected_paths", paths)
        object.__setattr__(
            self, "required_capabilities", frozenset(self.required_capabilities)
        )

    def canonical(self) -> Mapping[str, Any]:
        return {
            "support": self.support.value,
            "reason": self.reason,
            "witness": self.witness,
            "protected_paths": list(self.protected_paths),
            "required_capabilities": sorted(self.required_capabilities),
        }


@dataclass(frozen=True, slots=True)
class ResourceInvocation:
    """Parent-authenticated context supplied to a resource handler."""

    principal_id: str
    session_id: str
    tool_name: str
    call_id: str
    grant_digest: str
    worker: ExecutionContext


@dataclass(frozen=True)
class ResourceMediatorAdapter:
    """Describe and perform domain-specific operations outside the worker.

    `assess` must inspect the complete line, including selector, attributes and
    lowering strategy, against this host. `invoke` receives the authorized line
    and authenticated invocation; payloads are untrusted. `preflight`, when set,
    prepares immutable or invocation-local state before activation and worker
    release. `activate`, when set, establishes resource-side authority after a
    successful preflight. `release` tears lifecycle state down after the worker
    stops, including when preflight or activation fails. Callbacks must bound I/O
    and must not leave background work. Credentials and clients belong in these
    parent callbacks.
    """

    adapter_id: str
    assess: Callable[[ObjectGrantLine, HostAttestation], ResourceSupport]
    invoke: Callable[[ObjectGrantLine, Mapping[str, Any], ResourceInvocation], Any]
    preflight: (
        Callable[[tuple[ObjectGrantLine, ...], ResourceInvocation], None] | None
    ) = None
    activate: (
        Callable[[tuple[ObjectGrantLine, ...], ResourceInvocation], None] | None
    ) = None
    release: Callable[[ResourceInvocation], None] | None = None

    def __post_init__(self) -> None:
        if (
            not self.adapter_id
            or not callable(self.assess)
            or not callable(self.invoke)
        ):
            raise ValueError(
                "resource mediators require an identity, assess and invoke"
            )
        if any(
            callback is not None and not callable(callback)
            for callback in (self.preflight, self.activate, self.release)
        ):
            raise ValueError("mediator lifecycle hooks must be callable")


@dataclass(frozen=True, slots=True)
class ObjectLoweringRecord:
    """Inspectable input, retained authority, dependencies and negotiated plan."""

    candidate: Grant
    grant: Grant
    host: HostAttestation
    obligations: tuple[EnforcementObligation, ...]
    plan: EnforcementPlan


def negotiate_object_grant(
    grant: Grant,
    ledger: RequirementLedger,
    obligations: Sequence[EnforcementObligation],
    adapters: Sequence[EnforcementAdapter],
    verifier: HostAttestationVerifier,
    host: HostAttestation,
    *,
    expected_nonce: str,
) -> tuple[ObjectLoweringRecord, EnforcementCoordinator]:
    """Remove unenforceable optional authority, then negotiate the complete DAG.

    This function is platform-neutral. Missing default-deny, required authority,
    conflicting ownership, invalid host evidence and adapter exceptions deny.
    """
    coordinator = EnforcementCoordinator(adapters, verifier)
    try:
        # Validate trust and the original graph before using adapter assessments
        # to prune optional lines. Malformed inputs cannot disappear by pruning.
        first = coordinator.negotiate(
            grant, ledger, obligations, host, expected_nonce=expected_nonce
        )
        if first.allowed:
            assert first.plan is not None
            return ObjectLoweringRecord(
                grant, grant, host, tuple(obligations), first.plan
            ), coordinator
        if not first.reason.startswith("adapter_rule_unsupported:"):
            raise HostExecutionDenied(first.reason)
        by_id = {item.obligation_id: item for item in obligations}
        unsupported: set[str] = set()
        for obligation in obligations:
            candidates = []
            for adapter in adapters:
                assessment = adapter.assess(obligation, host)
                if (
                    assessment.adapter_id != adapter.adapter_id
                    or assessment.obligation_id != obligation.obligation_id
                    or not isinstance(assessment.support, SupportLevel)
                ):
                    raise ValueError("invalid adapter assessment")
                if assessment.support is not SupportLevel.UNSUPPORTED:
                    candidates.append(assessment)
            if len(candidates) > 1:
                raise HostExecutionDenied(
                    f"adapter_ownership_conflict:{obligation.obligation_id}"
                )
            if not candidates:
                unsupported.add(obligation.obligation_id)
        # Unsupported dependencies propagate to the semantic operation.
        while True:
            expanded = unsupported | {
                item.obligation_id
                for item in obligations
                if item.dependencies & unsupported
            }
            if expanded == unsupported:
                break
            unsupported = expanded
        if any(
            by_id[item].kind is ObligationKind.DENY_COMPLEMENT for item in unsupported
        ):
            raise HostExecutionDenied(first.reason)
        removed = {by_id[item].rule_id for item in unsupported}
        for rule in grant.rules:
            if rule.rule_id in removed and (
                rule.baseline or rule.requirement is Requirement.NEED
            ):
                raise HostExecutionDenied(f"required_authority_removed:{rule.rule_id}")
        retained = replace(
            grant,
            rules=tuple(rule for rule in grant.rules if rule.rule_id not in removed),
        )
        # A complement survives even when its original optional source rule
        # disappears. Rebind it to the domain and reassess the amended graph.
        reduced = tuple(
            replace(item, rule_id=f"domain:{item.domain.value}")
            if item.kind is ObligationKind.DENY_COMPLEMENT and item.rule_id in removed
            else item
            for item in obligations
            if item.kind is ObligationKind.DENY_COMPLEMENT
            or item.rule_id not in removed
        )
        result = coordinator.negotiate(
            retained, ledger, reduced, host, expected_nonce=expected_nonce
        )
        if not result.allowed or result.plan is None:
            raise HostExecutionDenied(result.reason)
        return ObjectLoweringRecord(
            grant, retained, host, reduced, result.plan
        ), coordinator
    except HostExecutionDenied:
        raise
    except Exception as exc:
        raise HostExecutionDenied(f"object_lowering:{type(exc).__name__}") from exc


def _digest(value: Any) -> str:
    return hashlib.sha256(
        json.dumps(value, sort_keys=True, separators=(",", ":")).encode()
    ).hexdigest()


class _LocalEvidence:
    """Per-invocation local trust anchor; never shared with the worker."""

    def __init__(self, adapter_id: str) -> None:
        self.adapter_id = adapter_id
        self._key = secrets.token_bytes(32)
        self._issued: set[str] = set()

    def _sign(self, value: str) -> str:
        return hmac.new(self._key, value.encode(), hashlib.sha256).hexdigest()

    def _evidence(
        self, plan: AdapterPlan, context: ExecutionContext, nonce: str, expires: float
    ) -> ActivationEvidence:
        now = time.time()
        evidence = ActivationEvidence(
            self.adapter_id,
            plan.native_plan_digest,
            context.digest,
            nonce,
            plan.obligation_ids,
            now,
            expires,
            "pending",
        )
        evidence = replace(evidence, signature=self._sign(_evidence_payload(evidence)))
        self._issued.add(evidence.signature)
        return evidence

    def verify_activation(self, evidence: ActivationEvidence) -> bool:
        return (
            evidence.adapter_id == self.adapter_id
            and evidence.signature in self._issued
            and hmac.compare_digest(
                evidence.signature, self._sign(_evidence_payload(evidence))
            )
        )


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


class _BoundMediator(_LocalEvidence):
    """Bind a semantic adapter to one grant and its authenticated broker channel."""

    def __init__(
        self,
        mediator: ResourceMediatorAdapter,
        lines: Sequence[ObjectGrantLine],
        host: HostAttestation,
    ) -> None:
        super().__init__(mediator.adapter_id)
        self.mediator = mediator
        self.lines = {line.line_id: line for line in lines}
        self.host = host
        self.assessments: dict[str, ResourceSupport] = {}
        self.invocation: ResourceInvocation | None = None
        self.plan: AdapterPlan | None = None
        self.grant: Grant | None = None
        self.enabled = False
        self._lock = RLock()
        self._active = 0
        self._closing = False

    def assess_line(self, line: ObjectGrantLine) -> ResourceSupport:
        value = self.mediator.assess(line, self.host)
        if not isinstance(value, ResourceSupport):
            raise ValueError("mediator assessment must be ResourceSupport")
        if not value.required_capabilities.issubset(self.host.capabilities):
            return ResourceSupport(
                SupportLevel.UNSUPPORTED, "required_host_capability_missing"
            )
        return value

    def assess(
        self, obligation: EnforcementObligation, host: HostAttestation
    ) -> SupportAssessment:
        line = self.lines.get(obligation.rule_id)
        value = self.assessments.get(obligation.rule_id)
        supported = (
            host.digest == self.host.digest
            and line is not None
            and value is not None
            and obligation.obligation_id
            in {f"rule:{line.line_id}:operate", f"resource:{line.line_id}:custody"}
        )
        return SupportAssessment(
            self.adapter_id,
            obligation.obligation_id,
            value.support if supported else SupportLevel.UNSUPPORTED,
            value.reason if supported else "not_owned_by_mediator",
            (value.witness,) if supported else (),
        )

    def lower(
        self,
        grant: Grant,
        obligations: Sequence[EnforcementObligation],
        host: HostAttestation,
    ) -> AdapterPlan:
        if host.digest != self.host.digest:
            raise ValueError("mediator host changed")
        ids = sorted({item.rule_id for item in obligations})
        payload = {
            "grant": grant.digest,
            "lines": [dict(self.lines[key].canonical()) for key in ids],
            "assessments": {
                key: dict(self.assessments[key].canonical()) for key in ids
            },
        }
        self.plan = AdapterPlan(
            self.adapter_id,
            frozenset(item.obligation_id for item in obligations),
            _digest(payload),
            payload,
        )
        self.grant = grant
        return self.plan

    def activate(
        self, plan: AdapterPlan, context: ExecutionContext, nonce: str
    ) -> ActivationEvidence:
        if (
            self.plan != plan
            or self.grant is None
            or context.broker_epoch == "no-broker"
        ):
            raise ValueError("mediator activation has no bound channel/plan")
        self.invocation = ResourceInvocation(
            self.grant.principal_id,
            self.grant.session_id,
            self.grant.tool_name,
            self.grant.call_id,
            self.grant.digest,
            context,
        )
        lines = tuple(
            line
            for key, line in self.lines.items()
            if f"rule:{key}:operate" in plan.obligation_ids
        )
        for line in lines:
            if self.assess_line(line) != self.assessments[line.line_id]:
                raise ValueError("resource support changed before activation")
        if self.mediator.preflight is not None:
            self.mediator.preflight(lines, self.invocation)
        if self.mediator.activate is not None:
            self.mediator.activate(lines, self.invocation)
        self.enabled = True
        return self._evidence(plan, context, nonce, self.host.expires_at)

    def invoke(
        self, line: ObjectGrantLine, payload: Mapping[str, Any], spawn: Any
    ) -> Any:
        with self._lock:
            invocation = self.invocation
            if (
                not self.enabled
                or invocation is None
                or time.time() >= self.host.expires_at
                or self.lines.get(line.line_id) != line
                or self.plan is None
                or f"rule:{line.line_id}:operate" not in self.plan.obligation_ids
                or spawn.nonce != invocation.worker.broker_epoch
                or spawn.grant_hash != invocation.grant_digest
                or spawn.principal_id != invocation.principal_id
                or spawn.tool_name != invocation.tool_name
            ):
                raise PermissionError(
                    "mediator channel is not active for this invocation"
                )
            self._active += 1
        try:
            if self.assess_line(line) != self.assessments[line.line_id]:
                raise PermissionError("resource support changed")
            return self.mediator.invoke(line, _DecisionArguments(payload), invocation)
        finally:
            with self._lock:
                self._active -= 1
                if self._closing and not self._active:
                    self._release()

    def _release(self) -> None:
        invocation, self.invocation = self.invocation, None
        if invocation is not None and self.mediator.release is not None:
            self.mediator.release(invocation)

    def close(self) -> None:
        with self._lock:
            self.enabled = False
            self._closing = True
            self._issued.clear()
            # An indeterminate broker operation retains its resource lease until
            # it returns. Never revoke/reuse resource state underneath active I/O.
            if not self._active:
                self._release()
