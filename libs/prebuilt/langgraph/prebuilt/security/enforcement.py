"""Platform-neutral grants, enforcement obligations, and activation evidence."""

from __future__ import annotations

import hashlib
import json
import math
import time
from collections import defaultdict
from collections.abc import Mapping, Sequence
from dataclasses import dataclass, field
from enum import Enum
from types import MappingProxyType
from typing import Any, Protocol, runtime_checkable

from langgraph.prebuilt.security.profile import (
    DacEvaluation,
    Requirement,
    SourceLocation,
)


class AuthorityDomain(str, Enum):
    """Closed-world authority domains represented by a final grant."""

    FILESYSTEM = "filesystem"
    NETWORK = "network"
    PROCESS = "process"
    IPC = "ipc"
    SERVICE = "service"
    CREDENTIAL = "credential"
    RUNTIME = "runtime"
    DELEGATION = "delegation"
    RESOURCE_LIMIT = "resource_limit"


class ObligationKind(str, Enum):
    """Role played by one independently verifiable enforcement obligation."""

    OPERATE = "operate"
    DENY_COMPLEMENT = "deny_complement"
    BYPASS_PREVENTION = "bypass_prevention"
    CREDENTIAL_CUSTODY = "credential_custody"
    AUTHENTICATED_CHANNEL = "authenticated_channel"
    RESOURCE_LIMIT = "resource_limit"
    EVIDENCE = "evidence"


class SupportLevel(str, Enum):
    """Conservative relation between an obligation and its native lowering."""

    EXACT = "exact"
    TIGHTENED = "tightened"
    STRICTER = "tightened"
    UNSUPPORTED = "unsupported"


class EnforcementMode(str, Enum):
    """Whether every guarantee was enforced or an explicit waiver was used."""

    ENFORCED = "enforced"
    DEGRADED = "degraded"


@dataclass(frozen=True, slots=True)
class GrantRule:
    """One exact, platform-neutral authority line in a final grant."""

    rule_id: str
    domain: AuthorityDomain
    operation: str
    selector: str
    conditions: Mapping[str, Any] = field(default_factory=dict)
    requirement: Requirement = Requirement.NEED
    provenance: tuple[str, ...] = ()
    baseline: bool = False

    def __post_init__(self) -> None:
        if not self.rule_id or not self.operation or not self.selector:
            raise ValueError("grant rule identifiers and selector must be non-empty")
        object.__setattr__(self, "conditions", _freeze_mapping(self.conditions))
        object.__setattr__(self, "provenance", tuple(self.provenance))

    def canonical(self) -> Mapping[str, Any]:
        """Return the canonical digest payload for this authority line."""
        return {
            "baseline": self.baseline,
            "conditions": _plain(self.conditions),
            "domain": self.domain.value,
            "operation": self.operation,
            "provenance": list(self.provenance),
            "requirement": self.requirement.value,
            "rule_id": self.rule_id,
            "selector": self.selector,
        }


@dataclass(frozen=True, slots=True)
class Grant:
    """Exact authority authorized for one principal, artifact, and normalized call."""

    principal_id: str
    session_id: str
    tool_name: str
    artifact_digest: str
    call_id: str
    normalized_intent_digest: str
    policy_digest: str
    rules: tuple[GrantRule, ...]
    deployment_digest: str = ""
    runtime_digest: str = ""
    _digest_value: str = field(init=False, repr=False, compare=False, default="")

    def __post_init__(self) -> None:
        identifiers = (
            self.principal_id,
            self.session_id,
            self.tool_name,
            self.artifact_digest,
            self.call_id,
            self.normalized_intent_digest,
            self.policy_digest,
        )
        if not all(identifiers):
            raise ValueError("grant identity and digest fields must be non-empty")
        rules = tuple(self.rules)
        rule_ids = [rule.rule_id for rule in rules]
        if len(rule_ids) != len(set(rule_ids)):
            raise ValueError("grant rule IDs must be unique")
        object.__setattr__(self, "rules", rules)

    @property
    def digest(self) -> str:
        """Return a canonical SHA-256 digest of the complete authorized authority."""
        cached = self._digest_value
        if cached:
            return cached
        cached = _digest(
            {
                "artifact_digest": self.artifact_digest,
                "call_id": self.call_id,
                "normalized_intent_digest": self.normalized_intent_digest,
                "policy_digest": self.policy_digest,
                "principal_id": self.principal_id,
                "rules": [
                    rule.canonical() for rule in sorted(self.rules, key=_rule_key)
                ],
                "session_id": self.session_id,
                "tool_name": self.tool_name,
                **(
                    {"deployment_digest": self.deployment_digest}
                    if self.deployment_digest
                    else {}
                ),
                **(
                    {"runtime_digest": self.runtime_digest}
                    if self.runtime_digest
                    else {}
                ),
            }
        )
        object.__setattr__(self, "_digest_value", cached)
        return cached


@dataclass(frozen=True, slots=True)
class RequirementEntry:
    """Source requirement and the final grant rules derived from it."""

    source_id: str
    requirement: Requirement
    rule_ids: frozenset[str]

    def __post_init__(self) -> None:
        if not self.source_id:
            raise ValueError("requirement entries need a source identity")
        object.__setattr__(self, "rule_ids", frozenset(self.rule_ids))


@dataclass(frozen=True, slots=True)
class RequirementCheck:
    """Result of revalidating source requirements after authority reduction."""

    allowed: bool
    missing_needs: tuple[str, ...] = ()
    removed_wants: tuple[str, ...] = ()


@dataclass(frozen=True, slots=True)
class RequirementLedger:
    """Track `need` and `want` descendants through every restrictive stage."""

    entries: tuple[RequirementEntry, ...]

    def __post_init__(self) -> None:
        entries = tuple(self.entries)
        source_ids = [entry.source_id for entry in entries]
        if len(source_ids) != len(set(source_ids)):
            raise ValueError("requirement source IDs must be unique")
        object.__setattr__(self, "entries", entries)

    def recheck(self, active_rule_ids: frozenset[str]) -> RequirementCheck:
        """Fail when no fully enforced descendant remains for a required source."""
        missing_needs: list[str] = []
        removed_wants: list[str] = []
        for entry in self.entries:
            if entry.rule_ids.isdisjoint(active_rule_ids):
                if entry.requirement is Requirement.NEED:
                    missing_needs.append(entry.source_id)
                else:
                    removed_wants.append(entry.source_id)
        return RequirementCheck(
            not missing_needs,
            tuple(sorted(missing_needs)),
            tuple(sorted(removed_wants)),
        )


@dataclass(frozen=True, slots=True)
class GrantCompilation:
    """Final grant plus the requirement lineage used by later reductions."""

    grant: Grant
    ledger: RequirementLedger


def compile_grant(
    evaluation: DacEvaluation,
    *,
    principal_id: str,
    session_id: str,
    artifact_digest: str,
    call_id: str,
    normalized_intent_digest: str,
    policy_digest: str,
    baseline_rules: Sequence[GrantRule] = (),
    deployment_digest: str = "",
    runtime_digest: str = "",
) -> GrantCompilation:
    """Materialize an attributed, exact grant from a successful DAC result."""
    if evaluation.denied:
        raise ValueError("cannot compile a grant from a denied DAC evaluation")
    constructive = evaluation.grant
    if constructive.subject[0] != principal_id:
        raise ValueError("grant principal does not match the DAC subject")

    rules: list[GrantRule] = []
    descendants: dict[str, set[str]] = defaultdict(set)
    requirements: dict[str, Requirement] = {}

    def add_rule(
        *,
        source_id: str,
        requirement: Requirement,
        domain: AuthorityDomain,
        operation: str,
        selector: str,
        conditions: Mapping[str, Any] | None = None,
        provenance: tuple[str, ...] = (),
        baseline: bool = False,
    ) -> None:
        prior = requirements.setdefault(source_id, requirement)
        if prior is not requirement:
            raise ValueError(f"source requirement changed:{source_id}")
        material = {
            "conditions": _plain(conditions or {}),
            "domain": domain.value,
            "operation": operation,
            "selector": selector,
            "source_id": source_id,
        }
        rule_id = f"{source_id}:{_digest(material)[:16]}"
        rule = GrantRule(
            rule_id,
            domain,
            operation,
            selector,
            conditions or {},
            requirement,
            provenance,
            baseline,
        )
        if any(existing.rule_id == rule_id for existing in rules):
            raise ValueError(f"duplicate derived grant rule:{rule_id}")
        rules.append(rule)
        descendants[source_id].add(rule_id)

    for fs_line in constructive.fs:
        source_id = _required_source_id("fs", fs_line.source_id)
        provenance = _source_provenance(fs_line.source)
        for operation in sorted(fs_line.operations):
            add_rule(
                source_id=source_id,
                requirement=fs_line.requirement,
                domain=AuthorityDomain.FILESYSTEM,
                operation=operation,
                selector=fs_line.path.value,
                conditions={"subtree": fs_line.path.subtree},
                provenance=provenance,
            )
    for net_line in constructive.net:
        add_rule(
            source_id=_required_source_id("net", net_line.source_id),
            requirement=net_line.requirement,
            domain=AuthorityDomain.NETWORK,
            operation=net_line.operation,
            selector=str(net_line.port),
            conditions={"protocol": "tcp"},
            provenance=_source_provenance(net_line.source),
        )
    for exec_line in constructive.exec:
        add_rule(
            source_id=_required_source_id("exec", exec_line.source_id),
            requirement=exec_line.requirement,
            domain=AuthorityDomain.PROCESS,
            operation="exec",
            selector=exec_line.path.value,
            conditions={"subtree": exec_line.path.subtree},
            provenance=_source_provenance(exec_line.source),
        )
    for service_line in constructive.services:
        add_rule(
            source_id=_required_source_id("service", service_line.source_id),
            requirement=service_line.requirement,
            domain=AuthorityDomain.SERVICE,
            operation="invoke",
            selector=service_line.kind,
            conditions=service_line.attributes,
            provenance=_source_provenance(service_line.source),
        )
    for syscall_set in sorted(constructive.syscall_sets):
        add_rule(
            source_id=f"syscall:{syscall_set}",
            requirement=Requirement.NEED,
            domain=AuthorityDomain.PROCESS,
            operation="syscall_set",
            selector=syscall_set,
        )
    for limit_name in ("cpu_ms", "memory_bytes", "pids", "nofile", "wall_ms"):
        value = getattr(constructive.limits, limit_name)
        if value is not None:
            add_rule(
                source_id=f"limit:{limit_name}",
                requirement=Requirement.NEED,
                domain=AuthorityDomain.RESOURCE_LIMIT,
                operation="limit",
                selector=limit_name,
                conditions={"maximum": value},
            )
    if constructive.delegable:
        add_rule(
            source_id="delegation:enabled",
            requirement=Requirement.NEED,
            domain=AuthorityDomain.DELEGATION,
            operation="delegate",
            selector="child",
        )

    for baseline_rule in baseline_rules:
        if not baseline_rule.baseline:
            raise ValueError("runtime baseline rules must set baseline=True")
        if baseline_rule.requirement is not Requirement.NEED:
            raise ValueError("runtime baseline rules must be non-waivable needs")
        if any(existing.rule_id == baseline_rule.rule_id for existing in rules):
            raise ValueError(f"duplicate baseline grant rule:{baseline_rule.rule_id}")
        rules.append(baseline_rule)
        source_id = f"baseline:{baseline_rule.rule_id}"
        requirements[source_id] = Requirement.NEED
        descendants[source_id].add(baseline_rule.rule_id)

    grant = Grant(
        principal_id,
        session_id,
        constructive.subject[1],
        artifact_digest,
        call_id,
        normalized_intent_digest,
        policy_digest,
        tuple(rules),
        deployment_digest,
        runtime_digest,
    )
    ledger = RequirementLedger(
        tuple(
            RequirementEntry(source_id, requirements[source_id], frozenset(rule_ids))
            for source_id, rule_ids in sorted(descendants.items())
        )
    )
    return GrantCompilation(grant, ledger)


@dataclass(frozen=True, slots=True)
class EnforcementObligation:
    """One exact enforcement guarantee assigned independently to an adapter."""

    obligation_id: str
    rule_id: str
    kind: ObligationKind
    domain: AuthorityDomain
    operation: str
    selector: str
    conditions: Mapping[str, Any] = field(default_factory=dict)
    dependencies: frozenset[str] = frozenset()
    waivable: bool = False

    def __post_init__(self) -> None:
        if not all((self.obligation_id, self.rule_id, self.operation, self.selector)):
            raise ValueError("obligation identity and selector must be non-empty")
        object.__setattr__(self, "conditions", _freeze_mapping(self.conditions))
        object.__setattr__(self, "dependencies", frozenset(self.dependencies))
        if self.obligation_id in self.dependencies:
            raise ValueError("an obligation cannot depend on itself")
        if self.kind is ObligationKind.DENY_COMPLEMENT and self.waivable:
            raise ValueError("closed-world complement obligations are non-waivable")

    def canonical(self) -> Mapping[str, Any]:
        """Return the canonical digest payload for this obligation."""
        return {
            "conditions": _plain(self.conditions),
            "dependencies": sorted(self.dependencies),
            "domain": self.domain.value,
            "kind": self.kind.value,
            "obligation_id": self.obligation_id,
            "operation": self.operation,
            "rule_id": self.rule_id,
            "selector": self.selector,
            "waivable": self.waivable,
        }


def compile_obligations(
    grant: Grant,
    *,
    additional: Sequence[EnforcementObligation] = (),
) -> tuple[EnforcementObligation, ...]:
    """Expand a grant into operation and all-domain default-deny obligations."""
    obligations: list[EnforcementObligation] = []
    for rule in grant.rules:
        kind = (
            ObligationKind.RESOURCE_LIMIT
            if rule.domain is AuthorityDomain.RESOURCE_LIMIT
            else ObligationKind.OPERATE
        )
        obligations.append(
            EnforcementObligation(
                f"rule:{rule.rule_id}:operate",
                rule.rule_id,
                kind,
                rule.domain,
                rule.operation,
                rule.selector,
                rule.conditions,
                waivable=(rule.requirement is Requirement.WANT and not rule.baseline),
            )
        )
    for domain in AuthorityDomain:
        obligations.append(
            EnforcementObligation(
                f"domain:{domain.value}:deny_complement",
                f"domain:{domain.value}",
                ObligationKind.DENY_COMPLEMENT,
                domain,
                "deny_unlisted",
                "*",
            )
        )
    obligations.extend(additional)
    identifiers = [item.obligation_id for item in obligations]
    if len(identifiers) != len(set(identifiers)):
        raise ValueError("compiled obligation IDs must be unique")
    return tuple(obligations)


@dataclass(frozen=True, slots=True)
class HostAttestation:
    """Trust-anchored host evidence used for one negotiation freshness window."""

    issuer: str
    nonce: str
    boot_id: str
    platform: str
    issued_at: float
    expires_at: float
    capabilities: frozenset[str]
    context: Mapping[str, str]
    evidence: Mapping[str, Any]
    signature: str
    _digest_value: str = field(init=False, repr=False, compare=False)

    def __post_init__(self) -> None:
        if not all(
            (self.issuer, self.nonce, self.boot_id, self.platform, self.signature)
        ):
            raise ValueError("host attestation identity fields must be non-empty")
        if self.issued_at <= 0 or self.expires_at <= self.issued_at:
            raise ValueError("host attestation freshness window is invalid")
        object.__setattr__(self, "capabilities", frozenset(self.capabilities))
        object.__setattr__(self, "context", _freeze_string_mapping(self.context))
        object.__setattr__(self, "evidence", _freeze_mapping(self.evidence))
        object.__setattr__(
            self,
            "_digest_value",
            _digest(
                {
                    "boot_id": self.boot_id,
                    "capabilities": sorted(self.capabilities),
                    "context": dict(self.context),
                    "evidence": _plain(self.evidence),
                    "expires_at": self.expires_at,
                    "issued_at": self.issued_at,
                    "issuer": self.issuer,
                    "nonce": self.nonce,
                    "platform": self.platform,
                }
            ),
        )

    @property
    def digest(self) -> str:
        """Hash the authenticated statement; the hash is not itself authentication."""
        return self._digest_value


@runtime_checkable
class HostAttestationVerifier(Protocol):
    """Trust-anchor verifier for host evidence."""

    def verify(self, attestation: HostAttestation) -> bool:
        """Return whether the statement has a valid authenticated trust chain."""
        ...


@dataclass(frozen=True, slots=True)
class SupportAssessment:
    """One adapter's rule-specific support statement for an obligation."""

    adapter_id: str
    obligation_id: str
    support: SupportLevel
    reason: str
    evidence_requirements: tuple[str, ...] = ()

    def __post_init__(self) -> None:
        if not self.adapter_id or not self.obligation_id or not self.reason:
            raise ValueError("support assessment fields must be non-empty")
        object.__setattr__(
            self, "evidence_requirements", tuple(self.evidence_requirements)
        )


@dataclass(frozen=True, slots=True)
class AdapterPlan:
    """Opaque native plan plus the exact obligations it claims to enforce."""

    adapter_id: str
    obligation_ids: frozenset[str]
    native_plan_digest: str
    payload: Mapping[str, Any] = field(default_factory=dict)

    def __post_init__(self) -> None:
        if (
            not self.adapter_id
            or not self.obligation_ids
            or not self.native_plan_digest
        ):
            raise ValueError("adapter plans require identity, obligations, and digest")
        object.__setattr__(self, "obligation_ids", frozenset(self.obligation_ids))
        object.__setattr__(self, "payload", _freeze_mapping(self.payload))


@dataclass(frozen=True, slots=True)
class ActivationEvidence:
    """Adapter-signed evidence that one native plan is active for one worker."""

    adapter_id: str
    native_plan_digest: str
    context_digest: str
    nonce: str
    obligation_ids: frozenset[str]
    activated_at: float
    expires_at: float
    signature: str

    def __post_init__(self) -> None:
        if not all(
            (
                self.adapter_id,
                self.native_plan_digest,
                self.context_digest,
                self.nonce,
                self.signature,
            )
        ):
            raise ValueError("activation evidence identity fields must be non-empty")
        if self.activated_at <= 0 or self.expires_at <= self.activated_at:
            raise ValueError("activation evidence freshness window is invalid")
        object.__setattr__(self, "obligation_ids", frozenset(self.obligation_ids))


@runtime_checkable
class EnforcementAdapter(Protocol):
    """Platform-specific lowering and activation contract."""

    @property
    def adapter_id(self) -> str:
        """Return a stable operator-selected adapter identity."""
        ...

    def assess(
        self, obligation: EnforcementObligation, host: HostAttestation
    ) -> SupportAssessment:
        """Assess the exact obligation rather than only its resource class."""
        ...

    def lower(
        self,
        grant: Grant,
        obligations: Sequence[EnforcementObligation],
        host: HostAttestation,
    ) -> AdapterPlan:
        """Compile an exact or stricter native plan for assigned obligations."""
        ...

    def activate(
        self, plan: AdapterPlan, context: ExecutionContext, nonce: str
    ) -> ActivationEvidence:
        """Activate a plan and return worker-bound evidence before import."""
        ...

    def verify_activation(self, evidence: ActivationEvidence) -> bool:
        """Verify activation evidence against this adapter's trust anchor."""
        ...


@dataclass(frozen=True, slots=True)
class ExecutionContext:
    """Stable identity of the worker and authority-bearing execution context."""

    worker_id: str
    process_identity: str
    boot_id: str
    namespaces: Mapping[str, str]
    credential_digest: str
    cgroup_id: str
    broker_epoch: str
    _digest_value: str = field(init=False, repr=False, compare=False)

    def __post_init__(self) -> None:
        if not all(
            (
                self.worker_id,
                self.process_identity,
                self.boot_id,
                self.credential_digest,
                self.cgroup_id,
                self.broker_epoch,
            )
        ):
            raise ValueError("execution context identity fields must be non-empty")
        object.__setattr__(self, "namespaces", _freeze_string_mapping(self.namespaces))
        object.__setattr__(
            self,
            "_digest_value",
            _digest(
                {
                    "boot_id": self.boot_id,
                    "broker_epoch": self.broker_epoch,
                    "cgroup_id": self.cgroup_id,
                    "credential_digest": self.credential_digest,
                    "namespaces": dict(self.namespaces),
                    "process_identity": self.process_identity,
                    "worker_id": self.worker_id,
                }
            ),
        )

    @property
    def digest(self) -> str:
        """Return the context digest bound into every activation statement."""
        return self._digest_value


@dataclass(frozen=True, slots=True)
class ObligationAssignment:
    """Primary adapter and conservative support relation for one obligation."""

    obligation_id: str
    adapter_id: str
    support: SupportLevel


@dataclass(frozen=True, slots=True)
class EnforcementPlan:
    """Complete adapter assignment and native plans for one exact grant."""

    grant_digest: str
    host_digest: str
    obligation_digest: str
    mode: EnforcementMode
    assignments: tuple[ObligationAssignment, ...]
    adapter_plans: tuple[AdapterPlan, ...]
    waived_obligations: tuple[str, ...] = ()
    removed_wants: tuple[str, ...] = ()
    _digest_value: str = field(init=False, repr=False, compare=False, default="")

    @property
    def digest(self) -> str:
        """Return a canonical digest of assignments, plans, and reductions."""
        cached = self._digest_value
        if cached:
            return cached
        cached = _digest(
            {
                "adapter_plans": [
                    {
                        "adapter_id": plan.adapter_id,
                        "native_plan_digest": plan.native_plan_digest,
                        "obligation_ids": sorted(plan.obligation_ids),
                    }
                    for plan in sorted(
                        self.adapter_plans, key=lambda item: item.adapter_id
                    )
                ],
                "assignments": [
                    {
                        "adapter_id": item.adapter_id,
                        "obligation_id": item.obligation_id,
                        "support": item.support.value,
                    }
                    for item in sorted(
                        self.assignments, key=lambda value: value.obligation_id
                    )
                ],
                "grant_digest": self.grant_digest,
                "host_digest": self.host_digest,
                "mode": self.mode.value,
                "obligation_digest": self.obligation_digest,
                "removed_wants": list(self.removed_wants),
                "waived_obligations": list(self.waived_obligations),
            }
        )
        object.__setattr__(self, "_digest_value", cached)
        return cached


@dataclass(frozen=True, slots=True)
class NegotiationResult:
    """Fail-closed result of exact obligation negotiation and lowering."""

    plan: EnforcementPlan | None
    reason: str
    missing_obligations: tuple[str, ...] = ()

    @property
    def allowed(self) -> bool:
        """Whether a complete enforced or explicitly degraded plan exists."""
        return self.plan is not None


@dataclass(frozen=True, slots=True)
class RuleEnforcement:
    """Per-rule lowering relation persisted with activation evidence."""

    rule_id: str
    support: SupportLevel
    mechanism: str

    def __post_init__(self) -> None:
        if not self.rule_id or not self.mechanism:
            raise ValueError("rule enforcement fields must be non-empty")


@dataclass(frozen=True, slots=True)
class ActivationReceipt:
    """Verified evidence bundle required before releasing one worker."""

    grant_digest: str
    plan_digest: str
    host_digest: str
    context_digest: str
    nonce: str
    mode: EnforcementMode
    evidence: tuple[ActivationEvidence, ...]
    activated_obligations: frozenset[str]
    valid_until: float
    rule_enforcement: tuple[RuleEnforcement, ...] = ()
    artifact_digest: str = ""
    deployment_digest: str = ""
    runtime_digest: str = ""
    removed_wants: tuple[str, ...] = ()

    def __post_init__(self) -> None:
        if self.valid_until <= 0:
            raise ValueError("activation receipt expiry must be positive")
        object.__setattr__(self, "rule_enforcement", tuple(self.rule_enforcement))
        object.__setattr__(self, "removed_wants", tuple(self.removed_wants))

    def canonical(self) -> Mapping[str, Any]:
        """Return complete canonical evidence suitable for durable audit."""
        return {
            "activated_obligations": sorted(self.activated_obligations),
            "context_digest": self.context_digest,
            "evidence": [
                {
                    "activated_at": item.activated_at,
                    "adapter_id": item.adapter_id,
                    "context_digest": item.context_digest,
                    "expires_at": item.expires_at,
                    "native_plan_digest": item.native_plan_digest,
                    "nonce": item.nonce,
                    "obligation_ids": sorted(item.obligation_ids),
                    "signature": item.signature,
                }
                for item in sorted(self.evidence, key=lambda value: value.adapter_id)
            ],
            "grant_digest": self.grant_digest,
            "host_digest": self.host_digest,
            "mode": self.mode.value,
            "nonce": self.nonce,
            "plan_digest": self.plan_digest,
            "rule_enforcement": [
                {
                    "mechanism": item.mechanism,
                    "rule_id": item.rule_id,
                    "support": item.support.value,
                }
                for item in sorted(
                    self.rule_enforcement, key=lambda value: value.rule_id
                )
            ],
            "valid_until": self.valid_until,
            **(
                {"removed_wants": list(self.removed_wants)}
                if self.removed_wants
                else {}
            ),
            **(
                {"artifact_digest": self.artifact_digest}
                if self.artifact_digest
                else {}
            ),
            **(
                {"deployment_digest": self.deployment_digest}
                if self.deployment_digest
                else {}
            ),
            **({"runtime_digest": self.runtime_digest} if self.runtime_digest else {}),
        }

    @property
    def digest(self) -> str:
        """Return the canonical SHA-256 digest of this receipt."""
        return _digest(self.canonical())

    def audit_reason(self) -> str:
        """Serialize complete activation evidence into an audit-safe reason."""
        return "activation_receipt:" + json.dumps(
            self.canonical(), sort_keys=True, separators=(",", ":")
        )


class EnforcementCoordinator:
    """Fail-closed negotiation and worker-activation coordinator."""

    def __init__(
        self,
        adapters: Sequence[EnforcementAdapter],
        host_verifier: HostAttestationVerifier,
    ) -> None:
        adapter_map = {adapter.adapter_id: adapter for adapter in adapters}
        if len(adapter_map) != len(adapters) or not adapter_map:
            raise ValueError("adapter identities must be unique and non-empty")
        self._adapters = MappingProxyType(adapter_map)
        self._host_verifier = host_verifier

    def negotiate(
        self,
        grant: Grant,
        ledger: RequirementLedger,
        obligations: Sequence[EnforcementObligation],
        host: HostAttestation,
        *,
        expected_nonce: str,
        owners: Mapping[str, str] | None = None,
        waivers: frozenset[str] = frozenset(),
        now: float | None = None,
    ) -> NegotiationResult:
        """Verify host evidence, assign exact obligations, and lower adapter plans."""
        timestamp = time.time() if now is None else now
        evidence_error = self._validate_host(host, expected_nonce, timestamp)
        if evidence_error is not None:
            return NegotiationResult(None, evidence_error)
        obligation_map = {item.obligation_id: item for item in obligations}
        if len(obligation_map) != len(obligations):
            return NegotiationResult(None, "obligation_duplicate_identity")
        structure_error = _validate_obligations(grant, obligation_map)
        if structure_error is not None:
            return NegotiationResult(None, structure_error)
        selection, waived, reason = self._select_adapters(
            obligation_map, host, owners or {}, waivers
        )
        if reason is not None:
            return NegotiationResult(None, reason, tuple(sorted(waived)))
        active_rule_ids = _fully_enforced_rules(obligation_map, selection, waived)
        check = ledger.recheck(active_rule_ids)
        if not check.allowed:
            return NegotiationResult(
                None,
                f"required_authority_removed:{','.join(check.missing_needs)}",
                tuple(sorted(waived)),
            )
        try:
            plans = self._lower(grant, host, obligation_map, selection)
        except Exception as exc:
            return NegotiationResult(
                None, f"adapter_lowering_failed:{type(exc).__name__}"
            )
        assignments = tuple(
            ObligationAssignment(key, assessment.adapter_id, assessment.support)
            for key, assessment in sorted(selection.items())
        )
        mode = EnforcementMode.DEGRADED if waived else EnforcementMode.ENFORCED
        plan = EnforcementPlan(
            grant.digest,
            host.digest,
            _obligation_digest(obligations),
            mode,
            assignments,
            plans,
            tuple(sorted(waived)),
            check.removed_wants,
        )
        return NegotiationResult(plan, "allow")

    def activate(
        self,
        grant: Grant,
        plan: EnforcementPlan,
        host: HostAttestation,
        context: ExecutionContext,
        *,
        nonce: str,
        now: float | None = None,
    ) -> ActivationReceipt:
        """Activate every native plan and verify worker-bound evidence."""
        timestamp = time.time() if now is None else now
        if plan.grant_digest != grant.digest or plan.host_digest != host.digest:
            raise ValueError("activation inputs do not match the negotiated plan")
        host_error = self._validate_host(host, host.nonce, timestamp)
        if host_error is not None:
            raise ValueError(host_error)
        if context.boot_id != host.boot_id:
            raise ValueError("worker boot identity differs from host attestation")
        plans = _assigned_adapter_plans(plan)
        if not nonce:
            raise ValueError("activation nonce must be non-empty")
        if not plans.keys() <= self._adapters.keys():
            raise ValueError("activation plan references an unknown adapter")
        evidence: list[ActivationEvidence] = []
        activated: set[str] = set()
        for adapter_plan in plans.values():
            adapter = self._adapters[adapter_plan.adapter_id]
            item = adapter.activate(adapter_plan, context, nonce)
            validation_time = time.time() if now is None else timestamp
            _validate_activation(item, adapter_plan, context, nonce, validation_time)
            if not adapter.verify_activation(item):
                raise ValueError(f"activation evidence rejected:{adapter.adapter_id}")
            evidence.append(item)
            activated.update(item.obligation_ids)
        expected = {assignment.obligation_id for assignment in plan.assignments}
        if activated != expected:
            raise ValueError(
                "activation evidence does not cover every assigned obligation"
            )
        return ActivationReceipt(
            grant.digest,
            plan.digest,
            host.digest,
            context.digest,
            nonce,
            plan.mode,
            tuple(evidence),
            frozenset(activated),
            min(host.expires_at, *(item.expires_at for item in evidence)),
            tuple(
                RuleEnforcement(
                    assignment.obligation_id.removeprefix("rule:").removesuffix(
                        ":operate"
                    ),
                    assignment.support,
                    assignment.adapter_id,
                )
                for assignment in plan.assignments
                if assignment.obligation_id.startswith("rule:")
                and assignment.obligation_id.endswith(":operate")
            ),
            grant.artifact_digest,
            grant.deployment_digest,
            grant.runtime_digest,
            plan.removed_wants,
        )

    def validate_receipt(
        self,
        receipt: ActivationReceipt,
        grant: Grant,
        plan: EnforcementPlan,
        host: HostAttestation,
        context: ExecutionContext,
        *,
        now: float | None = None,
    ) -> bool:
        """Revalidate live host, worker, broker, credential, and adapter evidence."""
        timestamp = time.time() if now is None else now
        if (
            not math.isfinite(timestamp)
            or not math.isfinite(receipt.valid_until)
            or timestamp > receipt.valid_until
            or receipt.valid_until > host.expires_at
            or not receipt.nonce
        ):
            return False
        if self._validate_host(host, host.nonce, timestamp) is not None:
            return False
        if (
            plan.grant_digest != grant.digest
            or plan.host_digest != host.digest
            or context.boot_id != host.boot_id
            or receipt.grant_digest != grant.digest
            or receipt.plan_digest != plan.digest
            or receipt.host_digest != host.digest
            or receipt.context_digest != context.digest
            or receipt.mode is not plan.mode
            or receipt.artifact_digest != grant.artifact_digest
            or receipt.deployment_digest != grant.deployment_digest
            or receipt.runtime_digest != grant.runtime_digest
            or receipt.removed_wants != plan.removed_wants
        ):
            return False
        expected = {assignment.obligation_id for assignment in plan.assignments}
        if receipt.activated_obligations != expected:
            return False
        expected_rules = tuple(
            RuleEnforcement(
                assignment.obligation_id.removeprefix("rule:").removesuffix(":operate"),
                assignment.support,
                assignment.adapter_id,
            )
            for assignment in plan.assignments
            if assignment.obligation_id.startswith("rule:")
            and assignment.obligation_id.endswith(":operate")
        )
        if receipt.rule_enforcement != expected_rules:
            return False
        try:
            plans = _assigned_adapter_plans(plan)
            if len(receipt.evidence) != len(plans):
                return False
            verified_adapters: set[str] = set()
            verified_obligations: set[str] = set()
            for evidence in receipt.evidence:
                if evidence.adapter_id in verified_adapters:
                    return False
                adapter = self._adapters[evidence.adapter_id]
                adapter_plan = plans[evidence.adapter_id]
                _validate_activation(
                    evidence, adapter_plan, context, receipt.nonce, timestamp
                )
                if not adapter.verify_activation(evidence):
                    return False
                if receipt.valid_until > evidence.expires_at:
                    return False
                verified_adapters.add(evidence.adapter_id)
                verified_obligations.update(evidence.obligation_ids)
        except (KeyError, ValueError):
            return False
        return (
            verified_adapters == plans.keys()
            and verified_obligations == expected
            and receipt.activated_obligations == verified_obligations
        )

    def _validate_host(
        self, host: HostAttestation, nonce: str, timestamp: float
    ) -> str | None:
        if host.nonce != nonce:
            return "host_attestation_failed:nonce"
        if (
            not all(
                math.isfinite(value)
                for value in (timestamp, host.issued_at, host.expires_at)
            )
            or timestamp < host.issued_at
            or timestamp > host.expires_at
        ):
            return "host_attestation_failed:freshness"
        if not self._host_verifier.verify(host):
            return "host_attestation_failed:trust"
        return None

    def _select_adapters(
        self,
        obligations: Mapping[str, EnforcementObligation],
        host: HostAttestation,
        owners: Mapping[str, str],
        waivers: frozenset[str],
    ) -> tuple[dict[str, SupportAssessment], set[str], str | None]:
        selected: dict[str, SupportAssessment] = {}
        waived: set[str] = set()
        for obligation_id, obligation in sorted(obligations.items()):
            candidates = self._supporting(obligation, host)
            owner = owners.get(obligation_id)
            if owner is not None:
                candidates = [item for item in candidates if item.adapter_id == owner]
            if len(candidates) == 1:
                selected[obligation_id] = candidates[0]
                continue
            if len(candidates) > 1:
                return {}, waived, f"adapter_ownership_conflict:{obligation_id}"
            if obligation.waivable and obligation_id in waivers:
                waived.add(obligation_id)
                continue
            return {}, waived, f"adapter_rule_unsupported:{obligation_id}"
        return selected, waived, None

    def _supporting(
        self, obligation: EnforcementObligation, host: HostAttestation
    ) -> list[SupportAssessment]:
        supported: list[SupportAssessment] = []
        for adapter in self._adapters.values():
            assessment = adapter.assess(obligation, host)
            if assessment.adapter_id != adapter.adapter_id:
                raise ValueError("adapter returned another adapter's identity")
            if assessment.obligation_id != obligation.obligation_id:
                raise ValueError("adapter assessed a different obligation")
            if not isinstance(assessment.support, SupportLevel):
                raise ValueError("adapter returned an invalid support relation")
            if assessment.support is not SupportLevel.UNSUPPORTED:
                supported.append(assessment)
        return supported

    def _lower(
        self,
        grant: Grant,
        host: HostAttestation,
        obligations: Mapping[str, EnforcementObligation],
        selection: Mapping[str, SupportAssessment],
    ) -> tuple[AdapterPlan, ...]:
        grouped: dict[str, list[EnforcementObligation]] = defaultdict(list)
        for obligation_id, assessment in selection.items():
            grouped[assessment.adapter_id].append(obligations[obligation_id])
        plans: list[AdapterPlan] = []
        for adapter_id, assigned in sorted(grouped.items()):
            plan = self._adapters[adapter_id].lower(grant, tuple(assigned), host)
            expected = frozenset(item.obligation_id for item in assigned)
            if plan.adapter_id != adapter_id or plan.obligation_ids != expected:
                raise ValueError("adapter plan does not match assigned obligations")
            plans.append(plan)
        return tuple(plans)


def _validate_obligations(
    grant: Grant, obligations: Mapping[str, EnforcementObligation]
) -> str | None:
    if not obligations:
        return "obligations_missing"
    rule_ids = {rule.rule_id for rule in grant.rules}
    operated = {
        item.rule_id
        for item in obligations.values()
        if item.kind in {ObligationKind.OPERATE, ObligationKind.RESOURCE_LIMIT}
    }
    if not rule_ids.issubset(operated):
        return "obligation_operation_missing"
    if any(
        item.rule_id not in rule_ids
        and not (
            item.kind is ObligationKind.DENY_COMPLEMENT
            and item.rule_id == f"domain:{item.domain.value}"
        )
        for item in obligations.values()
    ):
        return "obligation_unknown_rule"
    obligation_ids = set(obligations)
    if any(
        not item.dependencies.issubset(obligation_ids) for item in obligations.values()
    ):
        return "obligation_dependency_missing"
    complemented = {
        item.domain
        for item in obligations.values()
        if item.kind is ObligationKind.DENY_COMPLEMENT
    }
    missing = set(AuthorityDomain) - complemented
    if missing:
        return "default_deny_missing:" + ",".join(
            sorted(item.value for item in missing)
        )
    if _has_dependency_cycle(obligations):
        return "obligation_dependency_cycle"
    return None


def _has_dependency_cycle(
    obligations: Mapping[str, EnforcementObligation],
) -> bool:
    visiting: set[str] = set()
    visited: set[str] = set()

    def visit(obligation_id: str) -> bool:
        if obligation_id in visiting:
            return True
        if obligation_id in visited:
            return False
        visiting.add(obligation_id)
        if any(visit(item) for item in obligations[obligation_id].dependencies):
            return True
        visiting.remove(obligation_id)
        visited.add(obligation_id)
        return False

    return any(visit(obligation_id) for obligation_id in obligations)


def _fully_enforced_rules(
    obligations: Mapping[str, EnforcementObligation],
    selection: Mapping[str, SupportAssessment],
    waived: set[str],
) -> frozenset[str]:
    by_rule: dict[str, set[str]] = defaultdict(set)
    for obligation in obligations.values():
        if obligation.kind is not ObligationKind.DENY_COMPLEMENT:
            by_rule[obligation.rule_id].add(obligation.obligation_id)
    return frozenset(
        rule_id
        for rule_id, obligation_ids in by_rule.items()
        if not obligation_ids.intersection(waived)
        and obligation_ids.issubset(selection)
    )


def _assigned_adapter_plans(plan: EnforcementPlan) -> dict[str, AdapterPlan]:
    """Check negotiated-plan composition without authorizing any new waiver."""
    if not plan.assignments or not plan.adapter_plans:
        raise ValueError("activation requires assigned enforcement obligations")
    assigned: dict[str, set[str]] = defaultdict(set)
    obligation_ids: set[str] = set()
    for assignment in plan.assignments:
        if (
            not assignment.obligation_id
            or not assignment.adapter_id
            or assignment.obligation_id in obligation_ids
            or (
                assignment.support is not SupportLevel.EXACT
                and assignment.support is not SupportLevel.TIGHTENED
            )
        ):
            raise ValueError("activation assignments must have unique supported owners")
        obligation_ids.add(assignment.obligation_id)
        assigned[assignment.adapter_id].add(assignment.obligation_id)
    waived = set(plan.waived_obligations)
    if (
        len(waived) != len(plan.waived_obligations)
        or obligation_ids.intersection(waived)
        or any(not obligation_id for obligation_id in waived)
        or (
            plan.mode
            is not (EnforcementMode.DEGRADED if waived else EnforcementMode.ENFORCED)
        )
    ):
        raise ValueError("activation mode does not match distinct waived obligations")
    plans: dict[str, AdapterPlan] = {}
    for adapter_plan in plan.adapter_plans:
        if (
            adapter_plan.adapter_id in plans
            or adapter_plan.obligation_ids != assigned.get(adapter_plan.adapter_id)
        ):
            raise ValueError("adapter plans must exactly cover their assignments")
        plans[adapter_plan.adapter_id] = adapter_plan
    if plans.keys() != assigned.keys():
        raise ValueError("adapter plans must cover every assigned adapter")
    return plans


def _validate_activation(
    evidence: ActivationEvidence,
    plan: AdapterPlan,
    context: ExecutionContext,
    nonce: str,
    timestamp: float,
) -> None:
    if evidence.adapter_id != plan.adapter_id:
        raise ValueError("activation adapter identity mismatch")
    if evidence.native_plan_digest != plan.native_plan_digest:
        raise ValueError("activation plan digest mismatch")
    if evidence.context_digest != context.digest or evidence.nonce != nonce:
        raise ValueError("activation worker binding mismatch")
    if evidence.obligation_ids != plan.obligation_ids:
        raise ValueError("activation obligation coverage mismatch")
    if (
        not all(
            math.isfinite(value)
            for value in (timestamp, evidence.activated_at, evidence.expires_at)
        )
        or timestamp < evidence.activated_at
        or timestamp > evidence.expires_at
    ):
        raise ValueError("activation evidence is stale")


def _obligation_digest(obligations: Sequence[EnforcementObligation]) -> str:
    return _digest(
        [
            item.canonical()
            for item in sorted(obligations, key=lambda value: value.obligation_id)
        ]
    )


def _rule_key(rule: GrantRule) -> str:
    return rule.rule_id


def _required_source_id(resource_class: str, source_id: str) -> str:
    if not source_id:
        raise ValueError(f"{resource_class} grant line has no source identity")
    return source_id


def _source_provenance(location: SourceLocation | None) -> tuple[str, ...]:
    if location is None:
        return ()
    return (f"{location.source}:{location.line}:{location.column}",)


def _freeze_mapping(value: Mapping[str, Any]) -> Mapping[str, Any]:
    return MappingProxyType({str(key): _freeze(item) for key, item in value.items()})


def _freeze_string_mapping(value: Mapping[str, str]) -> Mapping[str, str]:
    return MappingProxyType({str(key): str(item) for key, item in value.items()})


def _freeze(value: Any) -> Any:
    if isinstance(value, Mapping):
        return _freeze_mapping(value)
    if isinstance(value, list | tuple):
        return tuple(_freeze(item) for item in value)
    if isinstance(value, set | frozenset):
        return frozenset(_freeze(item) for item in value)
    return value


def _plain(value: Any) -> Any:
    if isinstance(value, Mapping):
        return {str(key): _plain(item) for key, item in value.items()}
    if isinstance(value, tuple | list):
        return [_plain(item) for item in value]
    if isinstance(value, set | frozenset):
        return sorted((_plain(item) for item in value), key=repr)
    if isinstance(value, Enum):
        return value.value
    return value


def _digest(value: Any) -> str:
    encoded = json.dumps(
        _plain(value), sort_keys=True, separators=(",", ":"), ensure_ascii=False
    ).encode()
    return hashlib.sha256(encoded).hexdigest()
