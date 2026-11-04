"""Contract tests for exact grant lowering and worker activation evidence."""

from __future__ import annotations

from dataclasses import replace
from typing import Any

import pytest

from langgraph.prebuilt.security import enforcement as enforcement_module
from langgraph.prebuilt.security.enforcement import (
    ActivationEvidence,
    ActivationReceipt,
    AdapterPlan,
    AuthorityDomain,
    EnforcementAdapter,
    EnforcementCoordinator,
    EnforcementMode,
    EnforcementObligation,
    EnforcementPlan,
    ExecutionContext,
    Grant,
    GrantRule,
    HostAttestation,
    ObligationKind,
    RequirementEntry,
    RequirementLedger,
    RuleEnforcement,
    SupportAssessment,
    SupportLevel,
    compile_grant,
    compile_obligations,
)
from langgraph.prebuilt.security.profile import (
    FsRule,
    PathTemplate,
    PrincipalProfile,
    Requirement,
    ToolProfile,
    evaluate_dac,
)


class _Verifier:
    def __init__(self, trusted: bool = True) -> None:
        self.trusted = trusted

    def verify(self, attestation: HostAttestation) -> bool:
        return self.trusted and attestation.signature == "trusted"


class _Adapter(EnforcementAdapter):
    def __init__(
        self,
        adapter_id: str,
        supported: set[str],
        *,
        wrong_context: bool = False,
    ) -> None:
        self._adapter_id = adapter_id
        self.supported = supported
        self.wrong_context = wrong_context

    @property
    def adapter_id(self) -> str:
        return self._adapter_id

    def assess(
        self, obligation: EnforcementObligation, host: HostAttestation
    ) -> SupportAssessment:
        support = (
            SupportLevel.EXACT
            if obligation.obligation_id in self.supported
            else SupportLevel.UNSUPPORTED
        )
        return SupportAssessment(
            self.adapter_id, obligation.obligation_id, support, support.value
        )

    def lower(
        self,
        grant: Grant,
        obligations: tuple[EnforcementObligation, ...],
        host: HostAttestation,
    ) -> AdapterPlan:
        obligation_ids = frozenset(item.obligation_id for item in obligations)
        return AdapterPlan(
            self.adapter_id,
            obligation_ids,
            f"plan:{self.adapter_id}:{','.join(sorted(obligation_ids))}",
        )

    def activate(
        self, plan: AdapterPlan, context: ExecutionContext, nonce: str
    ) -> ActivationEvidence:
        return ActivationEvidence(
            self.adapter_id,
            plan.native_plan_digest,
            "wrong" if self.wrong_context else context.digest,
            nonce,
            plan.obligation_ids,
            10.0,
            100.0,
            "adapter-signed",
        )

    def verify_activation(self, evidence: ActivationEvidence) -> bool:
        return evidence.signature == "adapter-signed"


def _grant(requirement: Requirement = Requirement.NEED) -> Grant:
    return Grant(
        "alice",
        "session",
        "send_email",
        "artifact-sha256",
        "call-1",
        "intent-sha256",
        "policy-sha256",
        (
            GrantRule(
                "mail-rule",
                AuthorityDomain.SERVICE,
                "mail.send",
                "mail-service",
                {"recipient": "alice@example.com"},
                requirement,
                ("tool-profile:12", "operator-policy:7"),
            ),
        ),
    )


def _ledger(requirement: Requirement = Requirement.NEED) -> RequirementLedger:
    return RequirementLedger(
        (RequirementEntry("profile:mail", requirement, frozenset({"mail-rule"})),)
    )


def _obligations(
    *, recipient_waivable: bool = False
) -> tuple[EnforcementObligation, ...]:
    return (
        EnforcementObligation(
            "mail.recipient",
            "mail-rule",
            ObligationKind.OPERATE,
            AuthorityDomain.SERVICE,
            "mail.send",
            "mail-service",
            {"recipient": "alice@example.com"},
            frozenset({"mail.channel", "mail.credential"}),
            recipient_waivable,
        ),
        EnforcementObligation(
            "mail.channel",
            "mail-rule",
            ObligationKind.AUTHENTICATED_CHANNEL,
            AuthorityDomain.SERVICE,
            "broker.request",
            "mail-broker",
        ),
        EnforcementObligation(
            "mail.credential",
            "mail-rule",
            ObligationKind.CREDENTIAL_CUSTODY,
            AuthorityDomain.SERVICE,
            "credential.hold",
            "mail-credential",
        ),
        EnforcementObligation(
            "mail.default_deny",
            "mail-rule",
            ObligationKind.DENY_COMPLEMENT,
            AuthorityDomain.SERVICE,
            "service.deny_unlisted",
            "*",
        ),
        *(
            EnforcementObligation(
                f"domain.{domain.value}.default_deny",
                f"domain:{domain.value}",
                ObligationKind.DENY_COMPLEMENT,
                domain,
                "deny_unlisted",
                "*",
            )
            for domain in AuthorityDomain
            if domain is not AuthorityDomain.SERVICE
        ),
    )


def _complement_ids() -> set[str]:
    return {
        item.obligation_id
        for item in _obligations()
        if item.kind is ObligationKind.DENY_COMPLEMENT
    }


def test_compile_grant_preserves_requirements_and_baseline() -> None:
    """Every final rule is attributable to its need/want or runtime source."""
    evaluation = evaluate_dac(
        ToolProfile(
            "reader",
            owner="alice",
            call_grants={"alice"},
            fs=(
                FsRule(
                    {"read", "write"},
                    PathTemplate("/workspace/report"),
                    Requirement.WANT,
                ),
            ),
        ),
        PrincipalProfile(
            "alice",
            fs=(FsRule({"read", "write"}, PathTemplate("/workspace", True)),),
        ),
        {},
    )
    baseline = GrantRule(
        "runtime:python",
        AuthorityDomain.RUNTIME,
        "read",
        "/usr/lib/python",
        {"subtree": True},
        baseline=True,
    )

    compiled = compile_grant(
        evaluation,
        principal_id="alice",
        session_id="session",
        artifact_digest="artifact-sha256",
        call_id="call-1",
        normalized_intent_digest="intent-sha256",
        policy_digest="policy-sha256",
        baseline_rules=(baseline,),
    )

    want_rules = {
        rule.rule_id
        for rule in compiled.grant.rules
        if rule.domain is AuthorityDomain.FILESYSTEM
    }
    assert len(want_rules) == 2
    assert all(
        rule.requirement is Requirement.WANT
        for rule in compiled.grant.rules
        if rule.rule_id in want_rules
    )
    assert compiled.ledger.recheck(frozenset({"runtime:python"})).removed_wants == (
        "fs:0",
    )
    assert compiled.ledger.recheck(frozenset(want_rules)).missing_needs == (
        "baseline:runtime:python",
        "syscall:minimal",
    )


def test_compile_grant_rejects_denial_and_unmarked_baseline() -> None:
    """Denied DAC results and hidden ambient authority never become grants."""
    denied = evaluate_dac(
        ToolProfile("reader", owner="alice", call_grants={"bob"}),
        PrincipalProfile("alice"),
        {},
    )
    arguments = {
        "principal_id": "alice",
        "session_id": "session",
        "artifact_digest": "artifact",
        "call_id": "call",
        "normalized_intent_digest": "intent",
        "policy_digest": "policy",
    }
    with pytest.raises(ValueError, match="denied DAC"):
        compile_grant(denied, **arguments)

    allowed = evaluate_dac(
        ToolProfile("reader", owner="alice", call_grants={"alice"}),
        PrincipalProfile("alice"),
        {},
    )
    hidden = GrantRule(
        "runtime:hidden",
        AuthorityDomain.RUNTIME,
        "read",
        "/usr/lib",
    )
    with pytest.raises(ValueError, match="baseline=True"):
        compile_grant(allowed, baseline_rules=(hidden,), **arguments)


def test_compile_obligations_denies_complement_of_every_domain() -> None:
    """Omitted domains still require proof that their ambient authority is denied."""
    obligations = compile_obligations(_grant())

    complements = {
        item.domain
        for item in obligations
        if item.kind is ObligationKind.DENY_COMPLEMENT
    }
    assert complements == set(AuthorityDomain)
    assert any(item.obligation_id == "rule:mail-rule:operate" for item in obligations)


def _host(*, nonce: str = "challenge", signature: str = "trusted") -> HostAttestation:
    return HostAttestation(
        "supervisor",
        nonce,
        "boot-1",
        "linux",
        1.0,
        100.0,
        frozenset({"service"}),
        {"mount_ns": "mnt:1", "cgroup": "/slanggraph/1"},
        {"probe_digest": "probe-sha256"},
        signature,
    )


def _context(*, worker_id: str = "worker-1") -> ExecutionContext:
    return ExecutionContext(
        worker_id,
        "pidfd:42",
        "boot-1",
        {"mount": "mnt:1", "network": "net:1"},
        "credential-context-sha256",
        "/slanggraph/1",
        "broker-epoch-1",
    )


def test_grant_digest_is_canonical_and_conditions_are_frozen() -> None:
    """Ordering and caller mutation cannot change the authority identity."""
    conditions: dict[str, Any] = {"method": "POST", "headers": {"x": "1"}}
    rule = GrantRule(
        "http-rule",
        AuthorityDomain.NETWORK,
        "http.request",
        "https://example.com/reports",
        conditions,
    )
    conditions["method"] = "DELETE"
    first = replace(_grant(), rules=(rule,))
    second = replace(
        _grant(),
        rules=(
            GrantRule(
                "http-rule",
                AuthorityDomain.NETWORK,
                "http.request",
                "https://example.com/reports",
                {"headers": {"x": "1"}, "method": "POST"},
            ),
        ),
    )
    assert first.digest == second.digest
    assert rule.conditions["method"] == "POST"


def test_immutable_authority_digests_are_computed_once(monkeypatch) -> None:
    """Repeated gates reuse identities after their immutable inputs are final."""
    original = enforcement_module._digest
    calls = 0

    def counted(value):
        nonlocal calls
        calls += 1
        return original(value)

    monkeypatch.setattr(enforcement_module, "_digest", counted)
    grant = _grant()
    host = _host()
    context = _context()
    eager_calls = calls
    assert grant.digest == grant.digest
    assert host.digest == host.digest
    assert context.digest == context.digest
    assert calls == eager_calls

    plan = EnforcementPlan(
        grant.digest,
        host.digest,
        "obligations",
        EnforcementMode.ENFORCED,
        (),
        (),
    )
    assert plan.digest == plan.digest
    assert calls == eager_calls + 1


def test_capability_class_does_not_substitute_for_exact_rule_support() -> None:
    """A host capability cannot make an adapter's unsupported rule executable."""
    adapter = _Adapter("service", _complement_ids())
    result = EnforcementCoordinator([adapter], _Verifier()).negotiate(
        _grant(),
        _ledger(),
        _obligations(),
        _host(),
        expected_nonce="challenge",
        now=50.0,
    )
    assert not result.allowed
    assert result.reason == "adapter_rule_unsupported:mail.channel"


def test_closed_world_complement_is_required_and_nonwaivable() -> None:
    """Listed permissions never run without denial of unlisted authority."""
    obligations = tuple(
        item
        for item in _obligations()
        if item.kind is not ObligationKind.DENY_COMPLEMENT
    )
    adapter = _Adapter("service", {item.obligation_id for item in obligations})
    result = EnforcementCoordinator([adapter], _Verifier()).negotiate(
        _grant(),
        _ledger(),
        obligations,
        _host(),
        expected_nonce="challenge",
        waivers=frozenset({"mail.default_deny"}),
        now=50.0,
    )
    assert not result.allowed
    assert result.reason.startswith("default_deny_missing:")
    assert "service" in result.reason


def test_multi_component_rule_requires_every_dependency() -> None:
    """Recipient validation alone is insufficient without channel and custody."""
    supported = {"mail.recipient", *_complement_ids()}
    adapter = _Adapter("service", supported)
    result = EnforcementCoordinator([adapter], _Verifier()).negotiate(
        _grant(),
        _ledger(),
        _obligations(),
        _host(),
        expected_nonce="challenge",
        now=50.0,
    )
    assert not result.allowed
    assert result.reason == "adapter_rule_unsupported:mail.channel"


def test_one_primary_owner_is_selected_per_obligation() -> None:
    """Overlapping adapters require an explicit primary obligation owner."""
    obligation_ids = {item.obligation_id for item in _obligations()}
    first = _Adapter("first", obligation_ids)
    second = _Adapter("second", obligation_ids)
    coordinator = EnforcementCoordinator([first, second], _Verifier())
    conflict = coordinator.negotiate(
        _grant(),
        _ledger(),
        _obligations(),
        _host(),
        expected_nonce="challenge",
        now=50.0,
    )
    owners = {item: "first" for item in obligation_ids}
    selected = coordinator.negotiate(
        _grant(),
        _ledger(),
        _obligations(),
        _host(),
        expected_nonce="challenge",
        owners=owners,
        now=50.0,
    )
    assert conflict.reason.startswith("adapter_ownership_conflict:")
    assert selected.allowed
    assert selected.plan is not None
    assert {item.adapter_id for item in selected.plan.assignments} == {"first"}


def test_waiver_cannot_remove_need_but_can_remove_want_as_degraded() -> None:
    """Later lowering rechecks source requirements instead of widening access."""
    supported = {
        "mail.channel",
        "mail.credential",
        *_complement_ids(),
    }
    adapter = _Adapter("service", supported)
    coordinator = EnforcementCoordinator([adapter], _Verifier())
    obligations = _obligations(recipient_waivable=True)
    need = coordinator.negotiate(
        _grant(Requirement.NEED),
        _ledger(Requirement.NEED),
        obligations,
        _host(),
        expected_nonce="challenge",
        waivers=frozenset({"mail.recipient"}),
        now=50.0,
    )
    want = coordinator.negotiate(
        _grant(Requirement.WANT),
        _ledger(Requirement.WANT),
        obligations,
        _host(),
        expected_nonce="challenge",
        waivers=frozenset({"mail.recipient"}),
        now=50.0,
    )
    assert need.reason == "required_authority_removed:profile:mail"
    assert want.allowed
    assert want.plan is not None
    assert want.plan.mode is EnforcementMode.DEGRADED
    assert want.plan.removed_wants == ("profile:mail",)


@pytest.mark.parametrize(
    ("host", "reason"),
    [
        (_host(nonce="other"), "host_attestation_failed:nonce"),
        (_host(signature="untrusted"), "host_attestation_failed:trust"),
    ],
)
def test_host_evidence_is_verified_and_nonce_bound(
    host: HostAttestation, reason: str
) -> None:
    """A digest without fresh trust-anchored evidence cannot negotiate a plan."""
    obligation_ids = {item.obligation_id for item in _obligations()}
    result = EnforcementCoordinator(
        [_Adapter("service", obligation_ids)], _Verifier()
    ).negotiate(
        _grant(),
        _ledger(),
        _obligations(),
        host,
        expected_nonce="challenge",
        now=50.0,
    )
    assert result.reason == reason


def test_activation_receipt_binds_plan_and_worker_context() -> None:
    """Only worker-specific activation evidence releases an enforced plan."""
    obligation_ids = {item.obligation_id for item in _obligations()}
    adapter = _Adapter("service", obligation_ids)
    coordinator = EnforcementCoordinator([adapter], _Verifier())
    result = coordinator.negotiate(
        _grant(),
        _ledger(),
        _obligations(),
        _host(),
        expected_nonce="challenge",
        now=50.0,
    )
    assert result.plan is not None
    receipt = coordinator.activate(
        _grant(), result.plan, _host(), _context(), nonce="activation", now=50.0
    )
    assert receipt.context_digest == _context().digest
    assert receipt.activated_obligations == frozenset(obligation_ids)
    assert receipt.mode is EnforcementMode.ENFORCED
    assert coordinator.validate_receipt(
        receipt,
        _grant(),
        result.plan,
        _host(),
        _context(),
        now=50.0,
    )
    changed_broker = replace(_context(), broker_epoch="broker-2")
    assert not coordinator.validate_receipt(
        receipt,
        _grant(),
        result.plan,
        _host(),
        changed_broker,
        now=50.0,
    )
    assert not coordinator.validate_receipt(
        receipt,
        _grant(),
        result.plan,
        _host(),
        _context(),
        now=101.0,
    )


def test_activation_rejects_evidence_from_another_worker() -> None:
    """Adapter evidence for a different execution context fails closed."""
    obligation_ids = {item.obligation_id for item in _obligations()}
    adapter = _Adapter("service", obligation_ids, wrong_context=True)
    coordinator = EnforcementCoordinator([adapter], _Verifier())
    result = coordinator.negotiate(
        _grant(),
        _ledger(),
        _obligations(),
        _host(),
        expected_nonce="challenge",
        now=50.0,
    )
    assert result.plan is not None
    with pytest.raises(ValueError, match="worker binding"):
        coordinator.activate(
            _grant(), result.plan, _host(), _context(), nonce="activation", now=50.0
        )


def _composition() -> tuple[
    EnforcementCoordinator,
    Grant,
    EnforcementPlan,
    HostAttestation,
    ExecutionContext,
    ActivationReceipt,
]:
    grant = _grant()
    obligations = compile_obligations(grant)
    first_ids = {obligations[0].obligation_id}
    remaining_ids = {item.obligation_id for item in obligations} - first_ids
    coordinator = EnforcementCoordinator(
        [_Adapter("first", first_ids), _Adapter("second", remaining_ids)],
        _Verifier(),
    )
    host = _host()
    context = _context()
    plan = coordinator.negotiate(
        grant, _ledger(), obligations, host, expected_nonce="challenge", now=50.0
    ).plan
    assert plan is not None
    receipt = coordinator.activate(
        grant, plan, host, context, nonce="activation", now=50.0
    )
    return coordinator, grant, plan, host, context, receipt


@pytest.mark.parametrize("reverse", [False, True])
def test_complete_multi_adapter_receipt_remains_useful(reverse: bool) -> None:
    """Evidence order is immaterial; every assigned adapter remains authenticated."""
    coordinator, grant, plan, host, context, receipt = _composition()
    assert len(receipt.evidence) == 2
    assert receipt.activated_obligations
    assert receipt.rule_enforcement
    if reverse:
        receipt = replace(receipt, evidence=tuple(reversed(receipt.evidence)))
    assert coordinator.validate_receipt(receipt, grant, plan, host, context, now=50.0)
    assert coordinator.validate_receipt(
        replace(receipt, valid_until=75.0), grant, plan, host, context, now=50.0
    )


def test_tightened_support_remains_valid() -> None:
    """A real negotiated stricter relation need not be relabeled as exact."""

    class TightenedAdapter(_Adapter):
        def assess(
            self, obligation: EnforcementObligation, host: HostAttestation
        ) -> SupportAssessment:
            return replace(
                super().assess(obligation, host), support=SupportLevel.TIGHTENED
            )

    grant = _grant()
    obligations = compile_obligations(grant)
    adapter = TightenedAdapter("stricter", {item.obligation_id for item in obligations})
    coordinator = EnforcementCoordinator([adapter], _Verifier())
    plan = coordinator.negotiate(
        grant, _ledger(), obligations, _host(), expected_nonce="challenge", now=50.0
    ).plan
    assert plan is not None
    receipt = coordinator.activate(
        grant, plan, _host(), _context(), nonce="activation", now=50.0
    )
    assert all(item.support is SupportLevel.TIGHTENED for item in plan.assignments)
    assert receipt.mode is EnforcementMode.ENFORCED
    assert coordinator.validate_receipt(
        receipt, grant, plan, _host(), _context(), now=50.0
    )


def test_empty_authority_still_requires_complement_evidence() -> None:
    """A grant with no positive rules retains real closed-world obligations."""
    grant = replace(_grant(), rules=())
    obligations = compile_obligations(grant)
    assert obligations
    assert all(item.kind is ObligationKind.DENY_COMPLEMENT for item in obligations)
    coordinator = EnforcementCoordinator(
        [_Adapter("deny-complement", {item.obligation_id for item in obligations})],
        _Verifier(),
    )
    plan = coordinator.negotiate(
        grant,
        RequirementLedger(()),
        obligations,
        _host(),
        expected_nonce="challenge",
        now=50.0,
    ).plan
    assert plan is not None
    receipt = coordinator.activate(
        grant, plan, _host(), _context(), nonce="activation", now=50.0
    )
    assert receipt.evidence
    assert receipt.activated_obligations
    assert coordinator.validate_receipt(
        receipt, grant, plan, _host(), _context(), now=50.0
    )
    assert not coordinator.validate_receipt(
        replace(receipt, evidence=()), grant, plan, _host(), _context(), now=50.0
    )


@pytest.mark.parametrize(
    "mutation",
    [
        "empty",
        "truncated",
        "duplicate",
        "same_length_duplicate",
        "unknown_adapter",
        "bad_signature",
        "wrong_nonce",
        "wrong_context",
        "wrong_native_plan",
        "missing_obligation",
        "extra_obligation",
        "claimed_missing",
        "claimed_extra",
        "wrong_rule_support",
        "wrong_mode",
        "removed_wants",
        "empty_nonce",
        "receipt_nonce",
        "receipt_expiry",
        "adapter_expiry",
        "not_yet_active",
        "nan_expiry",
        "infinite_expiry",
        "nan_adapter_expiry",
        "nan_activated_at",
    ],
)
def test_receipt_requires_complete_verified_composition(mutation: str) -> None:
    """Claimed coverage cannot substitute for one bound signed item per adapter."""
    coordinator, grant, plan, host, context, receipt = _composition()
    first, second = receipt.evidence
    if mutation == "empty":
        receipt = replace(receipt, evidence=())
    elif mutation == "truncated":
        receipt = replace(receipt, evidence=(first,))
    elif mutation == "duplicate":
        receipt = replace(receipt, evidence=(first, second, first))
    elif mutation == "same_length_duplicate":
        receipt = replace(receipt, evidence=(first, first))
    elif mutation in {
        "unknown_adapter",
        "bad_signature",
        "wrong_nonce",
        "wrong_context",
        "wrong_native_plan",
        "missing_obligation",
        "extra_obligation",
        "adapter_expiry",
        "not_yet_active",
        "nan_adapter_expiry",
        "nan_activated_at",
    }:
        changes: dict[str, Any] = {
            "unknown_adapter": {"adapter_id": "other"},
            "bad_signature": {"signature": "untrusted"},
            "wrong_nonce": {"nonce": "another-activation"},
            "wrong_context": {"context_digest": "another-worker"},
            "wrong_native_plan": {"native_plan_digest": "another-plan"},
            "missing_obligation": {"obligation_ids": frozenset()},
            "extra_obligation": {"obligation_ids": second.obligation_ids | {"extra"}},
            "adapter_expiry": {"expires_at": 75.0},
            "not_yet_active": {"activated_at": 60.0},
            "nan_adapter_expiry": {"expires_at": float("nan")},
            "nan_activated_at": {"activated_at": float("nan")},
        }[mutation]
        receipt = replace(receipt, evidence=(first, replace(second, **changes)))
    elif mutation == "claimed_missing":
        receipt = replace(receipt, activated_obligations=frozenset())
    elif mutation == "claimed_extra":
        receipt = replace(
            receipt, activated_obligations=receipt.activated_obligations | {"extra"}
        )
    elif mutation == "wrong_rule_support":
        receipt = replace(
            receipt,
            rule_enforcement=(
                RuleEnforcement("mail-rule", SupportLevel.TIGHTENED, "first"),
            ),
        )
    else:
        changes = {
            "wrong_mode": {"mode": EnforcementMode.DEGRADED},
            "removed_wants": {"removed_wants": ("profile:mail",)},
            "empty_nonce": {"nonce": ""},
            "receipt_nonce": {"nonce": "another-activation"},
            "receipt_expiry": {"valid_until": 101.0},
            "nan_expiry": {"valid_until": float("nan")},
            "infinite_expiry": {"valid_until": float("inf")},
        }[mutation]
        receipt = replace(receipt, **changes)
    assert not coordinator.validate_receipt(
        receipt, grant, plan, host, context, now=50.0
    )


def _malformed_composition(plan: EnforcementPlan, mutation: str) -> EnforcementPlan:
    first, second = plan.adapter_plans
    assignment, *others = plan.assignments
    if mutation == "duplicate_plan":
        return replace(plan, adapter_plans=(first, second, first))
    if mutation == "missing_plan":
        return replace(plan, adapter_plans=(first,))
    if mutation == "empty_plan":
        return replace(plan, assignments=(), adapter_plans=())
    if mutation == "duplicate_assignment":
        return replace(plan, assignments=(*plan.assignments, assignment))
    if mutation == "missing_assignment":
        return replace(plan, assignments=tuple(others))
    if mutation == "reassigned":
        other_adapter = "second" if assignment.adapter_id == "first" else "first"
        return replace(
            plan, assignments=(replace(assignment, adapter_id=other_adapter), *others)
        )
    if mutation == "unsupported":
        return replace(
            plan,
            assignments=(
                replace(assignment, support=SupportLevel.UNSUPPORTED),
                *others,
            ),
        )
    if mutation == "widened":
        return replace(
            plan,
            adapter_plans=(
                replace(first, obligation_ids=first.obligation_ids | {"unassigned"}),
                second,
            ),
        )
    if mutation == "unknown_adapter":
        return replace(
            plan,
            assignments=tuple(
                replace(item, adapter_id="unknown")
                if item.adapter_id == first.adapter_id
                else item
                for item in plan.assignments
            ),
            adapter_plans=(replace(first, adapter_id="unknown"), second),
        )
    if mutation == "enforced_waiver":
        return replace(plan, waived_obligations=("waived",))
    if mutation == "degraded_without_waiver":
        return replace(plan, mode=EnforcementMode.DEGRADED)
    if mutation == "assigned_waiver":
        return replace(
            plan,
            mode=EnforcementMode.DEGRADED,
            waived_obligations=(assignment.obligation_id,),
        )
    if mutation == "duplicate_waiver":
        return replace(
            plan, mode=EnforcementMode.DEGRADED, waived_obligations=("waived", "waived")
        )
    if mutation == "wrong_grant":
        return replace(plan, grant_digest="another-grant")
    if mutation == "wrong_host":
        return replace(plan, host_digest="another-host")
    raise AssertionError("unknown test mutation")


@pytest.mark.parametrize(
    "mutation",
    [
        "duplicate_plan",
        "missing_plan",
        "empty_plan",
        "duplicate_assignment",
        "missing_assignment",
        "reassigned",
        "unsupported",
        "widened",
        "unknown_adapter",
        "enforced_waiver",
        "degraded_without_waiver",
        "assigned_waiver",
        "duplicate_waiver",
        "wrong_grant",
        "wrong_host",
    ],
)
def test_inconsistent_plan_cannot_activate_or_validate(
    mutation: str, monkeypatch: pytest.MonkeyPatch
) -> None:
    """Coherently changing a receipt digest cannot repair inconsistent assignments."""
    coordinator, grant, plan, host, context, receipt = _composition()
    changed = _malformed_composition(plan, mutation)
    receipt = replace(
        receipt,
        plan_digest=changed.digest,
        mode=changed.mode,
        activated_obligations=frozenset(
            item.obligation_id for item in changed.assignments
        ),
        rule_enforcement=tuple(
            RuleEnforcement(
                item.obligation_id.removeprefix("rule:").removesuffix(":operate"),
                item.support,
                item.adapter_id,
            )
            for item in changed.assignments
            if item.obligation_id.startswith("rule:")
            and item.obligation_id.endswith(":operate")
        ),
    )
    assert not coordinator.validate_receipt(
        receipt, grant, changed, host, context, now=50.0
    )

    def forbidden_activation(*args: Any, **kwargs: Any) -> ActivationEvidence:
        raise AssertionError("an inconsistent plan reached adapter activation")

    monkeypatch.setattr(_Adapter, "activate", forbidden_activation)
    with pytest.raises(ValueError):
        coordinator.activate(
            grant, changed, host, context, nonce="activation", now=50.0
        )


def test_explicit_want_waiver_still_produces_only_degraded_receipt() -> None:
    """Valid negotiated waivers retain their original constrained behavior."""
    obligations = _obligations(recipient_waivable=True)
    supported = {item.obligation_id for item in obligations} - {"mail.recipient"}
    coordinator = EnforcementCoordinator([_Adapter("service", supported)], _Verifier())
    grant = _grant(Requirement.WANT)
    plan = coordinator.negotiate(
        grant,
        _ledger(Requirement.WANT),
        obligations,
        _host(),
        expected_nonce="challenge",
        waivers=frozenset({"mail.recipient"}),
        now=50.0,
    ).plan
    assert plan is not None
    receipt = coordinator.activate(
        grant, plan, _host(), _context(), nonce="activation", now=50.0
    )
    assert receipt.mode is EnforcementMode.DEGRADED
    assert "mail.recipient" not in receipt.activated_obligations
    assert receipt.removed_wants == ("profile:mail",)
    assert coordinator.validate_receipt(
        receipt, grant, plan, _host(), _context(), now=50.0
    )
    assert not coordinator.validate_receipt(
        replace(receipt, mode=EnforcementMode.ENFORCED),
        grant,
        plan,
        _host(),
        _context(),
        now=50.0,
    )


@pytest.mark.parametrize("now", [0.0, 101.0, float("nan"), float("inf")])
def test_receipt_rejects_unusable_validation_time(now: float) -> None:
    coordinator, grant, plan, host, context, receipt = _composition()
    assert not coordinator.validate_receipt(
        receipt, grant, plan, host, context, now=now
    )


def test_receipt_worker_boot_must_match_authenticated_host() -> None:
    """Even internally consistent evidence cannot bind to a different host boot."""
    coordinator, grant, plan, host, context, receipt = _composition()
    context = replace(context, boot_id="another-boot")
    receipt = replace(
        receipt,
        context_digest=context.digest,
        evidence=tuple(
            replace(item, context_digest=context.digest) for item in receipt.evidence
        ),
    )
    assert not coordinator.validate_receipt(
        receipt, grant, plan, host, context, now=50.0
    )
