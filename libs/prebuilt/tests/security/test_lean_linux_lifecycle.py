"""Executable Lean decisions surround the actual controlled worker protocol.

These tests use OS pipes, a real child, and the built Lean executable. Activation
is a fixture and unknown cleanup is injected: this is bridge integration evidence,
not a proof of confinement, Python placement, or observation provenance.
"""

from __future__ import annotations

import hashlib
import json
import os
import signal
from copy import deepcopy
from dataclasses import replace
from pathlib import Path

import pytest

from langgraph.prebuilt.security import lean_lifecycle, linux
from langgraph.prebuilt.security.enforcement import (
    ActivationEvidence,
    AuthorityDomain,
    EnforcementMode,
    ExecutionContext,
    Grant,
    GrantRule,
    HostAttestation,
    ObligationAssignment,
    RequirementLedger,
    SupportLevel,
    compile_obligations,
)
from langgraph.prebuilt.security.execution import (
    HostExecutionDenied,
    HostExecutionError,
)
from langgraph.prebuilt.security.lean_grant import (
    _capture_filtered_grant,
    _capture_obligations,
)
from langgraph.prebuilt.security.lean_lifecycle import LeanLifecycleChecker
from langgraph.prebuilt.security.policy import PolicyFilterResult
from langgraph.prebuilt.security.types import ExecutionOutcome
from tests.security.test_linux_cleanup_context import worker as worker

_BINARY = (
    Path(__file__).resolve().parents[4]
    / "proofs/worker-route/.lake/build/bin/workerRoute"
)


@pytest.fixture(scope="module")
def checker():
    binary = Path(
        os.environ.get("LANGGRAPH_LEAN_WORKER_BINARY", str(_BINARY))
    ).resolve()
    if not binary.is_file():
        if os.environ.get("LANGGRAPH_REQUIRE_LEAN_WORKER") == "1":
            pytest.fail("required compiled Lean worker-route executable is missing")
        pytest.skip("build proofs/worker-route with lake build workerRoute")
    return LeanLifecycleChecker(
        str(binary), hashlib.sha256(binary.read_bytes()).hexdigest()
    )


@pytest.fixture
def lean_worker(worker, checker, monkeypatch):
    worker.executor._lifecycle_checker = checker
    worker.grant = Grant(
        worker.principal.user_id,
        worker.principal.session_id,
        worker.call.tool.name,
        worker.spec.artifact_digest,
        worker.call.call_id,
        "controlled-intent",
        "controlled-policy",
        (GrantRule("controlled", AuthorityDomain.FILESYSTEM, "read", "/controlled"),),
    )
    captured = _capture_filtered_grant(
        PolicyFilterResult(worker.grant, RequirementLedger(()), "allowed")
    )
    worker.grant = captured.filtered.grant
    worker.grant_projection = captured.projection
    generated = _capture_obligations(compile_obligations(worker.grant))
    worker.obligations = generated.obligations
    worker.obligation_projection = generated.projection
    boot_id = Path("/proc/sys/kernel/random/boot_id").read_text().strip()
    worker.host = HostAttestation(
        "controlled-issuer",
        "controlled-nonce",
        boot_id,
        "linux",
        1.0,
        2.0,
        frozenset(),
        {},
        {},
        "controlled-signature",
    )
    worker.plan = replace(
        worker.plan,
        grant_digest=worker.grant.digest,
        host_digest=worker.host.digest,
        assignments=tuple(
            ObligationAssignment(
                item.obligation_id, linux._ADAPTER_ID, SupportLevel.EXACT
            )
            for item in worker.obligations
        ),
        adapter_plans=(
            replace(
                worker.plan.adapter_plans[0],
                obligation_ids=frozenset(
                    item.obligation_id for item in worker.obligations
                ),
            ),
        ),
    )
    worker.contexts = []

    def context(pid):
        # Capture the real child's process identity while it waits for GO.
        start_time = linux._process_start_time(pid)
        result = ExecutionContext(
            f"controlled-worker:{pid}",
            f"pid:{pid}:start:{start_time}",
            boot_id,
            {},
            "controlled-credentials",
            "controlled-cgroup",
            "no-broker",
        )
        worker.contexts.append(result)
        return result

    monkeypatch.setattr(linux, "_execution_context", context)
    worker.receipt_changes = {}
    worker.receipt_transform = lambda receipt: receipt

    def activate(grant, plan, host, context, *, nonce):
        receipt = replace(
            worker.receipt,
            artifact_digest=grant.artifact_digest,
            grant_digest=grant.digest,
            plan_digest=plan.digest,
            host_digest=host.digest,
            context_digest=context.digest,
            nonce=nonce,
            deployment_digest=grant.deployment_digest,
            runtime_digest=grant.runtime_digest,
            mode=plan.mode,
            removed_wants=plan.removed_wants,
            evidence=tuple(
                ActivationEvidence(
                    item.adapter_id,
                    item.native_plan_digest,
                    context.digest,
                    nonce,
                    item.obligation_ids,
                    1.0,
                    2.0,
                    "controlled-signature",
                )
                for item in plan.adapter_plans
            ),
            activated_obligations=frozenset(
                item.obligation_id for item in plan.assignments
            ),
        )
        worker.receipt = worker.receipt_transform(
            replace(receipt, **worker.receipt_changes)
        )
        return worker.receipt

    worker.coordinator.activate.side_effect = activate
    worker.checks = []
    worker.preflight_checks = []
    original_require = LeanLifecycleChecker.require
    original_require_grant = LeanLifecycleChecker.require_grant

    def observe_grant(self, grant, obligations):
        worker.preflight_checks.append(
            {
                "grant": deepcopy(grant),
                "obligations": deepcopy(obligations),
                "children": len(worker.children),
                "go_received": worker.go_marker.exists(),
            }
        )
        return original_require_grant(self, grant, obligations)

    def observe(self, binding, events, phase, *, certificate):
        # This observer records call placement but delegates every decision to
        # the real sealed executable. It never supplies a permissive answer.
        worker.checks.append(
            {
                "phase": phase,
                "binding": binding,
                "events": events,
                "certificate": deepcopy(certificate),
                "go_received": worker.go_marker.exists(),
                "cleanup_errors": tuple(worker.cleanup_errors),
                "child_status": tuple(child.poll() for child in worker.children),
            }
        )
        return original_require(self, binding, events, phase, certificate=certificate)

    monkeypatch.setattr(LeanLifecycleChecker, "require", observe)
    monkeypatch.setattr(LeanLifecycleChecker, "require_grant", observe_grant)
    return worker


def test_useful_result_requires_real_lean_decisions_around_worker(lean_worker):
    result = lean_worker.run()
    assert result.value == "useful-result"
    assert result.receipt is lean_worker.receipt
    assert len(lean_worker.preflight_checks) == 1
    assert lean_worker.preflight_checks[0]["children"] == 0
    assert lean_worker.preflight_checks[0]["go_received"] is False
    assert lean_worker.go_marker.read_text() == "GO received"
    assert [item["phase"] for item in lean_worker.checks] == ["running", "ready"]
    before_go, after_cleanup = lean_worker.checks
    assert before_go["go_received"] is False
    assert before_go["cleanup_errors"] == ()
    assert before_go["child_status"] == (None,)
    assert after_cleanup["go_received"] is True
    assert after_cleanup["cleanup_errors"] == (None,)
    # The single-use cleanup may observe natural exit or win the race and
    # terminate the worker after its accepted response. Either way, the result
    # is released only after confirmed cleanup and no worker remains live.
    assert after_cleanup["child_status"] in {(0,), (-signal.SIGKILL,)}
    assert before_go["certificate"] == after_cleanup["certificate"]
    certificate = before_go["certificate"]
    assert certificate["plan"]["assignments"] == [
        {
            "obligation": item.obligation_id,
            "adapter": linux._ADAPTER_ID,
            "support": "exact",
        }
        for item in lean_worker.obligations
    ]
    assert set(certificate["receipt"]["activated"]) == {
        item.obligation_id for item in lean_worker.obligations
    }
    assert certificate["grant"] == json.loads(lean_worker.grant_projection)
    assert certificate["obligations"] == json.loads(lean_worker.obligation_projection)
    assert certificate["receipt"]["evidence"][0]["digest"] == "native-plan"
    binding = before_go["binding"]
    assert binding["worker"]["pid"] == str(lean_worker.children[0].pid)
    assert (
        binding["worker"]["startTime"]
        == lean_worker.contexts[0].process_identity.rsplit(":", 1)[1]
    )
    assert binding["worker"]["bootId"] == lean_worker.host.boot_id
    assert [event["kind"] for event in after_cleanup["events"]] == [
        "authorize",
        "activate",
        "go",
        "result",
        "cleanup",
    ]


@pytest.mark.parametrize(
    "field",
    [
        "artifact_digest",
        "grant_digest",
        "plan_digest",
        "nonce",
        "host_digest",
        "context_digest",
        "deployment_digest",
        "runtime_digest",
    ],
)
def test_receipt_binding_mismatch_refuses_before_go(lean_worker, field):
    lean_worker.receipt_changes[field] = "mismatched"
    with pytest.raises(HostExecutionDenied, match="host:lean_lifecycle_refused"):
        lean_worker.run()
    assert not lean_worker.go_marker.exists()
    assert [item["phase"] for item in lean_worker.checks] == ["running"]
    assert lean_worker.children[0].poll() is not None
    assert len(lean_worker.cleanup_errors) == 1


@pytest.mark.parametrize(
    "field",
    [
        "principal_id",
        "session_id",
        "call_id",
        "tool_name",
        "normalized_intent_digest",
        "policy_digest",
    ],
)
def test_grant_binding_mismatch_refuses_before_go(lean_worker, field):
    lean_worker.grant = replace(lean_worker.grant, **{field: "mismatched"})
    with pytest.raises(HostExecutionDenied, match="host:lean_lifecycle_refused"):
        lean_worker.run()
    assert not lean_worker.go_marker.exists()
    assert [item["phase"] for item in lean_worker.checks] == ["running"]


@pytest.mark.parametrize(
    "mutation",
    [
        "missing-evidence",
        "duplicate-evidence",
        "wrong-adapter",
        "wrong-native-plan",
        "wrong-context",
        "wrong-nonce",
        "missing-evidence-obligation",
        "extra-evidence-obligation",
        "missing-activated-obligation",
        "extra-activated-obligation",
        "changed-removed-wants",
    ],
)
def test_real_compiled_coverage_refuses_before_worker_release(lean_worker, mutation):
    def alter(receipt):
        evidence = receipt.evidence[0]
        if mutation == "missing-evidence":
            return replace(receipt, evidence=())
        if mutation == "duplicate-evidence":
            return replace(receipt, evidence=(evidence, evidence))
        if mutation == "missing-activated-obligation":
            return replace(receipt, activated_obligations=frozenset())
        if mutation == "extra-activated-obligation":
            return replace(
                receipt,
                activated_obligations=receipt.activated_obligations | {"extra"},
            )
        if mutation == "changed-removed-wants":
            return replace(receipt, removed_wants=("not-the-plan",))
        changes = {
            "wrong-adapter": {"adapter_id": "different-adapter"},
            "wrong-native-plan": {"native_plan_digest": "different-plan"},
            "wrong-context": {"context_digest": "different-worker"},
            "wrong-nonce": {"nonce": "different-activation"},
            "missing-evidence-obligation": {"obligation_ids": frozenset()},
            "extra-evidence-obligation": {
                "obligation_ids": evidence.obligation_ids | {"extra"}
            },
        }
        return replace(receipt, evidence=(replace(evidence, **changes[mutation]),))

    # The controlled coordinator deliberately claims validity: the compiled
    # certificate check must independently reject the contradictory rows.
    lean_worker.receipt_transform = alter
    with pytest.raises(HostExecutionDenied, match="host:lean_"):
        lean_worker.run()
    assert lean_worker.coordinator.validate_receipt.call_count == 1
    assert [item["phase"] for item in lean_worker.checks] == ["running"]
    assert not lean_worker.go_marker.exists()
    assert lean_worker.children[0].poll() is not None
    assert lean_worker.cleanup_errors and lean_worker.cleanup_errors[0] is not None


@pytest.mark.parametrize("mutation", ["duplicate-owner", "missing-owner", "extra-plan"])
def test_plan_coverage_is_checked_before_worker_release(lean_worker, mutation):
    plan = lean_worker.plan
    if mutation == "duplicate-owner":
        plan = replace(plan, assignments=plan.assignments + plan.assignments)
    elif mutation == "missing-owner":
        plan = replace(plan, assignments=())
    else:
        plan = replace(
            plan,
            adapter_plans=plan.adapter_plans
            + (replace(plan.adapter_plans[0], adapter_id="unassigned-adapter"),),
        )
    lean_worker.plan = plan
    with pytest.raises(HostExecutionDenied, match="host:lean_"):
        lean_worker.run()
    assert [item["phase"] for item in lean_worker.checks] == ["running"]
    assert not lean_worker.go_marker.exists()
    assert lean_worker.children[0].poll() is not None


@pytest.mark.parametrize("remove_complement", [False, True])
def test_consistent_receipt_omission_cannot_erase_a_grant_requirement(
    lean_worker, remove_complement
):
    # All v2 receipt inventories agree after this removal. The independent
    # admitted grant and generated inventory still require the omitted row.
    omitted = lean_worker.obligations[-1 if remove_complement else 0].obligation_id
    plan = lean_worker.plan
    lean_worker.plan = replace(
        plan,
        assignments=tuple(
            row for row in plan.assignments if row.obligation_id != omitted
        ),
        adapter_plans=tuple(
            replace(row, obligation_ids=row.obligation_ids - {omitted})
            for row in plan.adapter_plans
        ),
    )
    with pytest.raises(HostExecutionDenied, match="host:lean_lifecycle_refused"):
        lean_worker.run()
    assert lean_worker.preflight_checks
    assert [row["phase"] for row in lean_worker.checks] == ["running"]
    assert not lean_worker.go_marker.exists()
    assert lean_worker.children[0].poll() is not None
    certificate = lean_worker.checks[0]["certificate"]
    assert omitted in {row["id"] for row in certificate["obligations"]}
    assert omitted not in certificate["receipt"]["activated"]


@pytest.mark.parametrize("field", ["grant_projection", "obligation_projection"])
@pytest.mark.parametrize("missing", [None, b"not-json", b"\xff"])
def test_selected_worker_requires_captured_grant_before_command_setup(
    lean_worker, field, missing
):
    setattr(lean_worker, field, missing)
    with pytest.raises(HostExecutionDenied, match="host:lean_grant_"):
        lean_worker.run()
    assert not lean_worker.children
    assert not lean_worker.status_fds
    assert not lean_worker.checks
    assert not lean_worker.preflight_checks


def test_semantic_substitution_refuses_before_worker_creation(lean_worker):
    altered = (
        replace(lean_worker.obligations[0], operation="write"),
    ) + lean_worker.obligations[1:]
    lean_worker.obligation_projection = _capture_obligations(altered).projection
    with pytest.raises(HostExecutionDenied, match="host:lean_lifecycle_refused"):
        lean_worker.run()
    assert len(lean_worker.preflight_checks) == 1
    assert not lean_worker.children
    assert not lean_worker.status_fds
    assert not lean_worker.checks


def test_unknown_cleanup_never_reaches_success_decision(lean_worker):
    lean_worker.confirmed = False
    with pytest.raises(HostExecutionError) as caught:
        lean_worker.run()
    assert caught.value.outcome is ExecutionOutcome.INDETERMINATE
    assert caught.value.termination_confirmed is False
    assert caught.value.recovery in lean_worker.executor.unresolved_terminations()
    assert lean_worker.go_marker.exists()
    assert [item["phase"] for item in lean_worker.checks] == ["running"]
    assert lean_worker.cleanup_errors == [None]


@pytest.mark.parametrize("unavailable_at", ["memfd", "execution"])
def test_unavailable_checker_execution_never_sends_go(
    lean_worker, monkeypatch, unavailable_at
):
    def unavailable(*args, **kwargs):
        raise FileNotFoundError("controlled checker execution failure")

    if unavailable_at == "memfd":
        monkeypatch.setattr(lean_lifecycle, "_memfd", unavailable)
    else:
        monkeypatch.setattr(lean_lifecycle.subprocess, "run", unavailable)
    with pytest.raises(HostExecutionDenied, match="host:lean_lifecycle_refused"):
        lean_worker.run()
    assert not lean_worker.go_marker.exists()
    assert not lean_worker.children
    assert not lean_worker.checks
    assert len(lean_worker.preflight_checks) == 1


def test_post_execution_checker_failure_preserves_effect_and_cleanup_status(
    lean_worker, monkeypatch
):
    original_memfd = lean_lifecycle._memfd

    def unavailable_after_go():
        if lean_worker.go_marker.exists():
            raise OSError("controlled checker failure after worker execution")
        return original_memfd()

    monkeypatch.setattr(lean_lifecycle, "_memfd", unavailable_after_go)
    with pytest.raises(HostExecutionError) as caught:
        lean_worker.run()
    assert lean_worker.go_marker.exists()
    assert caught.value.receipt is lean_worker.receipt
    assert caught.value.outcome is ExecutionOutcome.INDETERMINATE
    assert caught.value.termination_confirmed is True
    assert caught.value.recovery is None
    assert isinstance(caught.value.__cause__, HostExecutionDenied)
    assert [item["phase"] for item in lean_worker.checks] == ["running", "ready"]
    assert lean_worker.cleanup_errors == [None]


@pytest.mark.parametrize("waived", [False, True])
def test_unsupported_plan_never_sends_go(lean_worker, waived):
    if waived:
        lean_worker.plan = replace(lean_worker.plan, waived_obligations=("missing",))
    else:
        lean_worker.receipt_changes["mode"] = EnforcementMode.DEGRADED
    with pytest.raises(HostExecutionDenied, match="host:lean_lifecycle_refused"):
        lean_worker.run()
    assert not lean_worker.go_marker.exists()


def test_consistent_degraded_certificate_does_not_widen_selected_linux_route(
    lean_worker,
):
    lean_worker.plan = replace(
        lean_worker.plan,
        mode=EnforcementMode.DEGRADED,
        waived_obligations=("wanted-only",),
    )
    with pytest.raises(HostExecutionDenied, match="host:lean_lifecycle_refused"):
        lean_worker.run()
    assert [item["phase"] for item in lean_worker.checks] == ["running"]
    certificate = lean_worker.checks[0]["certificate"]
    assert certificate["plan"]["mode"] == certificate["receipt"]["mode"] == "degraded"
    assert not lean_worker.go_marker.exists()


@pytest.mark.asyncio
async def test_selected_route_refuses_async_before_spawning(lean_worker):
    with pytest.raises(HostExecutionDenied, match="host:lean_async_route_unavailable"):
        await lean_worker.executor.ainvoke(lean_worker.principal, lean_worker.call, ())
    assert not lean_worker.children
    assert not lean_worker.checks
