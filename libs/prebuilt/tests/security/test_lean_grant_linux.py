"""The selected Linux invoke route admits raw grants before downstream effects.

The compiled Lean checker and controlled OS child are real. Earlier grant
compilation/policy filtering and downstream attestation/lowering are fixtures;
these tests do not establish their authorization or confinement provenance.
"""

from __future__ import annotations

import signal
from collections.abc import Mapping
from dataclasses import replace
from types import MappingProxyType
from unittest.mock import Mock

import pytest

from langgraph.prebuilt.security import linux
from langgraph.prebuilt.security.enforcement import (
    Grant,
    GrantRule,
    NegotiationResult,
    ObligationKind,
    RequirementLedger,
    compile_obligations,
)
from langgraph.prebuilt.security.execution import HostExecutionDenied
from langgraph.prebuilt.security.policy import PolicyFilterResult
from tests.security.test_lean_linux_lifecycle import checker as checker
from tests.security.test_lean_linux_lifecycle import lean_worker as lean_worker
from tests.security.test_lean_linux_lifecycle import worker as worker


@pytest.fixture
def invoke_worker(lean_worker, monkeypatch):
    harness = lean_worker
    executor = harness.executor
    harness.original_conditions = {"budget": {"limit": 3}}
    harness.original_grant = replace(
        harness.grant,
        rules=(
            replace(harness.grant.rules[0], conditions=harness.original_conditions),
        ),
    )
    object.__setattr__(
        harness.original_grant.rules[0],
        "conditions",
        MappingProxyType(harness.original_conditions),
    )
    harness.original_filter = PolicyFilterResult(
        harness.original_grant, RequirementLedger(()), "allowed"
    )
    harness.plan = replace(harness.plan, grant_digest=harness.original_grant.digest)
    executor.tools = {harness.call.tool.name: harness.spec}
    executor._bound_spec = Mock(return_value=harness.spec)
    executor._bound_runtime = Mock(return_value=None)
    executor._compile_grant = Mock(
        return_value=(harness.original_grant, harness.original_filter.ledger)
    )
    executor.policy_backend = Mock()
    executor.policy_backend.filter.return_value = harness.original_filter
    executor._adapter_for_runtime = Mock(return_value=harness.adapter)
    executor._acquire_deployment_leases = Mock(return_value=())
    harness.adapter.attest.return_value = harness.host
    harness.coordinator.negotiate.return_value = NegotiationResult(
        harness.plan, "allowed"
    )
    harness.coordinator_factory = Mock(return_value=harness.coordinator)
    monkeypatch.setattr(linux, "EnforcementCoordinator", harness.coordinator_factory)
    harness.compiled_grants = []

    def compile_native(grant):
        harness.compiled_grants.append(grant)
        return compile_obligations(grant)

    harness.compile = Mock(side_effect=compile_native)
    monkeypatch.setattr(linux, "compile_obligations", harness.compile)
    harness.invoke = lambda: executor._invoke(
        harness.principal, harness.call, (), asynchronous=False
    )
    return harness


def _assert_no_downstream_effects(harness):
    harness.executor._adapter_for_runtime.assert_not_called()
    harness.coordinator_factory.assert_not_called()
    harness.adapter.attest.assert_not_called()
    harness.adapter.lower.assert_not_called()
    harness.coordinator.negotiate.assert_not_called()
    harness.coordinator.activate.assert_not_called()
    harness.executor._acquire_deployment_leases.assert_not_called()
    assert harness.status_fds == []
    assert harness.children == []
    assert not harness.go_marker.exists()


def test_invoke_uses_detached_grant_through_real_checker_and_controlled_worker(
    invoke_worker,
):
    harness = invoke_worker

    def attest(_challenge):
        # The original backend-owned aliases change after preflight. The
        # admitted reconstruction and its immutable wire bytes must persist.
        object.__setattr__(harness.original_grant, "tool_name", "replacement")
        harness.original_conditions["budget"]["limit"] = 999
        return harness.host

    harness.adapter.attest.side_effect = attest
    result = harness.invoke()
    assert result.value == "useful-result"
    assert result.receipt is harness.receipt
    harness.compile.assert_called_once()
    detached = harness.compiled_grants[0]
    assert detached is not harness.original_grant
    assert detached.rules[0] is not harness.original_grant.rules[0]
    assert detached.tool_name == harness.call.tool.name
    assert detached.rules[0].conditions["budget"]["limit"] == 3
    assert harness.original_conditions["budget"]["limit"] == 999
    assert len(harness.preflight_checks) == 2
    first, second = harness.preflight_checks
    assert first == second
    assert first["children"] == 0
    assert first["go_received"] is False
    assert [entry["phase"] for entry in harness.checks] == ["running", "ready"]
    before, after = harness.checks
    assert before["certificate"] == after["certificate"]
    assert before["certificate"]["grant"] == first["grant"]
    assert before["certificate"]["obligations"] == first["obligations"]
    assert before["certificate"]["grant"]["digest"] == detached.digest
    assert before["go_received"] is False
    assert after["child_status"] in {(0,), (-signal.SIGKILL,)}
    assert harness.go_marker.read_text() == "GO received"


@pytest.mark.parametrize(
    "shape", ["filter", "grant", "mapping", "nested_mapping", "diagnostics"]
)
def test_raw_shape_refuses_before_allowed_digest_compile_or_adapter(
    invoke_worker, monkeypatch, shape
):
    harness = invoke_worker
    callbacks = []

    class ForeignMapping(Mapping):
        def __iter__(self):
            callbacks.append("iter")
            raise AssertionError

        def __len__(self):
            callbacks.append("len")
            raise AssertionError

        def __getitem__(self, key):
            callbacks.append("getitem")
            raise AssertionError

        def items(self):
            callbacks.append("items")
            raise AssertionError

        def __bool__(self):
            callbacks.append("bool")
            raise AssertionError

    class ForeignFilter(PolicyFilterResult):
        @property
        def allowed(self):
            callbacks.append("allowed")
            raise AssertionError

    class ForeignGrant(Grant):
        @property
        def digest(self):
            callbacks.append("foreign_digest")
            raise AssertionError

    original = harness.original_filter
    if shape == "filter":
        original = ForeignFilter(original.grant, original.ledger, original.reason)
    elif shape == "grant":
        object.__setattr__(original, "grant", object.__new__(ForeignGrant))
    elif shape == "diagnostics":
        object.__setattr__(original, "diagnostics", ForeignMapping())
    else:
        proxy = MappingProxyType(ForeignMapping())
        value = proxy if shape == "mapping" else {"nested": proxy}
        object.__setattr__(original.grant.rules[0], "conditions", value)
    harness.executor.policy_backend.filter.return_value = original

    def forbidden_digest(self):
        callbacks.append("digest")
        raise AssertionError

    def forbidden_canonical(self):
        callbacks.append("canonical")
        raise AssertionError

    monkeypatch.setattr(Grant, "digest", property(forbidden_digest))
    monkeypatch.setattr(GrantRule, "canonical", forbidden_canonical)
    callbacks.clear()
    refusal = (
        "host:lean_grant_shape"
        if shape in {"mapping", "nested_mapping"}
        else "host:lean_certificate_shape"
    )
    with pytest.raises(HostExecutionDenied, match=refusal):
        harness.invoke()
    assert callbacks == []
    harness.executor._compile_grant.assert_called_once()
    harness.executor.policy_backend.filter.assert_called_once()
    harness.compile.assert_not_called()
    assert harness.preflight_checks == []
    _assert_no_downstream_effects(harness)


@pytest.mark.parametrize(
    "mutation",
    [
        "operation",
        "selector",
        "conditions",
        "kind",
        "waivable",
        "dependencies",
        "complement",
        "missing_complement",
        "extra",
    ],
)
def test_real_grant_check_refuses_changed_generated_rows_before_attestation(
    invoke_worker, mutation
):
    harness = invoke_worker

    def substituted_compile(grant):
        harness.compiled_grants.append(grant)
        rows = list(compile_obligations(grant))
        if mutation == "complement":
            rows[1] = replace(rows[1], operation="allow_unlisted")
        elif mutation == "missing_complement":
            rows.pop()
        elif mutation == "extra":
            rows.append(replace(rows[0], obligation_id="invented"))
        else:
            changes = {
                "operation": "write",
                "selector": "/different",
                "conditions": {"budget": {"limit": 999}},
                "kind": ObligationKind.RESOURCE_LIMIT,
                "waivable": True,
                "dependencies": frozenset({rows[-1].obligation_id}),
            }
            rows[0] = replace(rows[0], **{mutation: changes[mutation]})
        return tuple(rows)

    harness.compile.side_effect = substituted_compile
    with pytest.raises(HostExecutionDenied, match="host:lean_lifecycle_refused"):
        harness.invoke()
    harness.compile.assert_called_once()
    assert harness.compiled_grants[0] is not harness.original_grant
    assert len(harness.preflight_checks) == 1
    checked = harness.preflight_checks[0]
    assert checked["children"] == 0
    assert checked["go_received"] is False
    assert checked["grant"]["tool"] == harness.call.tool.name
    assert harness.checks == []
    _assert_no_downstream_effects(harness)
