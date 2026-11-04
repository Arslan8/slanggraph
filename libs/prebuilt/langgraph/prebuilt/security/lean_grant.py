"""Bounded native grant admission before obligation compilation.

Exact CPython record descriptors and gc.get_referents on mapping proxies are
runtime premises. This admits/detaches supplied data, not policy provenance or
the correctness of prior constructors/filtering. No candidate digest is called.
Conditions admit null, bool, signed64 integers, scalar text, exact native list
or tuple sequences, and exact dict-backed maps. Sets and floats are refused.
"""

from __future__ import annotations

import gc
import sys
from dataclasses import dataclass
from types import MappingProxyType
from typing import Any

from langgraph.prebuilt.security.enforcement import (
    AuthorityDomain,
    EnforcementObligation,
    Grant,
    GrantRule,
    ObligationKind,
    RequirementEntry,
    RequirementLedger,
)
from langgraph.prebuilt.security.execution import HostExecutionDenied
from langgraph.prebuilt.security.lean_lifecycle import (
    _MAX_REQUEST,
    _charge,
    _data,
    _encoded,
    _record,
    _rows,
    _slots,
    _string,
    _strings,
)
from langgraph.prebuilt.security.policy import PolicyFilterResult
from langgraph.prebuilt.security.profile import Requirement

_REFERENTS = gc.get_referents
_FILTER = _slots(
    PolicyFilterResult,
    ("grant", "ledger", "reason", "removed_rule_ids", "diagnostics"),
)
_GRANT = _slots(
    Grant,
    (
        "principal_id",
        "session_id",
        "tool_name",
        "artifact_digest",
        "call_id",
        "normalized_intent_digest",
        "policy_digest",
        "rules",
        "deployment_digest",
        "runtime_digest",
    ),
)
_RULE = _slots(
    GrantRule,
    (
        "rule_id",
        "domain",
        "operation",
        "selector",
        "conditions",
        "requirement",
        "provenance",
        "baseline",
    ),
)
_LEDGER = _slots(RequirementLedger, ("entries",))
_ENTRY = _slots(RequirementEntry, ("source_id", "requirement", "rule_ids"))
_OBLIGATION = _slots(
    EnforcementObligation,
    (
        "obligation_id",
        "rule_id",
        "kind",
        "domain",
        "operation",
        "selector",
        "conditions",
        "dependencies",
        "waivable",
    ),
)
_DOMAINS = (
    (AuthorityDomain.FILESYSTEM, "filesystem"),
    (AuthorityDomain.NETWORK, "network"),
    (AuthorityDomain.PROCESS, "process"),
    (AuthorityDomain.IPC, "ipc"),
    (AuthorityDomain.SERVICE, "service"),
    (AuthorityDomain.CREDENTIAL, "credential"),
    (AuthorityDomain.RUNTIME, "runtime"),
    (AuthorityDomain.DELEGATION, "delegation"),
    (AuthorityDomain.RESOURCE_LIMIT, "resource_limit"),
)
_KINDS = (
    (ObligationKind.OPERATE, "operate"),
    (ObligationKind.DENY_COMPLEMENT, "deny_complement"),
    (ObligationKind.BYPASS_PREVENTION, "bypass_prevention"),
    (ObligationKind.CREDENTIAL_CUSTODY, "credential_custody"),
    (ObligationKind.AUTHENTICATED_CHANNEL, "authenticated_channel"),
    (ObligationKind.RESOURCE_LIMIT, "resource_limit"),
    (ObligationKind.EVIDENCE, "evidence"),
)
_REQUIREMENTS = ((Requirement.NEED, "need"), (Requirement.WANT, "want"))


@dataclass(frozen=True, slots=True)
class CapturedGrant:
    """Detached native filter result and wire projection when a grant exists."""

    filtered: PolicyFilterResult
    projection: bytes | None
    data: dict | None


@dataclass(frozen=True, slots=True)
class CapturedObligations:
    """Detached native obligations and their immutable semantic projection."""

    obligations: tuple[EnforcementObligation, ...]
    projection: bytes | None
    data: list


def _enum(value: Any, choices: tuple) -> str:
    for member, name in choices:
        if value is member:
            return name
    raise HostExecutionDenied("host:lean_grant_shape")


def _boolean(value: Any) -> bool:
    if type(value) is not bool:
        raise HostExecutionDenied("host:lean_grant_shape")
    return value


def _mapping(value: Any) -> dict:
    if type(value) is dict:
        return value
    if type(value) is MappingProxyType and sys.implementation.name == "cpython":
        referents = _REFERENTS(value)
        if len(referents) == 1 and type(referents[0]) is dict:
            return referents[0]
    raise HostExecutionDenied("host:lean_grant_shape")


def _condition(
    value: Any, budget: list[int], active: set[int], depth: int = 0
) -> tuple[Any, dict]:
    if depth > 12:
        raise HostExecutionDenied("host:lean_grant_shape")
    # Minimum early node charge bounds traversal; final _data accounts for the
    # complete tagged wire representation, including keys and punctuation.
    _charge(budget, 16)
    if value is None:
        return None, {"kind": "null"}
    if type(value) is bool:
        return value, {"kind": "bool", "value": value}
    if type(value) is int:
        if not -(2**63) <= value < 2**63:
            raise HostExecutionDenied("host:lean_grant_shape")
        text = str(value)  # Exact bounded native int only.
        _charge(budget, len(text))
        return value, {"kind": "int", "value": text}
    if type(value) is str:
        return value, {"kind": "text", "value": _string(value, budget=budget)}
    if type(value) is tuple or type(value) is list:
        if len(value) > 256:
            raise HostExecutionDenied("host:lean_grant_shape")
        items = tuple(value)
        identity = id(value)
        kind = "sequence"
    else:
        backing = _mapping(value)
        if len(backing) > 256:
            raise HostExecutionDenied("host:lean_grant_shape")
        pairs = tuple(backing.items())
        # Validate every native key before sorting, hashing or dictionary lookup.
        for key, _ in pairs:
            _string(key, budget=budget)
        items = tuple(sorted(pairs, key=lambda pair: pair[0]))
        identity = id(backing)
        kind = "map"
    if identity in active:
        raise HostExecutionDenied("host:lean_grant_shape")
    active.add(identity)
    try:
        native = []
        wire = []
        for item in items:
            if kind == "map":
                key, child = item
                admitted, projected = _condition(child, budget, active, depth + 1)
                native.append((key, admitted))
                wire.append({"key": key, "value": projected})
            else:
                admitted, projected = _condition(item, budget, active, depth + 1)
                native.append(admitted)
                wire.append(projected)
        return (dict(native) if kind == "map" else tuple(native)), {
            "kind": kind,
            "value": wire,
        }
    finally:
        active.remove(identity)


def _conditions(value: Any, budget: list[int]) -> tuple[dict, dict]:
    # Conditions are maps, not arbitrary tagged root values.
    _mapping(value)
    return _condition(value, budget, set())


def _capture_filtered_grant(filtered: Any, *, encode: bool = True) -> CapturedGrant:
    """Admit raw filter slots before .allowed, compilation or digest helpers.

    Local missing-layout errors are not retained as context. Ambient caller
    exception state and traceback publication remain separate concerns.
    """
    result = None
    try:
        result = _filtered(filtered, encode=encode)
    except (AttributeError, RecursionError, ValueError, TypeError):
        pass
    if result is None:
        raise HostExecutionDenied("host:lean_grant_shape")
    return result


def _filtered(filtered: Any, *, encode: bool) -> CapturedGrant:
    budget = [_MAX_REQUEST - 1]
    grant, ledger, reason, removed, diagnostics = _record(
        filtered, PolicyFilterResult, _FILTER
    )
    reason = _string(reason, budget=budget)
    removed = tuple(_strings(removed, budget=budget))
    diagnostics = tuple(_strings(diagnostics, budget=budget))
    (entries,) = _record(ledger, RequirementLedger, _LEDGER)
    detached_entries = []
    for entry in _rows(entries):
        source, requirement, ids = _record(entry, RequirementEntry, _ENTRY)
        source = _string(source, nonempty=True, budget=budget)
        _enum(requirement, _REQUIREMENTS)
        ids = frozenset(_strings(ids, unordered=True, budget=budget))
        detached_entries.append(RequirementEntry(source, requirement, ids))
    detached_ledger = RequirementLedger(tuple(detached_entries))
    if grant is None:
        return CapturedGrant(
            PolicyFilterResult(None, detached_ledger, reason, removed, diagnostics),
            None,
            None,
        )
    (
        principal,
        session,
        tool,
        artifact,
        call,
        intent,
        policy,
        rules,
        deployment,
        runtime,
    ) = _record(grant, Grant, _GRANT)
    identities = [
        _string(item, nonempty=True, budget=budget)
        for item in (principal, session, tool, artifact, call, intent, policy)
    ]
    deployment = _string(deployment, budget=budget)
    runtime = _string(runtime, budget=budget)
    native_rules = []
    projected_rules = []
    for rule in _rows(rules):
        (
            identifier,
            domain,
            operation,
            selector,
            conditions,
            requirement,
            provenance,
            baseline,
        ) = _record(rule, GrantRule, _RULE)
        identifier = _string(identifier, nonempty=True, budget=budget)
        domain_text = _enum(domain, _DOMAINS)
        operation = _string(operation, nonempty=True, budget=budget)
        selector = _string(selector, nonempty=True, budget=budget)
        native_conditions, projected_conditions = _conditions(conditions, budget)
        requirement_text = _enum(requirement, _REQUIREMENTS)
        provenance = tuple(_strings(provenance, budget=budget))
        baseline = _boolean(baseline)
        native_rules.append(
            GrantRule(
                identifier,
                domain,
                operation,
                selector,
                native_conditions,
                requirement,
                provenance,
                baseline,
            )
        )
        projected_rules.append(
            {
                "id": identifier,
                "domain": domain_text,
                "operation": operation,
                "selector": selector,
                "conditions": projected_conditions,
                "requirement": requirement_text,
                "provenance": list(provenance),
                "baseline": baseline,
            }
        )
    # Constructors/digest see only detached admitted native values.
    principal, session, tool, artifact, call, intent, policy = identities
    detached = Grant(
        principal,
        session,
        tool,
        artifact,
        call,
        intent,
        policy,
        tuple(native_rules),
        deployment,
        runtime,
    )
    projected = {
        "principal": principal,
        "session": session,
        "tool": tool,
        "artifact": artifact,
        "call": call,
        "intent": intent,
        "policy": policy,
        "deployment": deployment,
        "runtime": runtime,
        "digest": detached.digest,
        "rules": projected_rules,
    }
    data = _data(projected)
    return CapturedGrant(
        PolicyFilterResult(detached, detached_ledger, reason, removed, diagnostics),
        _encoded(data) if encode else None,
        data,
    )


def _capture_obligations(
    obligations: Any, *, encode: bool = True
) -> CapturedObligations:
    """Detach the exact generated sequence before native lowering/negotiation."""
    result = None
    try:
        result = _obligations(obligations, encode=encode)
    except (AttributeError, RecursionError, ValueError, TypeError):
        pass
    if result is None:
        raise HostExecutionDenied("host:lean_grant_shape")
    return result


def _obligations(obligations: Any, *, encode: bool) -> CapturedObligations:
    budget = [_MAX_REQUEST - 1]
    native = []
    projected = []
    for row in _rows(obligations):
        (
            identifier,
            rule,
            kind,
            domain,
            operation,
            selector,
            conditions,
            dependencies,
            waivable,
        ) = _record(row, EnforcementObligation, _OBLIGATION)
        identifier = _string(identifier, nonempty=True, budget=budget)
        rule = _string(rule, nonempty=True, budget=budget)
        kind_text = _enum(kind, _KINDS)
        domain_text = _enum(domain, _DOMAINS)
        operation = _string(operation, nonempty=True, budget=budget)
        selector = _string(selector, nonempty=True, budget=budget)
        native_conditions, projected_conditions = _conditions(conditions, budget)
        dependencies = _strings(dependencies, unordered=True, budget=budget)
        waivable = _boolean(waivable)
        native.append(
            EnforcementObligation(
                identifier,
                rule,
                kind,
                domain,
                operation,
                selector,
                native_conditions,
                frozenset(dependencies),
                waivable,
            )
        )
        projected.append(
            {
                "id": identifier,
                "rule": rule,
                "kind": kind_text,
                "domain": domain_text,
                "operation": operation,
                "selector": selector,
                "conditions": projected_conditions,
                "dependencies": dependencies,
                "waivable": waivable,
            }
        )
    data = _data(projected)
    return CapturedObligations(tuple(native), _encoded(data) if encode else None, data)
