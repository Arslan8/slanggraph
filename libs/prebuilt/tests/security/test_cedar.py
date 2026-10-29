"""Cedar policy compilation and fail-closed engine integration."""

from __future__ import annotations

import json
from pathlib import Path

import pytest

from langgraph.prebuilt.security.cedar import CedarPolicyBackend
from langgraph.prebuilt.security.enforcement import (
    AuthorityDomain,
    Grant,
    GrantRule,
    RequirementEntry,
    RequirementLedger,
)
from langgraph.prebuilt.security.profile import Requirement
from langgraph.prebuilt.security.types import ForbidConstraint, RulePredicate


def _grant(*rules: GrantRule) -> Grant:
    return Grant(
        "alice",
        "session",
        "research",
        "artifact",
        "call",
        "intent",
        "policy",
        rules,
    )


def _ledger(*rules: GrantRule) -> RequirementLedger:
    return RequirementLedger(
        tuple(
            RequirementEntry(
                f"source:{rule.rule_id}",
                rule.requirement,
                frozenset({rule.rule_id}),
            )
            for rule in rules
        )
    )


def _fake_cedar(tmp_path: Path, *, validation_error: bool = False) -> Path:
    executable = tmp_path / "cedar"
    executable.write_text(
        "#!/usr/bin/env python3\n"
        "import json, pathlib, sys\n"
        "root = pathlib.Path(__file__).parent\n"
        "with (root / 'cedar.log').open('a') as stream:\n"
        "    stream.write(json.dumps(sys.argv[1:]) + '\\n')\n"
        "if sys.argv[1] == 'validate':\n"
        + (
            "    print('type error in module forbid', file=sys.stderr)\n"
            "    raise SystemExit(1)\n"
            if validation_error
            else "    print('VALID')\n    raise SystemExit(0)\n"
        )
        + "request = json.loads(pathlib.Path(sys.argv[sys.argv.index('--request-json') + 1]).read_text())\n"
        "policy = pathlib.Path(sys.argv[sys.argv.index('--policies') + 1]).read_text()\n"
        "resource = request['resource']\n"
        "needle = f'resource == {resource}'\n"
        "matched = request['context']['matchedForbids']\n"
        "print('ALLOW' if needle in policy and not matched else 'DENY')\n",
        encoding="utf-8",
    )
    executable.chmod(0o755)
    return executable


def test_cedar_validates_and_evaluates_one_ephemeral_permit_per_rule(
    tmp_path: Path,
) -> None:
    first = GrantRule("one", AuthorityDomain.FILESYSTEM, "read", "/one")
    second = GrantRule("two", AuthorityDomain.FILESYSTEM, "read", "/two")
    constraint = ForbidConstraint(
        "offline",
        RulePredicate(domain=AuthorityDomain.NETWORK.value),
        "no network",
        "network",
    )
    executable = _fake_cedar(tmp_path)

    result = CedarPolicyBackend(executable).filter(
        _grant(first, second), _ledger(first, second), (constraint,)
    )

    assert result.allowed
    assert result.reason == "allow:cedar"
    invocations = [
        json.loads(line) for line in (tmp_path / "cedar.log").read_text().splitlines()
    ]
    assert [item[0] for item in invocations] == [
        "validate",
        "authorize",
        "authorize",
    ]


def test_cedar_reuses_successful_policy_verification(tmp_path: Path) -> None:
    rule = GrantRule("one", AuthorityDomain.FILESYSTEM, "read", "/one")
    executable = _fake_cedar(tmp_path)
    backend = CedarPolicyBackend(executable)

    first = backend.filter(_grant(rule), _ledger(rule), ())
    second = backend.filter(_grant(rule), _ledger(rule), ())

    assert first == second
    invocations = [
        json.loads(line) for line in (tmp_path / "cedar.log").read_text().splitlines()
    ]
    assert [item[0] for item in invocations] == ["validate", "authorize"]


def test_cedar_cache_can_be_disabled(tmp_path: Path) -> None:
    rule = GrantRule("one", AuthorityDomain.FILESYSTEM, "read", "/one")
    executable = _fake_cedar(tmp_path)
    backend = CedarPolicyBackend(executable, cache_entries=0)

    backend.filter(_grant(rule), _ledger(rule), ())
    backend.filter(_grant(rule), _ledger(rule), ())

    invocations = [
        json.loads(line) for line in (tmp_path / "cedar.log").read_text().splitlines()
    ]
    assert [item[0] for item in invocations] == [
        "validate",
        "authorize",
        "validate",
        "authorize",
    ]


def test_cedar_cache_is_invalidated_when_engine_changes(tmp_path: Path) -> None:
    rule = GrantRule("one", AuthorityDomain.FILESYSTEM, "read", "/one")
    executable = _fake_cedar(tmp_path)
    backend = CedarPolicyBackend(executable)
    assert backend.filter(_grant(rule), _ledger(rule), ()).allowed

    _fake_cedar(tmp_path, validation_error=True)
    result = backend.filter(_grant(rule), _ledger(rule), ())

    assert not result.allowed
    assert result.diagnostics == ("cedar_error:validation:type error in module forbid",)


def test_cedar_rejects_negative_cache_size() -> None:
    with pytest.raises(ValueError, match="cache size"):
        CedarPolicyBackend(cache_entries=-1)


def test_missing_cedar_engine_denies() -> None:
    rule = GrantRule("one", AuthorityDomain.FILESYSTEM, "read", "/one")
    result = CedarPolicyBackend("/definitely/missing/cedar").filter(
        _grant(rule), _ledger(rule), ()
    )
    assert not result.allowed
    assert result.diagnostics == ("cedar_error:executable_unavailable",)


def test_cedar_observes_forbid_wins_for_removed_want(tmp_path: Path) -> None:
    rule = GrantRule(
        "network",
        AuthorityDomain.NETWORK,
        "connect",
        "443",
        requirement=Requirement.WANT,
    )
    constraint = ForbidConstraint(
        "offline",
        RulePredicate(domain=AuthorityDomain.NETWORK.value),
        "no network",
        "network",
    )
    result = CedarPolicyBackend(_fake_cedar(tmp_path)).filter(
        _grant(rule), _ledger(rule), (constraint,)
    )
    assert result.allowed
    assert result.grant is not None and result.grant.rules == ()


def test_cedar_validation_error_denies_and_names_stage(tmp_path: Path) -> None:
    rule = GrantRule("one", AuthorityDomain.FILESYSTEM, "read", "/one")
    result = CedarPolicyBackend(_fake_cedar(tmp_path, validation_error=True)).filter(
        _grant(rule), _ledger(rule), ()
    )
    assert not result.allowed
    assert result.diagnostics == ("cedar_error:validation:type error in module forbid",)


def test_module_cannot_emit_a_permit_policy(tmp_path: Path) -> None:
    class PermitPolicy:
        module = "bad_module"

    rule = GrantRule("one", AuthorityDomain.FILESYSTEM, "read", "/one")
    result = CedarPolicyBackend(_fake_cedar(tmp_path)).filter(
        _grant(rule),
        _ledger(rule),
        (PermitPolicy(),),  # type: ignore[arg-type]
    )
    assert not result.allowed
    assert result.diagnostics
    assert "bad_module" in result.diagnostics[0]
    assert not (tmp_path / "cedar.log").exists()
