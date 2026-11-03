"""Cedar string encoding and real-engine Unicode identity regressions."""

from __future__ import annotations

import json
import shutil
import subprocess
from pathlib import Path

import pytest

from langgraph.prebuilt.security import object_policy as op
from langgraph.prebuilt.security.cedar import CedarPolicyBackend, _cedar_string
from langgraph.prebuilt.security.enforcement import (
    AuthorityDomain,
    Grant,
    GrantRule,
    RequirementEntry,
    RequirementLedger,
)


@pytest.mark.parametrize("encode", [op._cedar, _cedar_string])
@pytest.mark.parametrize(
    ("value", "expected"),
    [
        ("alice", "alice"),
        ("josé", "josé"),
        ("jose\u0301", "jose\u0301"),
        ("使用者", "使用者"),
        ("😀", "😀"),
        ('a"b\\c', 'a\\"b\\\\c'),
        (r"jos\u00e9", r"jos\\u00e9"),
        ("\n\r\t\b\f\0\x7f", r"\n\r\t\u{8}\u{c}\u{0}\u{7f}"),
    ],
)
def test_cedar_encoding_preserves_identity(encode, value: str, expected: str) -> None:
    assert encode(value) == expected


@pytest.mark.parametrize("encode", [op._cedar, _cedar_string])
@pytest.mark.parametrize("value", ["\ud800", "\udfff"])
def test_cedar_encoding_rejects_non_scalar_values(encode, value: str) -> None:
    with pytest.raises(ValueError, match="surrogates"):
        encode(value)


class _Broker:
    enforcer_id = "unicode-regression"

    def supports(self, object_class, line):
        return object_class.enforced_by is op.EnforcementKind.BROKER


@pytest.fixture
def cedar() -> str:
    executable = shutil.which("cedar")
    if executable is None:
        pytest.skip("Real Cedar CLI required")
    return executable


@pytest.mark.parametrize(
    "principal", ["alice", "josé", "jose\u0301", "使用者", "😀", 'a"b\\c', r"jos\u00e9"]
)
def test_object_authorizer_preserves_unicode_identity(
    cedar: str, principal: str
) -> None:
    manifest = op.parse_security_manifest(
        """class record {
  operations read
  object item
  normalizer identity
  attrs owner
  enforced_by broker
}
tool lookup {
  runs broker
  record read @{item} need
  returns normal
}
""",
        enforcers={op.EnforcementKind.BROKER: _Broker()},
    )
    # Entity attributes are JSON, not Cedar literals. This comparison therefore
    # checks identity against an independently encoded value, not the same bug
    # on both sides of an entity-literal comparison.
    policy = (
        'permit(principal, action, resource) when { principal.roles.contains("許可") };'
    )
    authorizer = op.CedarObjectAuthorizer(
        manifest, op.CedarPolicySet({"lookup": policy}, policy), executable=cedar
    )
    inputs = dict(
        principal_id=principal,
        tool_name="lookup",
        tool_owner="propriétaire",
        arguments={"item": 'résumé/使用者/😀/"quoted"/\\literal'},
    )
    grant = authorizer.authorize(roles={"許可"}, call_id="allowed", **inputs)
    assert grant.principal_id == principal
    assert grant.lines[0].selector == inputs["arguments"]["item"]
    with pytest.raises(op.ObjectPolicyDenied):
        authorizer.authorize(roles={"別人"}, call_id="denied", **inputs)


def test_accented_principal_does_not_alias_another_identity(cedar: str) -> None:
    manifest = op.parse_security_manifest(
        "tool lookup {\n runs broker\n returns normal\n}"
    )
    policy = 'permit(principal == slangGraph::User::"josé", action, resource);'
    authorizer = op.CedarObjectAuthorizer(
        manifest, op.CedarPolicySet({"lookup": policy}, policy), executable=cedar
    )
    for principal in ("josé", "jose", "jose\u0301", r"jos\u00e9"):
        inputs = dict(
            principal_id=principal,
            roles=(),
            tool_name="lookup",
            tool_owner="owner",
            call_id=principal,
            arguments={},
        )
        if principal == "josé":
            assert authorizer.authorize(**inputs).principal_id == principal
        else:
            with pytest.raises(op.ObjectPolicyDenied):
                authorizer.authorize(**inputs)


@pytest.mark.parametrize("optimization", ["no", "normal", "aggressive"])
def test_grant_backend_accepts_unicode(cedar: str, optimization: str) -> None:
    rule = GrantRule("règle", AuthorityDomain.FILESYSTEM, "read", "/résumé")
    grant = Grant(
        "josé", "session", "tool", "artifact", "call", "intent", "policy", (rule,)
    )
    ledger = RequirementLedger(
        (RequirementEntry("source", rule.requirement, frozenset({rule.rule_id})),)
    )
    result = CedarPolicyBackend(cedar, optimization_level=optimization).filter(
        grant, ledger, ()
    )
    assert result.allowed
    assert result.grant is not None
    assert result.grant.principal_id == grant.principal_id
    assert result.grant.rules == grant.rules


def test_cedar_control_escapes_parse_without_changing_value(
    cedar: str, tmp_path: Path
) -> None:
    value = "\b\f\0\x1f\x7f\n\r\t"
    policy = tmp_path / "policy.cedar"
    policy.write_text(
        f'permit(principal, action, resource) when {{ context.value == "{op._cedar(value)}" }};'
    )
    request = tmp_path / "request.json"
    request.write_text(
        json.dumps(
            {
                "principal": 'User::"alice"',
                "action": 'Action::"read"',
                "resource": 'Record::"one"',
                "context": {"value": value},
            }
        )
    )
    entities = tmp_path / "entities.json"
    entities.write_text("[]")
    result = subprocess.run(
        [
            cedar,
            "authorize",
            "--policies",
            str(policy),
            "--entities",
            str(entities),
            "--request-json",
            str(request),
        ],
        capture_output=True,
        text=True,
        check=False,
    )
    assert result.returncode == 0, result.stderr
    assert result.stdout.strip() == "ALLOW"
