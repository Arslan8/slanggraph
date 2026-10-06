"""Tests for the frozen profile grammar and constructive DAC evaluator."""

from __future__ import annotations

import re
from dataclasses import FrozenInstanceError, replace

import pytest
from hypothesis import given
from hypothesis import strategies as st

from langgraph.prebuilt.security import (
    DacOverrides,
    FsRule,
    PathTemplate,
    PrincipalProfile,
    ProfileSyntaxError,
    Requirement,
    ShareRule,
    ToolProfile,
    evaluate_dac,
    parse_profiles,
)

PROFILE = """
tool read_file {
  owner analyst
  grant analyst manager: call
  requires fs:read
  runs inprocess
  delegable no
  syscalls @file-read
  fs read ${path} need
  net none
  exec none
  service none
  limits cpu 2s mem 256M pids 1 nofile 64 wall 5s
  returns sensitive
}

tool run_shell {
  owner ops; grant ops: call; runs subprocess; delegable no
  syscalls @process @file-read
  exec /usr/bin/${argv0} need
  fs read /usr need, read+write ${cwd} want
  net none
}

principal alice {
  roles analyst
  scopes fs:read
  fs ${home}/**
  net connect 443
  service mail(as: alice@corp.example)
  credential gmail(scope: send)
  share bob: read ${home}/shared/**
}

principal bob {
  roles guest
  fs /home/bob/**
}
"""


def test_parse_complete_profile_and_freeze_ast() -> None:
    """All frozen directives parse to immutable, typed values."""
    document = parse_profiles(PROFILE, source="course.slp")
    tool = document.tools["read_file"]
    alice = document.principals["alice"]

    assert tool.call_grants == {"analyst", "manager"}
    assert tool.syscall_sets == {"file-read"}
    assert tool.limits.cpu_ms == 2_000
    assert tool.limits.memory_bytes == 256 * 1024**2
    assert tool.limits.nofile == 64
    assert alice.fs[0].path == PathTemplate("${home}", subtree=True)
    assert alice.services[0].attributes == {"as": "alice@corp.example"}
    assert alice.credentials[0].attributes == {"scope": "send"}
    with pytest.raises(TypeError):
        document.tools["other"] = tool  # type: ignore[index]
    with pytest.raises(FrozenInstanceError):
        tool.owner = "other"  # type: ignore[misc]


def test_evaluate_exact_path_inside_principal_subtree() -> None:
    """Binding and intersection retain only authority both sides name."""
    document = parse_profiles(PROFILE)

    result = document.evaluate(
        "read_file",
        "alice",
        {"path": "/home/alice/report.txt"},
        principal_bindings={"alice": {"home": "/home/alice"}},
    )

    assert result.denied is False
    assert result.grant.subject == ("alice", "read_file")
    assert result.grant.fs[0].path.value == "/home/alice/report.txt"
    assert result.grant.fs[0].operations == {"read"}


def test_removed_need_denies_and_removed_want_is_recorded() -> None:
    """A missing need denies the call while a want simply disappears."""
    document = parse_profiles(PROFILE)
    principal = PrincipalProfile(
        "ops-user",
        roles={"ops"},
        fs=(FsRule({"read"}, PathTemplate("/usr", subtree=True)),),
        exec=(),
    )

    result = evaluate_dac(
        document.tools["run_shell"],
        principal,
        {"argv0": "echo", "cwd": "/work"},
    )

    assert result.denied is True
    assert result.reason == "required_line_removed"
    assert {line.resource_class for line in result.removed} == {"exec", "fs"}
    assert {line.requirement for line in result.removed} == {
        Requirement.NEED,
        Requirement.WANT,
    }


def test_inbound_share_contributes_only_its_operations() -> None:
    """A share augments the recipient envelope but cannot widen its operation."""
    document = parse_profiles(PROFILE)
    tool = ToolProfile(
        "shared_reader",
        owner="analyst",
        call_grants={"bob"},
        fs=(
            FsRule(
                {"read", "write"},
                PathTemplate("${path}"),
                Requirement.WANT,
            ),
        ),
    )
    overridden = DacOverrides(profiles={"shared_reader": tool})
    expanded = replace(
        document,
        tools={**document.tools, "shared_reader": tool},
    )

    result = expanded.evaluate(
        "shared_reader",
        "bob",
        {"path": "/home/alice/shared/data.txt"},
        principal_bindings={
            "alice": {"home": "/home/alice"},
            "bob": {},
        },
        dac_overrides=overridden,
    )

    assert result.denied is False
    assert len(result.grant.fs) == 1
    assert result.grant.fs[0].operations == {"read"}
    assert overridden["shared_reader"].grants == {"bob": "x", "*": "-"}


def test_profile_override_replaces_the_complete_tool_block() -> None:
    """Operator profile overrides replace rather than merge author lines."""
    document = parse_profiles(PROFILE)
    override = ToolProfile(
        "read_file",
        owner="operator",
        call_grants={"*"},
        fs=(
            FsRule(
                {"read"},
                PathTemplate("/public", subtree=True),
                Requirement.WANT,
            ),
        ),
        returns="public",
    )

    result = document.evaluate(
        "read_file",
        "bob",
        {},
        principal_bindings={"alice": {"home": "/home/alice"}},
        dac_overrides=DacOverrides(profiles={"read_file": override}),
    )

    assert result.denied is False
    assert result.reason is None
    assert result.grant.returns == "public"
    assert result.removed[0].requirement is Requirement.WANT


def test_direct_evaluator_ignores_share_for_another_subject() -> None:
    """The low-level evaluator does not trust callers to prefilter shares."""
    result = evaluate_dac(
        _tool({"/shared/file"}),
        _principal(set()),
        {},
        inbound_shares=(
            (ShareRule("mallory", {"read"}, PathTemplate("/shared", True)), {}),
        ),
    )

    assert result.grant.fs == ()
    assert len(result.removed) == 1


@pytest.mark.parametrize(
    ("path", "message"),
    [
        ("relative", "absolute"),
        ("/safe/*/file", "terminal '/**'"),
        ("/safe/${bad-name}", "malformed variable"),
    ],
)
def test_invalid_path_grammar_fails_at_parse(path: str, message: str) -> None:
    """Unsafe or ambiguous path syntax never reaches evaluation."""
    with pytest.raises(ProfileSyntaxError, match=re.escape(message)):
        parse_profiles(
            f"tool x {{ owner root; grant root: call; fs read {path} need }}"
        )


@pytest.mark.parametrize("path", ["../secret", "/safe/../secret", "/safe/"])
def test_noncanonical_bound_path_fails_closed(path: str) -> None:
    """The evaluator refuses to normalize path arguments on the caller's behalf."""
    document = parse_profiles(PROFILE)
    with pytest.raises(ValueError, match="absolute|normalized"):
        document.evaluate(
            "read_file",
            "alice",
            {"path": path},
            principal_bindings={"alice": {"home": "/home/alice"}},
        )


def test_duplicate_and_unknown_directives_report_source() -> None:
    """Parser diagnostics name the source line and invalid directive."""
    with pytest.raises(ProfileSyntaxError, match=r"bad\.slp:3:3: duplicate"):
        parse_profiles("tool x {\n  owner one\n  owner two\n}", source="bad.slp")
    with pytest.raises(ProfileSyntaxError, match="unknown principal directive"):
        parse_profiles("principal alice { magic yes }")


_PATHS = tuple(f"/data/{index}" for index in range(5))
_PATH_SETS = st.sets(st.sampled_from(_PATHS))


def _tool(paths: set[str]) -> ToolProfile:
    return ToolProfile(
        "reader",
        owner="owner",
        call_grants={"alice"},
        fs=tuple(
            FsRule({"read"}, PathTemplate(path), Requirement.WANT)
            for path in sorted(paths)
        ),
    )


def _principal(paths: set[str]) -> PrincipalProfile:
    return PrincipalProfile(
        "alice",
        fs=tuple(FsRule({"read"}, PathTemplate(path)) for path in sorted(paths)),
    )


def _surviving(result) -> set[tuple[str, frozenset[str]]]:
    return {(line.path.value, line.operations) for line in result.grant.fs}


@given(smaller=_PATH_SETS, extra=_PATH_SETS, envelope=_PATH_SETS)
def test_constructive_grant_is_monotone_in_tool_profile(
    smaller: set[str], extra: set[str], envelope: set[str]
) -> None:
    """Removing requested tool lines cannot add a surviving line."""
    small = _surviving(evaluate_dac(_tool(smaller), _principal(envelope), {}))
    large = _surviving(evaluate_dac(_tool(smaller | extra), _principal(envelope), {}))
    assert small <= large


@given(requested=_PATH_SETS, smaller=_PATH_SETS, extra=_PATH_SETS)
def test_constructive_grant_is_monotone_in_principal_envelope(
    requested: set[str], smaller: set[str], extra: set[str]
) -> None:
    """Removing principal authority cannot add a surviving line."""
    small = _surviving(evaluate_dac(_tool(requested), _principal(smaller), {}))
    large = _surviving(evaluate_dac(_tool(requested), _principal(smaller | extra), {}))
    assert small <= large


@given(requested=_PATH_SETS, smaller=_PATH_SETS, extra=_PATH_SETS)
def test_constructive_grant_is_monotone_in_shares(
    requested: set[str], smaller: set[str], extra: set[str]
) -> None:
    """Removing inbound shares cannot add a surviving line."""
    principal = _principal(set())

    def shares(paths: set[str]):
        return tuple(
            (
                ShareRule("alice", {"read"}, PathTemplate(path)),
                {},
            )
            for path in sorted(paths)
        )

    small = _surviving(
        evaluate_dac(_tool(requested), principal, {}, inbound_shares=shares(smaller))
    )
    large = _surviving(
        evaluate_dac(
            _tool(requested),
            principal,
            {},
            inbound_shares=shares(smaller | extra),
        )
    )
    assert small <= large
