"""Tests for framework discretionary access control."""

from __future__ import annotations

from collections.abc import Mapping
from typing import Any

import pytest
from hypothesis import given
from hypothesis import strategies as st

from langgraph.prebuilt.security import (
    Effect,
    Principal,
    Tool,
    ToolDac,
    Verdict,
    dac_check,
)


def _principal(
    *,
    user_id: str = "alice",
    roles: frozenset[str] = frozenset({"analyst"}),
    scopes: frozenset[str] = frozenset({"tool:read", "fs:read"}),
) -> Principal:
    return Principal(user_id, roles, scopes, "session-1")


def _tool(
    *,
    owner: str = "owner",
    grants: Mapping[str, str] | None = None,
    required_scopes: frozenset[str] = frozenset(),
    arg_grants: Mapping[str, Mapping[str, str]] | None = None,
) -> Tool:
    return Tool(
        "read",
        ToolDac(
            owner,
            grants or {"*": "-"},
            required_scopes,
            arg_grants or {},
        ),
        frozenset({Effect.READ}),
        (),
    )


@pytest.mark.parametrize(
    ("principal", "tool", "normalized", "verdict", "reason"),
    [
        (_principal(user_id="owner"), _tool(), {}, Verdict.ALLOW, "dac:allow"),
        (
            _principal(roles=frozenset({"analyst"})),
            _tool(grants={"analyst": "x", "*": "-"}),
            {},
            Verdict.ALLOW,
            "dac:allow",
        ),
        (
            _principal(roles=frozenset({"guest"})),
            _tool(grants={"*": "x"}),
            {},
            Verdict.ALLOW,
            "dac:allow",
        ),
        (
            _principal(scopes=frozenset()),
            _tool(owner="alice", required_scopes=frozenset({"fs:read"})),
            {},
            Verdict.DENY,
            "dac:scope",
        ),
        (
            _principal(),
            _tool(
                owner="alice",
                arg_grants={"path": {"/workspace/safe": "x", "*": "-"}},
            ),
            {"path": "/workspace/safe"},
            Verdict.ALLOW,
            "dac:allow",
        ),
        (
            _principal(),
            _tool(owner="alice", arg_grants={"path": {"*": "-"}}),
            {"path": "/etc/passwd"},
            Verdict.DENY,
            "dac:arg:path",
        ),
        (
            _principal(),
            _tool(grants={"*": "-"}),
            {},
            Verdict.DENY,
            "dac:grant",
        ),
    ],
)
def test_dac_table(
    principal: Principal,
    tool: Tool,
    normalized: Mapping[str, Any],
    verdict: Verdict,
    reason: str,
) -> None:
    """Every author DAC clause has an explicit allow and deny path."""
    decision = dac_check(principal, tool, normalized)
    assert (decision.verdict, decision.reason) == (verdict, reason)


def test_missing_normalized_argument_does_not_invent_a_dependency() -> None:
    """Argument grants apply only when the named normalized value is present."""
    tool = _tool(owner="alice", arg_grants={"path": {"*": "-"}})
    assert dac_check(_principal(), tool, {}).verdict is Verdict.ALLOW


@given(
    user_id=st.text(min_size=1),
    role=st.text(min_size=1),
    scope=st.text(min_size=1),
    granted=st.booleans(),
)
def test_dac_check_is_pure(user_id: str, role: str, scope: str, granted: bool) -> None:
    """Repeated evaluation depends only on explicit immutable inputs."""
    principal = _principal(
        user_id=user_id, roles=frozenset({role}), scopes=frozenset({scope})
    )
    tool = _tool(
        grants={role: "x" if granted else "-", "*": "-"},
        required_scopes=frozenset({scope}),
    )
    normalized = {"path": "/constant"}

    first = dac_check(principal, tool, normalized)
    second = dac_check(principal, tool, normalized)

    assert first == second
    assert normalized == {"path": "/constant"}
