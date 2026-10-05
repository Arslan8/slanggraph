"""Tests for restrictive security-stack composition."""

from __future__ import annotations

import time
from collections.abc import Sequence

import pytest
from hypothesis import given
from hypothesis import strategies as st

from langgraph.prebuilt.security import (
    Approval,
    Decision,
    Effect,
    Principal,
    ResourceArg,
    SecurityModule,
    SecurityStack,
    Tool,
    ToolCall,
    ToolDac,
    Verdict,
)


def _principal(scopes: Sequence[str] = ("fs:read",)) -> Principal:
    return Principal("alice", frozenset({"analyst"}), frozenset(scopes), "session")


def _call(*, allowed_path: str = "/safe") -> ToolCall:
    tool = Tool(
        "read_file",
        ToolDac(
            "analyst",
            {"analyst": "x", "*": "-"},
            frozenset({"fs:read"}),
            {"path": {allowed_path: "x", "*": "-"}},
        ),
        frozenset({Effect.READ}),
        (ResourceArg("path", "path", "realpath"),),
    )
    return ToolCall(tool, {"path": allowed_path}, {"path": allowed_path}, "call", 0)


class FixedModule(SecurityModule):
    """Test module returning a configured permission verdict."""

    def __init__(self, name: str, decision: Decision) -> None:
        self.name = name
        self.decision = decision
        self.calls = 0

    def tool_call_permission(self, principal: Principal, call: ToolCall) -> Decision:
        self.calls += 1
        return self.decision


def test_dac_denial_short_circuits_modules() -> None:
    """MAC hooks cannot observe or override an author-DAC denial."""
    module = FixedModule("allow_all", Decision(Verdict.ALLOW, "allow"))
    stack = SecurityStack([module])
    try:
        decision = stack.permission(_principal(scopes=()), _call())
    finally:
        stack.close()

    assert decision.reason == "dac:scope"
    assert module.calls == 0


@pytest.mark.parametrize("reverse", [False, True])
def test_module_order_cannot_turn_deny_into_allow(reverse: bool) -> None:
    """A permissive module cannot override a strict module in either order."""
    modules = [
        FixedModule("permissive", Decision(Verdict.ALLOW, "allow")),
        FixedModule("strict", Decision(Verdict.DENY, "strict")),
    ]
    stack = SecurityStack(list(reversed(modules)) if reverse else modules)
    try:
        decision = stack.permission(_principal(), _call())
    finally:
        stack.close()
    assert decision == Decision(Verdict.DENY, "strict")


def test_transform_is_rechecked_by_dac() -> None:
    """A prepare hook cannot widen arguments beyond author grants."""

    class WidenPath(SecurityModule):
        name = "widen"

        def tool_call_prepare(self, principal: Principal, call: ToolCall) -> Decision:
            return Decision(
                Verdict.TRANSFORM, "rewrite", new_args={"path": "/etc/passwd"}
            )

    stack = SecurityStack([WidenPath()])
    try:
        decision, transformed = stack.prepare(_principal(), _call())
    finally:
        stack.close()

    assert decision == Decision(Verdict.DENY, "prepare:dac:arg:path")
    assert transformed.normalized["path"] == "/etc/passwd"


@pytest.mark.parametrize(
    ("module", "reason"),
    [
        (
            type(
                "Raises",
                (SecurityModule,),
                {
                    "name": "raises",
                    "tool_call_permission": lambda self, principal, call: (
                        _ for _ in ()
                    ).throw(RuntimeError()),
                },
            )(),
            "module_error:raises",
        ),
        (
            type(
                "Malformed",
                (SecurityModule,),
                {
                    "name": "malformed",
                    "tool_call_permission": lambda self, principal, call: None,
                },
            )(),
            "module_error:malformed",
        ),
    ],
)
def test_module_failure_is_fail_closed(module: SecurityModule, reason: str) -> None:
    """Exceptions and malformed hook results become explicit denies."""
    stack = SecurityStack([module])
    try:
        assert stack.permission(_principal(), _call()).reason == reason
    finally:
        stack.close()


def test_sync_timeout_returns_without_waiting_for_hook() -> None:
    """A slow sync policy is cancelled from the enforcement path."""

    class Slow(SecurityModule):
        name = "slow"

        def tool_call_permission(
            self, principal: Principal, call: ToolCall
        ) -> Decision:
            time.sleep(0.5)
            return Decision(Verdict.ALLOW, "late")

    stack = SecurityStack([Slow()], policy_timeout_s=0.02)
    started = time.monotonic()
    try:
        decision = stack.permission(_principal(), _call())
    finally:
        stack.close()

    assert decision.reason == "module_timeout:slow"
    assert time.monotonic() - started < 0.2


@pytest.mark.asyncio
async def test_async_parity() -> None:
    """Async enforcement preserves restrictive sync semantics."""
    strict = FixedModule("strict", Decision(Verdict.DENY, "strict"))
    stack = SecurityStack([strict])
    try:
        decision = await stack.apermission(_principal(), _call())
        resume = await stack.aresume_permission(
            _principal(), Approval("approval", False, "reviewer")
        )
    finally:
        stack.close()
    assert decision.verdict is Verdict.DENY
    assert resume.reason == "cap:approval_rejected"


@given(dac_allows=st.booleans(), module_allows=st.lists(st.booleans(), max_size=8))
def test_no_module_sequence_allows_after_dac_denial(
    dac_allows: bool, module_allows: list[bool]
) -> None:
    """Property: final allow requires DAC and every module to allow."""
    modules = [
        FixedModule(
            f"m{index}",
            Decision(Verdict.ALLOW if allows else Verdict.DENY, "policy"),
        )
        for index, allows in enumerate(module_allows)
    ]
    principal = _principal() if dac_allows else _principal(scopes=())
    stack = SecurityStack(modules)
    try:
        decision = stack.permission(principal, _call())
    finally:
        stack.close()
    assert (decision.verdict is Verdict.ALLOW) is (dac_allows and all(module_allows))
