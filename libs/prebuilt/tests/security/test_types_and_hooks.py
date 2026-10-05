"""Tests for the graph-independent security module API."""

from __future__ import annotations

from dataclasses import FrozenInstanceError
from pathlib import Path

import pytest

from langgraph.prebuilt.security import (
    Approval,
    Blobs,
    Decision,
    Effect,
    EscalationRequest,
    Principal,
    ResourceArg,
    SecurityModule,
    Tool,
    ToolCall,
    ToolDac,
    Verdict,
)


def _principal() -> Principal:
    return Principal(
        user_id="alice",
        roles=frozenset({"analyst"}),
        scopes=frozenset({"fs:read"}),
        session_id="session-1",
    )


def _tool() -> Tool:
    return Tool(
        name="read_file",
        dac=ToolDac(owner="analyst", grants={"analyst": "x"}),
        effects=frozenset({Effect.READ}),
        resources=(ResourceArg("path", "path", "realpath"),),
    )


def _call() -> ToolCall:
    return ToolCall(
        tool=_tool(),
        args={"path": "notes.txt"},
        normalized={"path": "/workspace/notes.txt"},
        call_id="call-1",
        call_index=0,
    )


def test_public_records_are_frozen_and_collections_are_snapshotted() -> None:
    """Policy input cannot be changed by mutating caller-owned collections."""
    roles = {"analyst"}
    principal = Principal(
        user_id="alice",
        roles=frozenset(roles),
        scopes=frozenset(),
        session_id="session-1",
    )
    roles.add("admin")

    assert principal.roles == {"analyst"}
    with pytest.raises(FrozenInstanceError):
        principal.user_id = "mallory"  # type: ignore[misc]
    with pytest.raises(TypeError):
        _call().args["path"] = "/etc/passwd"  # type: ignore[index]


def test_blobs_allocate_private_independent_slots() -> None:
    """Cloning blobs does not share mutable policy state."""
    blobs = Blobs()
    blobs.allocate("paths")["root"] = "/workspace"
    copied = blobs.clone()
    copied["paths"]["root"] = "/tmp"

    assert blobs["paths"]["root"] == "/workspace"
    assert copied["paths"]["root"] == "/tmp"


def test_decision_payload_invariants() -> None:
    """Verdict-specific payloads cannot be mixed or omitted."""
    with pytest.raises(ValueError, match="TRANSFORM requires"):
        Decision(Verdict.TRANSFORM, "narrow")
    with pytest.raises(ValueError, match="ALLOW and DENY"):
        Decision(Verdict.ALLOW, "ok", new_args={})

    transformed = Decision(Verdict.TRANSFORM, "narrow", new_args={"path": "a"})
    assert transformed.new_args == {"path": "a"}


def test_escalation_payload_contains_no_tool_arguments() -> None:
    """Human approval payloads expose identifiers, not sensitive arguments."""
    escalation = EscalationRequest(
        request_id="approval-1",
        reason="human_review",
        tool_name="send_email",
        call_id="call-1",
        metadata={"risk": "high"},
    )

    payload = escalation.to_payload()

    assert payload["type"] == "security_approval"
    assert "args" not in payload


def test_security_module_defaults_are_no_op_allow() -> None:
    """A module objects only by explicitly overriding a decision hook."""
    module = SecurityModule()
    principal = _principal()
    call = _call()
    slot = principal.security.allocate(module.name)
    approval = Approval("approval-1", True, "reviewer")

    assert module.cred_transfer(principal, principal, slot).verdict is Verdict.ALLOW
    assert module.tool_call_prepare(principal, call).verdict is Verdict.ALLOW
    assert module.tool_call_permission(principal, call).verdict is Verdict.ALLOW
    assert module.resume_permission(principal, approval).verdict is Verdict.ALLOW
    assert module.tool_alloc_security(call.tool, slot) is None
    assert module.cred_prepare(principal, slot) is None
    assert module.tool_call_post(principal, call, "result", slot) is None


def test_types_and_hooks_do_not_import_langgraph_runtime() -> None:
    """Student policy modules remain usable without graph internals."""
    package = Path(__file__).parents[2] / "langgraph" / "prebuilt" / "security"

    for filename in ("types.py", "hooks.py"):
        source = (package / filename).read_text()
        assert "langgraph.graph" not in source
        assert "langgraph.runtime" not in source
        assert "langgraph.prebuilt.tool_node" not in source
