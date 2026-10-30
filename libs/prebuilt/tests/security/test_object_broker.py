"""Real kernel-confined object broker tests, including hostile requests."""

import hashlib
import socket
import sys
from dataclasses import replace
from pathlib import Path

import pytest

from langgraph.prebuilt.security import ResourceSupport, SupportLevel
from langgraph.prebuilt.security.capabilities import probe_landlock_abi
from langgraph.prebuilt.security.execution import (
    HostExecutionDenied,
    HostExecutionError,
)
from langgraph.prebuilt.security.linux import LinuxToolSpec
from langgraph.prebuilt.security.object_broker import ObjectBrokerDispatcher
from langgraph.prebuilt.security.object_policy import (
    EnforcementKind,
    ObjectGrant,
    ObjectGrantLine,
)
from langgraph.prebuilt.security.profile import Requirement
from langgraph.prebuilt.security.types import (
    ExecutionOutcome,
    Principal,
    Tool,
    ToolCall,
    ToolDac,
)
from tests.security.mediator_fixtures import exact_mediator


@pytest.fixture
def setup(tmp_path):
    source = tmp_path / "worker.py"
    source.write_text("""
from langgraph.prebuilt.security.object_broker import object_request
import socket
import os
import json

def run(operation, selector, direct=False, spoof=False):
    if spoof:
        fd = int(os.environ["SLANGGRAPH_BROKER_FD"])
        request = {"service": '["pump","pump-1"]', "operation": "inspect",
                   "payload": {}, "principal": "administrator"}
        os.write(fd, json.dumps(request).encode() + bytes([10]))
        return json.loads(os.read(fd, 4096))["status"]
    if direct:
        try:
            sock = socket.socket(socket.AF_UNIX, socket.SOCK_STREAM)
            sock.connect(selector)
        except OSError:
            return "blocked"
        return "escaped"
    try:
        return object_request("pump", operation, selector)
    except PermissionError:
        return "denied"

async def async_run(operation, selector):
    return run(operation, selector)
""")
    seen = []

    def handle(line, payload):
        seen.append((line.operation, line.selector))
        return "inspected"

    dispatcher = ObjectBrokerDispatcher(
        {
            "pump_tool": LinuxToolSpec(
                "worker:run", source, hashlib.sha256(source.read_bytes()).hexdigest()
            )
        },
        mediators=(exact_mediator({("pump", "inspect"): handle}),),
        runtime_roots=tuple(Path(p) for p in sys.path if p and Path(p).is_dir()),
    )
    principal = Principal("alice", frozenset(), frozenset(), "session")
    call = ToolCall(
        Tool("pump_tool", ToolDac("owner", {"*": "x"}), frozenset(), ()),
        {"operation": "inspect", "selector": "pump-1"},
        {},
        "call-1",
        0,
    )
    grant = ObjectGrant(
        "alice",
        "pump_tool",
        "call-1",
        "policy",
        (
            ObjectGrantLine(
                "pump_tool:0",
                "pump",
                "inspect",
                "pump-1",
                {},
                Requirement.NEED,
                EnforcementKind.BROKER,
            ),
        ),
    )
    return dispatcher, principal, call, grant, seen


@pytest.mark.skipif(probe_landlock_abi() < 1, reason="Landlock required")
@pytest.mark.parametrize(
    "operation,selector,expected",
    [
        ("inspect", "pump-1", "inspected"),
        ("calibrate", "pump-1", "denied"),
        ("inspect", "pump-2", "denied"),
    ],
)
def test_exact_capability(setup, operation, selector, expected):
    dispatcher, principal, call, grant, seen = setup
    call = replace(call, args={"operation": operation, "selector": selector})
    result = dispatcher.invoke(principal, call, grant)
    assert result.value == expected
    assert seen == ([("inspect", "pump-1")] if expected == "inspected" else [])
    assert result.receipt.grant_digest == grant.digest


@pytest.mark.skipif(probe_landlock_abi() < 1, reason="Landlock required")
def test_no_direct_socket(setup, tmp_path):
    dispatcher, principal, call, grant, seen = setup
    path = str(tmp_path / "pump.sock")
    with socket.socket(socket.AF_UNIX) as server:
        server.bind(path)
        server.listen()
        call = replace(
            call, args={"operation": "inspect", "selector": path, "direct": True}
        )
        assert dispatcher.invoke(principal, call, grant).value == "blocked"
    assert not seen


@pytest.mark.skipif(probe_landlock_abi() < 1, reason="Landlock required")
def test_import_time_effect_is_confined_before_legitimate_broker_call(setup, tmp_path):
    dispatcher, principal, call, grant, seen = setup
    forbidden = tmp_path / "forbidden.txt"
    forbidden.write_text("unchanged")
    source = dispatcher.tools[call.tool.name].artifact_path
    source.write_text(
        f"""from pathlib import Path
from langgraph.prebuilt.security.object_broker import object_request

try:
    Path({str(forbidden)!r}).write_text("import escaped")
except OSError as error:
    IMPORT_EFFECT = {{"blocked": type(error).__name__}}
else:
    IMPORT_EFFECT = {{"blocked": False}}

def run(operation, selector):
    return {{"import_effect": IMPORT_EFFECT,
            "legitimate": object_request("pump", operation, selector)}}
"""
    )
    dispatcher = ObjectBrokerDispatcher(
        {
            call.tool.name: LinuxToolSpec(
                "worker:run", source, hashlib.sha256(source.read_bytes()).hexdigest()
            )
        },
        mediators=dispatcher.mediators,
        runtime_roots=dispatcher.runtime_roots,
    )

    result = dispatcher.invoke(principal, call, grant)

    assert result.value["legitimate"] == "inspected"
    assert result.value["import_effect"]["blocked"]
    assert forbidden.read_text() == "unchanged"
    assert seen == [("inspect", "pump-1")]


def test_wrong_invocation_never_dispatches(setup):
    dispatcher, principal, call, grant, seen = setup
    with pytest.raises(HostExecutionDenied, match="grant_binding"):
        dispatcher.invoke(principal, call, replace(grant, call_id="other"))
    assert not seen


@pytest.mark.skipif(probe_landlock_abi() < 1, reason="Landlock required")
def test_worker_cannot_supply_identity(setup):
    dispatcher, principal, call, grant, seen = setup
    call = replace(call, args={**call.args, "spoof": True})
    assert dispatcher.invoke(principal, call, grant).value == "denied"
    assert not seen


@pytest.mark.skipif(probe_landlock_abi() < 1, reason="Landlock required")
async def test_async_dispatch(setup):
    dispatcher, principal, call, grant, seen = setup
    dispatcher = ObjectBrokerDispatcher(
        {
            "pump_tool": replace(
                dispatcher.tools["pump_tool"], entrypoint="worker:async_run"
            )
        },
        mediators=dispatcher.mediators,
        runtime_roots=dispatcher.runtime_roots,
    )
    assert (await dispatcher.ainvoke(principal, call, grant)).value == "inspected"
    assert seen == [("inspect", "pump-1")]
    assert dispatcher.audit_records()[0].principal_id == "alice"


def test_missing_confinement_never_falls_back(setup, monkeypatch):
    dispatcher, principal, call, grant, seen = setup
    monkeypatch.setattr(
        "langgraph.prebuilt.security.landlock.probe_landlock_abi", lambda: 0
    )
    with pytest.raises(RuntimeError, match="Landlock"):
        dispatcher.invoke(principal, call, grant)
    assert not seen


@pytest.mark.skipif(probe_landlock_abi() < 1, reason="Landlock required")
def test_changed_artifact_never_executes(setup):
    dispatcher, principal, call, grant, seen = setup
    dispatcher.tools["pump_tool"].artifact_path.write_text(
        "raise RuntimeError('tampered')"
    )
    with pytest.raises(HostExecutionDenied, match="artifact_changed"):
        dispatcher.invoke(principal, call, grant)
    assert not seen


@pytest.mark.skipif(probe_landlock_abi() < 1, reason="Landlock required")
def test_no_grant_means_no_broker_authority(setup):
    dispatcher, principal, call, grant, seen = setup
    assert (
        dispatcher.invoke(principal, call, replace(grant, lines=())).value == "denied"
    )
    assert not seen


@pytest.mark.skipif(probe_landlock_abi() < 5, reason="Landlock ABI 5 required")
@pytest.mark.parametrize("requirement", [Requirement.NEED, Requirement.WANT])
@pytest.mark.parametrize(
    "unsupported", ["strategy", "capability", "protected_path", "missing"]
)
def test_lowering_need_and_want(setup, requirement, unsupported):
    dispatcher, principal, call, grant, seen = setup
    mediator = dispatcher.mediators[0]
    line = replace(grant.lines[0], requirement=requirement)
    if unsupported == "strategy":
        line = replace(line, lowering="unknown.strategy")
    elif unsupported == "capability":
        mediator = replace(
            mediator,
            assess=lambda line, host: ResourceSupport(
                SupportLevel.EXACT,
                "requires unavailable device driver",
                "device-v1",
                required_capabilities=frozenset({"device:unavailable"}),
            ),
        )
    elif unsupported == "protected_path":
        mediator = replace(
            mediator,
            assess=lambda line, host: ResourceSupport(
                SupportLevel.EXACT,
                "resource data overlaps runtime",
                "device-v1",
                protected_paths=(str(Path(sys.executable).resolve()),),
            ),
        )
    dispatcher = ObjectBrokerDispatcher(
        dispatcher.tools,
        runtime_roots=dispatcher.runtime_roots,
        mediators=() if unsupported == "missing" else (mediator,),
    )
    grant = replace(grant, lines=(line,))
    if requirement is Requirement.NEED:
        with pytest.raises(HostExecutionDenied, match="required_authority_removed"):
            dispatcher.invoke(principal, call, grant)
    else:
        result = dispatcher.invoke(principal, call, grant)
        assert result.value == "denied"
        assert result.receipt.removed_wants == (line.line_id,)
        record = dispatcher.lowering_records()[0]
        assert line.line_id in {rule.rule_id for rule in record.candidate.rules}
        assert line.line_id not in {rule.rule_id for rule in record.grant.rules}
        assert record.plan.removed_wants == (line.line_id,)
        assert all(item.rule_id != line.line_id for item in record.obligations)
    assert not seen


@pytest.mark.skipif(probe_landlock_abi() < 5, reason="Landlock ABI 5 required")
def test_mediator_ownership_conflict(setup):
    dispatcher, principal, call, grant, seen = setup
    first = dispatcher.mediators[0]
    dispatcher = ObjectBrokerDispatcher(
        dispatcher.tools,
        runtime_roots=dispatcher.runtime_roots,
        mediators=(first, replace(first, adapter_id="second")),
    )
    with pytest.raises(HostExecutionDenied, match="adapter_ownership_conflict"):
        dispatcher.invoke(principal, call, grant)
    assert not seen


@pytest.mark.skipif(probe_landlock_abi() < 5, reason="Landlock ABI 5 required")
def test_activation_failure_cleans_up_before_tool_import(setup):
    dispatcher, principal, call, grant, seen = setup
    lifecycle = []

    def activate(lines, context):
        lifecycle.append(("activate", context))
        raise RuntimeError("resource unavailable")

    def release(context):
        lifecycle.append(("release", context))

    dispatcher = ObjectBrokerDispatcher(
        dispatcher.tools,
        runtime_roots=dispatcher.runtime_roots,
        mediators=(
            replace(dispatcher.mediators[0], activate=activate, release=release),
        ),
    )
    with pytest.raises(HostExecutionDenied, match="activation_failed"):
        dispatcher.invoke(principal, call, grant)
    assert not seen
    assert [kind for kind, _ in lifecycle] == ["activate", "release"]
    assert lifecycle[0][1] == lifecycle[1][1]


@pytest.mark.skipif(probe_landlock_abi() < 5, reason="Landlock ABI 5 required")
def test_preflight_runs_before_activation_and_cleans_up_on_failure(setup):
    dispatcher, principal, call, grant, seen = setup
    lifecycle = []

    def preflight(lines, context):
        lifecycle.append(("preflight", lines, context))

    def activate(lines, context):
        lifecycle.append(("activate", lines, context))
        raise RuntimeError("resource unavailable")

    def release(context):
        lifecycle.append(("release", (), context))

    dispatcher = ObjectBrokerDispatcher(
        dispatcher.tools,
        runtime_roots=dispatcher.runtime_roots,
        mediators=(
            replace(
                dispatcher.mediators[0],
                preflight=preflight,
                activate=activate,
                release=release,
            ),
        ),
    )
    with pytest.raises(HostExecutionDenied, match="activation_failed"):
        dispatcher.invoke(principal, call, grant)
    assert not seen
    assert [item[0] for item in lifecycle] == ["preflight", "activate", "release"]
    assert lifecycle[0][1] == grant.lines
    assert lifecycle[0][2] == lifecycle[1][2] == lifecycle[2][2]


@pytest.mark.skipif(probe_landlock_abi() < 5, reason="Landlock ABI 5 required")
def test_resource_support_rechecked_on_each_request(setup):
    dispatcher, principal, call, grant, seen = setup
    original = dispatcher.mediators[0]
    activated = False

    def activate(lines, context):
        nonlocal activated
        activated = True
        assert lines == grant.lines
        assert context.principal_id == principal.user_id
        assert context.worker.broker_epoch != "no-broker"

    def assess(line, host):
        if activated:
            return ResourceSupport(SupportLevel.UNSUPPORTED, "resource lease lost")
        return original.assess(line, host)

    dispatcher = ObjectBrokerDispatcher(
        dispatcher.tools,
        runtime_roots=dispatcher.runtime_roots,
        mediators=(replace(original, assess=assess, activate=activate),),
    )
    assert dispatcher.invoke(principal, call, grant).value == "denied"
    assert not seen
    assert dispatcher.audit_records()[0].reason == "adapter_failure"


@pytest.mark.skipif(probe_landlock_abi() < 5, reason="Landlock ABI 5 required")
def test_release_failure_is_indeterminate_after_effect(setup):
    dispatcher, principal, call, grant, seen = setup

    def release(context):
        raise RuntimeError("lease revocation failed")

    dispatcher = ObjectBrokerDispatcher(
        dispatcher.tools,
        runtime_roots=dispatcher.runtime_roots,
        mediators=(replace(dispatcher.mediators[0], release=release),),
    )
    with pytest.raises(HostExecutionError, match="resource_release_failed") as caught:
        dispatcher.invoke(principal, call, grant)
    assert seen == [("inspect", "pump-1")]
    assert caught.value.outcome is ExecutionOutcome.INDETERMINATE
    assert not caught.value.termination_confirmed


def test_bare_handler_is_not_a_lowering_contract(setup):
    dispatcher, *_ = setup
    with pytest.raises(ValueError, match="no lowering contract"):
        ObjectBrokerDispatcher(
            dispatcher.tools,
            {("pump", "inspect"): lambda line, payload: None},
            runtime_roots=dispatcher.runtime_roots,
        )
