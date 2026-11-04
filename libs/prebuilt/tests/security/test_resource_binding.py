"""Both binding forms retain typed checks, custom validation, and parent state."""

import hashlib
import sys
from abc import ABC, abstractmethod
from dataclasses import replace
from pathlib import Path
from uuid import uuid4

import pytest

from langgraph.prebuilt.security import (
    EnforcementKind,
    LinuxToolSpec,
    ObjectBrokerDispatcher,
    ObjectGrantLine,
    Principal,
    Requirement,
    ResourceInvocation,
    ResourceSupport,
    SupportLevel,
    object_broker,
    parse_security_manifest,
)
from langgraph.prebuilt.security.capabilities import probe_landlock_abi
from langgraph.prebuilt.security.manifest_consistency import (
    check_manifest_consistency,
)
from langgraph.prebuilt.security.mediators.contracts import (
    ResourceContract,
    client_binding,
    current_invocation,
)
from langgraph.prebuilt.security.object_policy import ObjectGrant
from langgraph.prebuilt.security.types import Tool, ToolCall, ToolDac
from tests.security.test_enforcement import _context, _host


class CounterAPI(ABC):
    __slots__ = ()

    @abstractmethod
    def increment(self, counter_id: str, amount: int) -> int:
        raise NotImplementedError


OPTIONS = dict(
    class_name="counter",
    object_kind="counter",
    resource_parameter="counter_id",
    lowering="counter.local.v1",
)
CONTRACT = ResourceContract(CounterAPI, **OPTIONS)
LINE = ObjectGrantLine(
    "increment",
    "counter",
    "increment",
    "jobs",
    {},
    Requirement.NEED,
    EnforcementKind.BROKER,
    CONTRACT.lowering,
)
CONTEXT = ResourceInvocation("alice", "session", "tool", "call", "grant", _context())


class Backend(CounterAPI):
    def __init__(self):
        self.value = 0
        self.events = []

    def increment(self, counter_id: str, amount: int) -> int:
        self.events.append(
            ("implementation", counter_id, current_invocation().principal_id)
        )
        self.value += amount
        return self.value


class Assessment:
    def assess(self, line, host):
        return assess(line, host)


class Validator(Assessment):
    def __init__(self, backend):
        self.backend = backend

    def validate(self, operation, arguments, context):
        assert current_invocation() is context
        assert operation == "increment"
        self.backend.events.append(
            ("validation", arguments["counter_id"], context.principal_id)
        )
        if not 1 <= arguments["amount"] <= 3:
            raise PermissionError("amount outside range")


def assess(line, host):
    if line.selector != "jobs":
        return ResourceSupport(SupportLevel.UNSUPPORTED, "unknown counter")
    return ResourceSupport(SupportLevel.EXACT, "test counter", witness=__file__)


def bind(backend, *, constructor, **kwargs):
    if "mediator" not in kwargs:
        kwargs["assess"] = assess
    if constructor:
        return ResourceContract(CounterAPI, **OPTIONS, implementation=backend, **kwargs)
    return CONTRACT.bind(implementation=backend, **kwargs)


@pytest.mark.parametrize("constructor", [False, True])
def test_binding_forms_validate_before_effects(constructor):
    backend = Backend()
    resource = bind(backend, constructor=constructor, mediator=Validator(backend))
    assert resource.class_declaration() == CONTRACT.class_declaration()
    assert resource.adapter.assess(LINE, _host()).support is SupportLevel.EXACT
    assert resource.adapter.invoke(LINE, {"amount": 2}, CONTEXT) == 2
    assert backend.events == [
        ("validation", "jobs", "alice"),
        ("implementation", "jobs", "alice"),
    ]
    with pytest.raises(PermissionError, match="outside range"):
        resource.adapter.invoke(LINE, {"amount": -1}, CONTEXT)
    assert backend.value == 2
    assert backend.events[-1][0] == "validation"
    with pytest.raises(PermissionError, match="no active"):
        current_invocation()
    with pytest.raises(ValueError, match="no bound"):
        _ = CONTRACT.adapter


@pytest.mark.parametrize("constructor", [False, True])
def test_optional_mediator_preserves_typed_checks(constructor):
    backend = Backend()
    resource = bind(backend, constructor=constructor)
    assert resource.adapter.invoke(LINE, {"amount": -1}, CONTEXT) == -1
    for payload in (
        {"amount": True},
        {"amount": "2"},
        {},
        {"amount": 1, "extra": 0},
        {"amount": 1, "counter_id": "private"},
    ):
        with pytest.raises(ValueError):
            resource.adapter.invoke(LINE, payload, CONTEXT)
    assert backend.value == -1
    assert len(backend.events) == 1


@pytest.mark.parametrize(
    "change",
    [
        {"class_name": "other"},
        {"operation": "delete"},
        {"lowering": "other.v1"},
        {"attributes": {"extra": "value"}},
    ],
)
def test_binding_cannot_assess_or_execute_another_contract(change):
    backend = Backend()
    assessments = []

    def permissive(line, host):
        assessments.append(line)
        return ResourceSupport(
            SupportLevel.EXACT, "overbroad callback", witness=__file__
        )

    resource = CONTRACT.bind(implementation=backend, assess=permissive)
    line = replace(LINE, **change)
    assert resource.adapter.assess(line, _host()).support is SupportLevel.UNSUPPORTED
    assert assessments == []
    with pytest.raises(PermissionError, match="does not match"):
        resource.adapter.invoke(line, {"amount": 1}, CONTEXT)
    assert backend.events == []


def test_validator_cannot_rewrite_arguments():
    class Rewriter(Assessment):
        def validate(self, operation, arguments, context):
            arguments["counter_id"] = "private"

    backend = Backend()
    resource = CONTRACT.bind(implementation=backend, mediator=Rewriter())
    with pytest.raises(TypeError):
        resource.adapter.invoke(LINE, {"amount": 2}, CONTEXT)
    assert backend.events == []


@pytest.mark.parametrize("returned", [False, True, {"amount": 1}])
def test_validator_must_raise_or_return_none(returned):
    class WrongValidator(Assessment):
        def validate(self, operation, arguments, context):
            return returned

    backend = Backend()
    resource = CONTRACT.bind(implementation=backend, mediator=WrongValidator())
    with pytest.raises(TypeError, match="return None"):
        resource.adapter.invoke(LINE, {"amount": 2}, CONTEXT)
    assert backend.events == []


@pytest.mark.parametrize("constructor", [False, True])
def test_signature_mismatch_fails_in_both_forms(constructor):
    class WrongBackend(Backend):
        def increment(self, counter_id: str, amount: str) -> int:
            return 0

    with pytest.raises(TypeError, match="signature"):
        bind(WrongBackend(), constructor=constructor)


def test_invalid_binding_options():
    with pytest.raises(TypeError, match="explicit assess"):
        ResourceContract(CounterAPI, **OPTIONS, implementation=Backend())
    with pytest.raises(ValueError, match="require an implementation"):
        ResourceContract(CounterAPI, **OPTIONS, assess=assess)
    with pytest.raises(TypeError, match="validate method"):
        CONTRACT.bind(implementation=Backend(), mediator=object())

    class AsyncValidator:
        async def validate(self, operation, arguments, context):
            pass

    with pytest.raises(TypeError, match="synchronous"):
        CONTRACT.bind(implementation=Backend(), mediator=AsyncValidator())


def test_bound_client_uses_broker_and_does_not_retain_backend(monkeypatch):
    backend = Backend()
    resource = CONTRACT.bind(implementation=backend, mediator=Validator(backend))
    client = resource.client(export=f"test_binding.client_{uuid4().hex}")
    binding = client_binding(client)
    assert binding is not None
    with pytest.raises(ValueError, match="no bound"):
        _ = binding.contract.adapter
    calls = []

    def transport(*args):
        calls.append(args)
        return 7

    monkeypatch.setattr(object_broker, "object_request", transport)
    assert client.increment("jobs", 2) == 7
    assert calls == [("counter", "increment", "jobs", {"amount": 2})]
    assert backend.events == []
    assert binding.models("counter")[0].operation == "increment"


def test_independent_bindings_and_lifecycle():
    first, second = Backend(), Backend()
    events = []
    resource = CONTRACT.bind(
        implementation=first,
        assess=assess,
        activate=lambda lines, ctx: events.append(("activate", ctx)),
        release=lambda ctx: events.append(("release", ctx)),
    )
    other = resource.bind(implementation=second, assess=assess)
    resource.adapter.activate((LINE,), CONTEXT)
    assert resource.adapter.invoke(LINE, {"amount": 2}, CONTEXT) == 2
    assert other.adapter.invoke(LINE, {"amount": 1}, CONTEXT) == 1
    resource.adapter.release(CONTEXT)
    assert events == [("activate", CONTEXT), ("release", CONTEXT)]
    assert (first.value, second.value) == (2, 1)


def test_result_validation_without_custom_mediator():
    class WrongResult(Backend):
        def increment(self, counter_id: str, amount: int) -> int:
            return "not an integer"

    resource = CONTRACT.bind(implementation=WrongResult(), assess=assess)
    with pytest.raises(TypeError, match="invalid typed result"):
        resource.adapter.invoke(LINE, {"amount": 2}, CONTEXT)


def test_validation_never_observes_malformed_payloads():
    backend = Backend()
    resource = CONTRACT.bind(implementation=backend, mediator=Validator(backend))
    with pytest.raises(ValueError):
        resource.adapter.invoke(LINE, {"amount": "2"}, CONTEXT)
    assert backend.events == []


@pytest.mark.parametrize("foreign", ["mapping", "key"])
def test_resource_payload_refuses_foreign_protocols_before_backend(foreign):
    calls = []

    class ForeignMapping(dict):
        def __contains__(self, key):
            calls.append("contains")
            raise AssertionError("payload membership protocol executed")

    class ForeignKey:
        def __hash__(self):
            return hash("amount")

        def __eq__(self, other):
            calls.append("equality")
            raise AssertionError("payload key protocol executed")

    payload = ForeignMapping(amount=2) if foreign == "mapping" else {ForeignKey(): 2}
    backend = Backend()
    resource = CONTRACT.bind(implementation=backend, mediator=Validator(backend))
    with pytest.raises(ValueError, match="payload"):
        resource.adapter.invoke(LINE, payload, CONTEXT)
    assert calls == []
    assert backend.events == []


def test_bound_client_preserves_static_inference():

    resource = CONTRACT.bind(implementation=Backend(), assess=assess)
    export = f"test_binding.client_{uuid4().hex}"
    resource.client(export=export)
    source = f"from test_binding import {export.split('.')[-1]} as counter\ndef increment(amount: int):\n    return counter.increment('jobs', amount)"
    manifest = parse_security_manifest(
        CONTRACT.class_declaration()
        + "\ntool increment {\ncounter increment jobs need\n}"
    )
    assert check_manifest_consistency(source, manifest, tool_name="increment")[
        "consistent"
    ]


def test_binding_without_custom_mediator_preserves_broker_grants(tmp_path):

    if probe_landlock_abi() < 5:
        pytest.skip("Landlock ABI 5 required")
    source = tmp_path / "worker.py"
    source.write_text("""from langgraph.prebuilt.security import object_request

def increment(selector: str):
    try:
        return object_request("counter", "increment", selector, {"amount": 2})
    except PermissionError:
        return "denied"
""")
    backend = Backend()
    resource = CONTRACT.bind(implementation=backend, assess=assess)
    dispatcher = ObjectBrokerDispatcher(
        {
            "increment": LinuxToolSpec(
                "worker:increment",
                source,
                hashlib.sha256(source.read_bytes()).hexdigest(),
            )
        },
        runtime_roots=tuple(
            Path(p).resolve() for p in sys.path if p and Path(p).is_dir()
        ),
        mediators=(resource.adapter,),
    )
    principal = Principal("alice", frozenset(), frozenset(), "session")
    call = ToolCall(
        Tool("increment", ToolDac("owner", {"*": "x"}), frozenset(), ()),
        {"selector": "jobs"},
        {},
        "call",
        0,
    )
    grant = ObjectGrant("alice", "increment", "call", "policy", (LINE,))
    assert dispatcher.invoke(principal, call, grant).value == 2
    forbidden = replace(call, args={"selector": "private"})
    assert dispatcher.invoke(principal, forbidden, grant).value == "denied"
    assert backend.value == 2
    assert len(backend.events) == 1


@pytest.mark.parametrize("constructor", [False, True])
def test_mediator_owns_assessment(constructor):
    backend = Backend()
    seen = []

    class RejectingMediator(Validator):
        def assess(self, line, host):
            seen.append((line.selector, host))
            return ResourceSupport(SupportLevel.UNSUPPORTED, "resource unavailable")

    resource = bind(
        backend, constructor=constructor, mediator=RejectingMediator(backend)
    )
    host = _host()
    assert resource.adapter.assess(LINE, host).support is SupportLevel.UNSUPPORTED
    assert seen == [("jobs", host)]
    assert backend.events == []


def test_separate_assessment_cannot_override_mediator():
    backend = Backend()
    with pytest.raises(ValueError, match="not a separate assess"):
        CONTRACT.bind(
            implementation=backend, mediator=Validator(backend), assess=assess
        )


def test_mediator_must_supply_synchronous_assessment():
    class MissingAssessment:
        def validate(self, operation, arguments, context):
            pass

    with pytest.raises(TypeError, match="mediator.assess"):
        CONTRACT.bind(implementation=Backend(), mediator=MissingAssessment())

    class AsyncAssessment(MissingAssessment):
        async def assess(self, line, host):
            return assess(line, host)

    with pytest.raises(TypeError, match="assessment must be synchronous"):
        CONTRACT.bind(implementation=Backend(), mediator=AsyncAssessment())
