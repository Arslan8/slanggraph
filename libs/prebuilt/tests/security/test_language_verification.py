"""Proof obligations for every construct in the admitted data language."""

import ast
from collections import OrderedDict
from dataclasses import replace
from inspect import Parameter, Signature
from types import MappingProxyType

import pytest

from langgraph.prebuilt.security import _language_sandbox as sandbox
from langgraph.prebuilt.security._language_sandbox import LanguageProgram, inert_copy
from langgraph.prebuilt.security.errors import SecurityConfigurationError
from langgraph.prebuilt.security.execution import HostExecutionDenied
from langgraph.prebuilt.security.language_verification import (
    TerminalContract,
    _signature_snapshot,
    derive_program,
)

SIGNATURE = Signature([Parameter("path", Parameter.POSITIONAL_OR_KEYWORD)])
CONTRACT = TerminalContract((("path", "str"),), frozenset({"str"}))
CALL = ("call", "read", (("local", "path"),), ())


class ForeignMetadata:
    calls = 0

    def values(self):
        type(self).calls += 1
        raise AssertionError("foreign metadata values ran")

    def __len__(self):
        type(self).calls += 1
        raise AssertionError("foreign metadata length ran")

    def __iter__(self):
        type(self).calls += 1
        raise AssertionError("foreign metadata iteration ran")

    def __getitem__(self, key):
        type(self).calls += 1
        raise AssertionError("foreign metadata lookup ran")

    def __hash__(self):
        type(self).calls += 1
        raise AssertionError("foreign metadata hash ran")


@pytest.mark.parametrize("wrapped", [False, True])
def test_exact_signature_refuses_foreign_parameter_mapping_before_protocols(wrapped):
    signature = Signature()
    foreign = ForeignMetadata()
    signature._parameters = MappingProxyType(foreign) if wrapped else foreign
    ForeignMetadata.calls = 0
    with pytest.raises(SecurityConfigurationError, match="invalid_signature"):
        derive_program((), signature, {})
    assert ForeignMetadata.calls == 0


@pytest.mark.parametrize("field", ["_name", "_kind", "_default"])
def test_exact_parameter_refuses_foreign_fields_before_protocols(field):
    parameter = Parameter("path", Parameter.POSITIONAL_OR_KEYWORD)
    signature = Signature([parameter])
    setattr(parameter, field, ForeignMetadata())
    ForeignMetadata.calls = 0
    with pytest.raises(SecurityConfigurationError):
        derive_program((), signature, {})
    assert ForeignMetadata.calls == 0


@pytest.mark.parametrize("field", ["parameters", "result"])
def test_exact_contract_refuses_forged_metadata_before_protocols(field):
    contract = TerminalContract((), frozenset({"str"}))
    object.__setattr__(contract, field, ForeignMetadata())
    ForeignMetadata.calls = 0
    with pytest.raises(SecurityConfigurationError, match="invalid_terminal_contracts"):
        derive_program(
            (("return", ("call", "read", (), ())),), Signature(), {"read": contract}
        )
    assert ForeignMetadata.calls == 0


def test_signature_snapshot_preserves_native_ordered_dictionary_order():
    parameters = OrderedDict(
        (name, Parameter(name, Parameter.POSITIONAL_OR_KEYWORD))
        for name in ("first", "second")
    )
    parameters.move_to_end("first")
    signature = Signature()
    signature._parameters = MappingProxyType(parameters)
    captured = _signature_snapshot(signature)
    assert tuple(captured.parameters) == ("second", "first")
    assert captured.bind("a", "b").arguments == {"second": "a", "first": "b"}
    parameters.clear()
    assert tuple(captured.parameters) == ("second", "first")


def test_signature_snapshot_rejects_unavailable_backing_inspection(monkeypatch):
    monkeypatch.setattr(
        "langgraph.prebuilt.security.language_verification.get_referents", None
    )
    with pytest.raises(SecurityConfigurationError, match="invalid_signature"):
        _signature_snapshot(Signature())


def test_signature_snapshot_rejects_foreign_annotations_without_protocols():
    parameter = Parameter(
        "path", Parameter.POSITIONAL_OR_KEYWORD, annotation=ForeignMetadata()
    )
    signature = Signature([parameter], return_annotation=ForeignMetadata())
    ForeignMetadata.calls = 0
    with pytest.raises(SecurityConfigurationError, match="invalid_parameter_type"):
        _signature_snapshot(signature)
    assert ForeignMetadata.calls == 0
    parameter._name = "different"
    with pytest.raises(SecurityConfigurationError, match="invalid_signature"):
        _signature_snapshot(signature)


def test_signature_snapshot_never_hashes_native_backing_foreign_keys():
    class Key:
        armed = False
        calls = 0

        def __hash__(self):
            if self.armed:
                type(self).calls += 1
                raise AssertionError("signature key hash ran")
            return 0

    key = Key()
    parameters = OrderedDict(
        [(key, Parameter("path", Parameter.POSITIONAL_OR_KEYWORD))]
    )
    signature = Signature()
    signature._parameters = MappingProxyType(parameters)
    key.armed = True
    with pytest.raises(SecurityConfigurationError, match="invalid_signature"):
        _signature_snapshot(signature)
    assert Key.calls == 0


def test_execution_uses_only_metadata_captured_before_proof(monkeypatch):
    signature = Signature([Parameter("path", Parameter.POSITIONAL_OR_KEYWORD)])
    contract = TerminalContract((("path", "str"),), frozenset({"str"}))
    calls = []
    program = LanguageProgram(
        (("return", CALL),),
        signature,
        {"read": lambda path: calls.append(path) or "original"},
        {"read": contract},
    )
    original = sandbox.derive_program

    def derive_then_mutate(*args):
        report = original(*args)
        signature._parameters = ForeignMetadata()
        object.__setattr__(contract, "result", ForeignMetadata())
        object.__setattr__(program, "body", ForeignMetadata())
        object.__setattr__(program, "terminals", ForeignMetadata())
        return report

    monkeypatch.setattr(sandbox, "derive_program", derive_then_mutate)
    ForeignMetadata.calls = 0
    assert program.invoke({"path": "captured"}) == "original"
    assert calls == ["captured"]
    assert ForeignMetadata.calls == 0


def test_positive_derivation_covers_both_branches_and_effects():
    entry = ast.parse("""def tool(path, mode="read"):
    local = f"{path}"
    if mode == "read":
        return read(local)
    else:
        return "absent"
""").body[0]
    calls = []
    program = LanguageProgram.lower(
        entry,
        {"read": lambda path: calls.append(path) or "contents"},
        ("read",),
        {},
        contracts={"read": CONTRACT},
    )
    proof = program.proof()
    assert proof["proved"]
    assert proof["effects"] == ["read"]
    assert proof["result_types"] == ["str"]
    assert not proof["system_complete"]
    assert program.invoke({"path": "x"}) == "contents"
    assert program.invoke({"path": "x", "mode": "skip"}) == "absent"
    assert calls == ["x"]


@pytest.mark.parametrize(
    "body",
    [
        (("return", ("local", "unknown")),),
        (("expression", CALL), ("return", ("eval", "evil"))),
        (("assign", ("x",), ("constant", object())),),
        (("return", ("call", "unknown", (), ())),),
        (("return", ("call", "read", (("constant", 1),), ())),),
        (("return", ("call", "read", (), ())),),
        (
            (
                "return",
                ("call", "read", (("local", "path"),), (("path", ("local", "path")),)),
            ),
        ),
        (("return", ("join", (("constant", 1),))),),
        (("if", ("constant", "truthy"), (), ()),),
        (
            (
                "if",
                ("compare", True, ("local", "path"), ("constant", "x")),
                (("assign", ("x",), ("constant", "v")),),
                (),
            ),
            ("return", ("local", "x")),
        ),
        (
            (
                "if",
                ("compare", True, ("local", "path"), ("constant", "x")),
                (),
                (("exec", "evil"),),
            ),
        ),
    ],
)
def test_unknown_or_untyped_instruction_refuses_before_any_effect(body):
    calls = []
    program = LanguageProgram(
        body,
        SIGNATURE,
        {"read": lambda path: calls.append(path) or "data"},
        {"read": CONTRACT},
    )
    with pytest.raises(SecurityConfigurationError, match="language_proof"):
        program.invoke({"path": "x"})
    assert calls == []


def test_a_type_name_does_not_certify_a_data_value():
    fake_str = type("str", (), {})
    with pytest.raises(SecurityConfigurationError, match="non_data_constant"):
        derive_program((("return", ("constant", fake_str())),), SIGNATURE, {})


@pytest.mark.parametrize(
    "boundary",
    ["constant", "terminal_result", "terminals", "contracts", "derive", "lower"],
)
def test_native_type_admission_never_hashes_or_compares_candidate_metaclasses(boundary):
    calls = []

    class Meta(type):
        def __hash__(cls):
            calls.append("hash")
            raise AssertionError("candidate metaclass hash ran")

        def __eq__(cls, other):
            calls.append("equality")
            raise AssertionError("candidate metaclass equality ran")

        def __getattribute__(cls, name):
            if name == "__name__":
                calls.append("name")
                raise AssertionError("candidate metaclass attribute ran")
            return super().__getattribute__(name)

    class Foreign(metaclass=Meta):
        pass

    value = Foreign()
    if boundary == "terminal_result":
        with pytest.raises(HostExecutionDenied, match="non_data_result"):
            inert_copy(value)
        program = LanguageProgram(
            (("return", CALL),),
            SIGNATURE,
            {"read": lambda path: value},
            {"read": CONTRACT},
        )
        with pytest.raises(HostExecutionDenied, match="non_data_result"):
            program.invoke({"path": "x"})
    elif boundary in {"terminals", "contracts"}:
        with pytest.raises(SecurityConfigurationError, match="invalid_bindings"):
            LanguageProgram(
                (),
                SIGNATURE,
                value if boundary == "terminals" else {},
                value if boundary == "contracts" else {},
            )
    elif boundary == "derive":
        with pytest.raises(
            SecurityConfigurationError, match="invalid_terminal_contracts"
        ):
            derive_program((), SIGNATURE, value)
    elif boundary == "lower":
        entry = ast.parse("def tool():\n    return None").body[0]
        entry.body[0].value = ast.Constant(value=value)
        with pytest.raises(SecurityConfigurationError, match="unsupported_expression"):
            LanguageProgram.lower(entry, {}, (), {}, contracts={})
    else:
        with pytest.raises(SecurityConfigurationError, match="non_data_constant"):
            derive_program((("return", ("constant", value)),), SIGNATURE, {})
    assert calls == []


def test_mutable_program_is_not_admitted():
    with pytest.raises(SecurityConfigurationError, match="mutable_or_invalid_sequence"):
        derive_program([("return", ("constant", "data"))], SIGNATURE, {})


def test_proof_binds_program_defaults_and_terminal_contracts():
    program = LanguageProgram(
        (("return", CALL),), SIGNATURE, {"read": lambda path: path}, {"read": CONTRACT}
    )
    before = program.proof()
    other = replace(program, body=(("return", ("constant", "changed")),))
    assert before["program_sha256"] != other.proof()["program_sha256"]
    changed = replace(
        program,
        contracts={"read": TerminalContract((("path", "str"),), frozenset({"int"}))},
    )
    assert before["program_sha256"] != changed.proof()["program_sha256"]
    assert changed.proof()["result_types"] == ["int"]


def test_terminal_without_contract_cannot_execute():
    program = LanguageProgram(
        (("return", CALL),), SIGNATURE, {"read": lambda path: path}, {}
    )
    with pytest.raises(SecurityConfigurationError, match="terminal_contract_mismatch"):
        program.invoke({"path": "x"})


def test_terminal_result_contract_is_enforced_before_local_use():
    program = LanguageProgram(
        (("return", CALL),), SIGNATURE, {"read": lambda path: 7}, {"read": CONTRACT}
    )

    with pytest.raises(HostExecutionDenied, match="terminal_result_type"):
        program.invoke({"path": "x"})


def test_program_proof_does_not_execute_terminal_to_infer_its_result():
    def unknown(path):
        pytest.fail("proof attempted to execute a terminal")

    program = LanguageProgram(
        (("return", CALL),), SIGNATURE, {"read": unknown}, {"read": CONTRACT}
    )
    assert program.proof()["effects"] == ["read"]


def test_program_captures_terminal_and_contract_mappings():
    terminals = {"read": lambda path: "original"}
    contracts = {"read": CONTRACT}
    program = LanguageProgram((("return", CALL),), SIGNATURE, terminals, contracts)
    proof = program.proof()
    terminals["read"] = lambda path: "replacement"
    contracts.clear()
    assert program.proof() == proof
    assert program.invoke({"path": "x"}) == "original"


@pytest.mark.parametrize("boundary", ["program", "derivation"])
def test_native_proxy_does_not_admit_foreign_backing_protocols(boundary):
    calls = []

    class Foreign(dict):
        def items(self):
            calls.append("items")
            raise AssertionError("foreign mapping ran")

        def keys(self):
            calls.append("keys")
            raise AssertionError("foreign mapping ran")

        def __iter__(self):
            calls.append("iter")
            raise AssertionError("foreign mapping ran")

    proxy = MappingProxyType(Foreign(read=CONTRACT))
    with pytest.raises(SecurityConfigurationError):
        if boundary == "program":
            LanguageProgram((), SIGNATURE, {}, proxy)
        else:
            derive_program((), SIGNATURE, proxy)
    assert calls == []
