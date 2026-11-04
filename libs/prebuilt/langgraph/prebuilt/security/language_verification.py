"""Structural type/effect derivations for the admitted execution language.

This proves a property of an immutable program under explicit terminal contracts.
It is a component of composition, not a certificate for terminal implementations,
the Python interpreter, graph placement, or host isolation.
"""

from __future__ import annotations

import hashlib
import json
from collections import OrderedDict
from collections.abc import Mapping
from dataclasses import dataclass
from inspect import Parameter, Signature
from types import MappingProxyType
from typing import Any

try:
    from gc import get_referents
except ImportError:  # Unsupported interpreter layouts cannot establish backing shape.
    get_referents = None

from langgraph.prebuilt.security._language_pure import pure_type
from langgraph.prebuilt.security.errors import SecurityConfigurationError
from langgraph.prebuilt.security.types import _decision_arguments

_DATA = frozenset({"str", "int", "float", "bool", "NoneType", "dict"})
_SCALARS = _DATA - {"dict"}
_SCALAR_TYPES = (str, int, float, bool, type(None))


@dataclass(frozen=True, slots=True)
class TerminalContract:
    """Data-only call contract; authority/implementation proofs are separate."""

    parameters: tuple[tuple[str, str], ...]
    result: frozenset[str]

    def __post_init__(self):
        if (
            type(self.parameters) is not tuple
            or any(
                type(parameter) is not tuple or len(parameter) != 2
                for parameter in self.parameters
            )
            or type(self.result) is not frozenset
        ):
            raise ValueError("terminal contracts must be immutable")
        if any(
            type(name) is not str
            or not name.isidentifier()
            or type(kind) is not str
            or kind not in _SCALARS
            for name, kind in self.parameters
        ):
            raise ValueError("invalid language terminal parameters")
        names = [name for name, _ in self.parameters]
        if len(set(names)) != len(names):
            raise ValueError("duplicate language terminal parameter")
        if (
            not self.result
            or any(type(kind) is not str for kind in self.result)
            or not self.result <= _DATA
        ):
            raise ValueError("invalid language terminal result")


def _signature_snapshot(signature: Signature) -> Signature:
    """Capture native signature fields without trusting a proxy's backing type.

    Native inspect signatures store their parameters in a mapping proxy over an
    OrderedDict. Native GC referents expose that backing object without invoking
    its mapping protocols. Other interpreter layouts fail closed. Annotations are
    unused metadata and are omitted from the captured execution signature.
    """
    if type(signature) is not Signature:
        raise SecurityConfigurationError("language_proof:invalid_signature")
    try:
        proxy = signature._parameters
    except AttributeError:
        raise SecurityConfigurationError("language_proof:invalid_signature") from None
    if type(proxy) is not MappingProxyType:
        raise SecurityConfigurationError("language_proof:invalid_signature")
    if get_referents is None:
        raise SecurityConfigurationError("language_proof:invalid_signature")
    referents = get_referents(proxy)
    if len(referents) != 1 or (
        type(referents[0]) is not dict and type(referents[0]) is not OrderedDict
    ):
        raise SecurityConfigurationError("language_proof:invalid_signature")
    # OrderedDict.items can look up values by key. Native dict.items scans the
    # underlying table without hashing or comparing unvalidated keys.
    backing = referents[0]
    pairs = tuple(dict.items(backing))
    if type(backing) is OrderedDict:
        entries = {}
        for key, parameter in pairs:
            if type(key) is not str:
                raise SecurityConfigurationError("language_proof:invalid_signature")
            entries[key] = parameter
        try:
            order = tuple(OrderedDict.__iter__(backing))
        except RuntimeError:
            raise SecurityConfigurationError(
                "language_proof:invalid_signature"
            ) from None
        if len(order) != len(entries) or any(
            type(key) is not str or key not in entries for key in order
        ):
            raise SecurityConfigurationError("language_proof:invalid_signature")
        pairs = tuple((key, entries[key]) for key in order)
    parameters = []
    for key, parameter in pairs:
        if type(key) is not str or type(parameter) is not Parameter:
            raise SecurityConfigurationError("language_proof:invalid_signature")
        try:
            name, kind, default = parameter._name, parameter._kind, parameter._default
        except AttributeError:
            raise SecurityConfigurationError(
                "language_proof:invalid_signature"
            ) from None
        if type(name) is not str or name != key:
            raise SecurityConfigurationError("language_proof:invalid_signature")
        if (
            kind is not Parameter.POSITIONAL_ONLY
            and kind is not Parameter.POSITIONAL_OR_KEYWORD
            and kind is not Parameter.KEYWORD_ONLY
        ):
            raise SecurityConfigurationError("language_proof:variadic_parameters")
        if default is not Parameter.empty and type(default) is not str:
            raise SecurityConfigurationError("language_proof:non_data_default")
        try:
            parameters.append(Parameter(name, kind, default=default))
        except (TypeError, ValueError):
            raise SecurityConfigurationError(
                "language_proof:invalid_signature"
            ) from None
    try:
        return Signature(parameters)
    except (TypeError, ValueError):
        raise SecurityConfigurationError("language_proof:invalid_signature") from None


def _terminal_contract_snapshot(
    terminals: Mapping[str, TerminalContract],
) -> dict[str, TerminalContract]:
    """Revalidate exact contracts and detach mutable record fields before use."""
    try:
        copied = _decision_arguments(terminals)
        result = {}
        for name, contract in copied.items():
            if type(contract) is not TerminalContract:
                raise TypeError("invalid terminal contract")
            result[name] = TerminalContract(contract.parameters, contract.result)
    except (AttributeError, TypeError, ValueError):
        raise SecurityConfigurationError(
            "language_proof:invalid_terminal_contracts"
        ) from None
    return result


def derive_program(
    body: tuple,
    signature: Signature,
    terminals: Mapping[str, TerminalContract],
) -> dict[str, Any]:
    """Check every instruction, including unreachable branches, by induction.

    Each recursive premise is a proper subterm of the finite immutable program.
    Local environments contain only data types, calls cannot produce capabilities,
    and the effect set is the union of all statically named terminal calls.
    No source spelling, supplied passing flag, or previously saved report is proof.
    """
    budget = 10_000
    trace = []
    effects: set[str] = set()

    def reject(reason):
        raise SecurityConfigurationError(f"language_proof:{reason}")

    signature = _signature_snapshot(signature)
    terminals = _terminal_contract_snapshot(terminals)

    def node(value, arity=None):
        nonlocal budget
        budget -= 1
        if budget < 0:
            reject("budget_exhausted")
        if type(value) is not tuple or not value or type(value[0]) is not str:
            reject("invalid_instruction")
        if arity is not None and len(value) != arity:
            reject("invalid_arity")

    def sequence(value):
        if type(value) is not tuple:
            reject("mutable_or_invalid_sequence")
        return value

    def expression(value, environment):
        node(value)
        rule = value[0]
        if rule == "constant":
            node(value, 2)
            if not any(type(value[1]) is kind for kind in _SCALAR_TYPES):
                reject("non_data_constant")
            kind = type(value[1]).__name__
            if kind not in _SCALARS:
                reject("non_data_constant")
            result = frozenset({kind})
        elif rule == "local":
            node(value, 2)
            if type(value[1]) is not str or value[1] not in environment:
                reject("unbound_local")
            result = environment[value[1]]
        elif rule == "join":
            node(value, 2)
            for part in sequence(value[1]):
                if expression(part, environment) != frozenset({"str"}):
                    reject("format_requires_strings")
            result = frozenset({"str"})
        elif rule == "compare":
            node(value, 4)
            if type(value[1]) is not bool:
                reject("invalid_comparison")
            if any(
                expression(part, environment) != frozenset({"str"})
                for part in value[2:]
            ):
                reject("comparison_requires_strings")
            result = frozenset({"bool"})
        elif rule == "pure":
            node(value, 3)
            result = pure_type(value[1], [expression(part, environment) for part in sequence(value[2])])
        elif rule == "call":
            node(value, 4)
            target = value[1]
            if type(target) is not str or target not in terminals:
                reject("unregistered_terminal")
            contract = terminals[target]
            if type(contract) is not TerminalContract:
                reject("invalid_terminal_contract")
            arguments = [expression(part, environment) for part in sequence(value[2])]
            if len(arguments) > len(contract.parameters):
                reject("terminal_arity")
            bound = {
                name: kind for (name, _), kind in zip(contract.parameters, arguments)
            }
            for keyword in sequence(value[3]):
                if (
                    type(keyword) is not tuple
                    or len(keyword) != 2
                    or type(keyword[0]) is not str
                ):
                    reject("invalid_keyword")
                name, part = keyword
                if name in bound or name not in dict(contract.parameters):
                    reject("terminal_keyword")
                bound[name] = expression(part, environment)
            if set(bound) != {name for name, _ in contract.parameters}:
                reject("terminal_arity")
            if any(
                bound[name] != frozenset({kind}) for name, kind in contract.parameters
            ):
                reject("terminal_argument_type")
            effects.add(target)
            result = contract.result
        else:
            reject("unsupported_expression")
        trace.append({"rule": rule, "types": sorted(result)})
        return result

    invariants = []

    def statements(statements_, initial):
        environment = dict(initial)
        returned = False
        results: set[str] = set()
        for value in sequence(statements_):
            node(value)
            rule = value[0]
            if rule in {"return", "expression"}:
                node(value, 2)
                kind = expression(value[1], environment)
                if rule == "return":
                    returned = True
                    results.update(kind)
            elif rule == "assign":
                node(value, 3)
                kind = expression(value[2], environment)
                for name in sequence(value[1]):
                    if type(name) is not str or not name.isidentifier():
                        reject("invalid_local")
                    for invariant in invariants:
                        if name in invariant and not kind <= invariant[name]:
                            reject("loop_local_type_changed")
                    environment[name] = kind
            elif rule == "while":
                node(value, 4)
                if expression(value[1], environment) != frozenset({"bool"}):
                    reject("branch_requires_bool")
                # Every assignment to a pre-existing local preserves its loop-head
                # type. Check each assignment, not just the final environment:
                # returns and future continue paths must not hide a changed type.
                loop_environment = dict(environment)
                before_invariants = list(invariants)
                invariants.append(loop_environment)
                try:
                    _, _, body_results = statements(value[2], loop_environment)
                finally:
                    invariants[:] = before_invariants
                # The loop may execute zero times; body-created locals are not
                # definitely bound afterward. The else branch always runs on a
                # normally terminating loop (this IR has no break).
                environment, else_return, else_results = statements(value[3], environment)
                results.update(body_results | else_results)
                returned = returned or else_return
            elif rule == "if":
                node(value, 4)
                if expression(value[1], environment) != frozenset({"bool"}):
                    reject("branch_requires_bool")
                left, left_return, left_result = statements(value[2], environment)
                right, right_return, right_result = statements(value[3], environment)
                results.update(left_result | right_result)
                if left_return and not right_return:
                    environment = right
                elif right_return and not left_return:
                    environment = left
                else:
                    environment = {
                        name: left[name] | right[name]
                        for name in left.keys() & right.keys()
                    }
                returned = returned or (left_return and right_return)
            else:
                reject("unsupported_statement")
            trace.append(
                {
                    "rule": rule,
                    "locals": {
                        name: sorted(kind) for name, kind in sorted(environment.items())
                    },
                }
            )
        return environment, returned, results

    environment = {}
    for name, parameter in signature.parameters.items():
        if parameter.kind not in {
            Parameter.POSITIONAL_ONLY,
            Parameter.POSITIONAL_OR_KEYWORD,
            Parameter.KEYWORD_ONLY,
        }:
            reject("variadic_parameters")
        if (
            parameter.default is not Parameter.empty
            and type(parameter.default) is not str
        ):
            reject("non_data_default")
        environment[name] = frozenset({"str"})
    _, returns, results = statements(body, environment)
    if not returns:
        results.add("NoneType")
    payload = {
        "body": body,
        "parameters": [
            (
                name,
                parameter.kind.name,
                None if parameter.default is Parameter.empty else parameter.default,
                parameter.default is Parameter.empty,
            )
            for name, parameter in signature.parameters.items()
        ],
        "terminals": {
            name: {"parameters": contract.parameters, "result": sorted(contract.result)}
            for name, contract in sorted(terminals.items())
        },
    }
    return {
        "schema_version": 1,
        "property": "Every admitted instruction preserves inert data and every candidate effect is a statically admitted terminal call.",
        "proved": True,
        "program_sha256": hashlib.sha256(
            json.dumps(payload, sort_keys=True).encode()
        ).hexdigest(),
        "effects": sorted(effects),
        "result_types": sorted(results),
        "derivation": trace,
        "dependencies": [
            "execution-language implementation correspondence",
            "terminal identity and authorization contracts",
            "host isolation where required",
        ],
        "system_complete": False,
    }
