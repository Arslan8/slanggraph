"""Closed scalar operations for the interpreter; never dispatch object protocols.

These are language operations, not tool-author callables or resource terminals.
The type rule and runtime guard use exact native scalar types, excluding subclasses.
"""

from __future__ import annotations

import operator

from langgraph.prebuilt.security.errors import SecurityConfigurationError
from langgraph.prebuilt.security.execution import HostExecutionDenied

PURE_BUILTINS = frozenset({"int", "float", "str", "bool", "len"})
_NUMERIC = frozenset({"int", "float"})
_SCALARS = frozenset({"str", "int", "float", "bool", "NoneType"})
_OPS = {
    "add": operator.add, "sub": operator.sub, "mul": operator.mul,
    "div": operator.truediv, "floordiv": operator.floordiv, "mod": operator.mod,
    "lt": operator.lt, "le": operator.le, "gt": operator.gt, "ge": operator.ge,
    "neg": operator.neg, "pos": operator.pos, "not": operator.not_,
    "getitem": operator.getitem,
    "range_more": lambda i, end, step: i < end if step > 0 else i > end,
    "range_step": lambda step: step if step != 0 else (_ for _ in ()).throw(ValueError("zero step")),
    "int": int, "float": float, "str": str, "bool": bool, "len": len,
}


def pure_type(op: str, arguments: list[frozenset[str]]) -> frozenset[str]:
    """Validate all possible operand types before admitting an operation."""
    if type(op) is not str or op not in _OPS:
        raise SecurityConfigurationError("language_proof:unknown_pure_operation")
    if op == "range_more":
        if len(arguments) == 3 and all(a == {"int"} for a in arguments):
            return frozenset({"bool"})
        raise SecurityConfigurationError("language_proof:pure_operand_type")
    if op == "range_step":
        if arguments == [frozenset({"int"})]:
            return frozenset({"int"})
        raise SecurityConfigurationError("language_proof:pure_operand_type")
    unary = op in PURE_BUILTINS or op in {"neg", "pos", "not"}
    if len(arguments) != (1 if unary else 2):
        raise SecurityConfigurationError("language_proof:pure_arity")
    left = arguments[0]
    if op in {"str", "bool"} and left <= _SCALARS:
        return frozenset({op})
    if op in {"int", "float"} and left <= {"str", "int", "float", "bool"}:
        return frozenset({op})
    if op == "len" and left == {"str"}:
        return frozenset({"int"})
    if op == "not" and left == {"bool"}:
        return frozenset({"bool"})
    if op in {"neg", "pos"} and left <= _NUMERIC:
        return left
    if len(arguments) == 2:
        right = arguments[1]
        if op == "getitem" and left == {"str"} and right == {"int"}:
            return frozenset({"str"})
        if op == "add" and left == right == {"str"}:
            return frozenset({"str"})
        if op in {"lt", "le", "gt", "ge"} and (
            left == right == {"str"} or (left <= _NUMERIC and right <= _NUMERIC)
        ):
            return frozenset({"bool"})
        if op in {"add", "sub", "mul", "div", "floordiv", "mod"} and left <= _NUMERIC and right <= _NUMERIC:
            if op == "div":
                return frozenset({"float"})
            return frozenset(
                "float" if "float" in (a, b) else "int"
                for a in left for b in right
            )
    raise SecurityConfigurationError("language_proof:pure_operand_type")


def pure_eval(op: str, arguments: list[object]) -> object:
    kinds = []
    for value in arguments:
        # Do not access __name__ on an attacker-controlled metaclass.
        if not any(type(value) is k for k in (str, int, float, bool, type(None))):
            raise HostExecutionDenied("language_sandbox:non_data_operand")
        kinds.append(frozenset({type(value).__name__}))
    try:
        pure_type(op, kinds)
        return _OPS[op](*arguments)
    except (SecurityConfigurationError, ValueError, TypeError, ArithmeticError, IndexError):
        raise HostExecutionDenied("language_sandbox:invalid_pure_operation") from None
