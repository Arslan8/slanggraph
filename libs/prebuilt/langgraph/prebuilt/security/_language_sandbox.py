"""Execute the admitted data-and-terminal language without executing Python code.

The program is immutable data. There is no eval, exec, import, attribute lookup,
user callable invocation, or library object in the language's value environment.
Framework terminals remain part of the enforcement implementation.
"""

from __future__ import annotations

import ast
from collections.abc import Callable, Mapping
from contextvars import ContextVar
from dataclasses import dataclass
from inspect import Parameter, Signature
from threading import Event
from typing import Any

from langgraph.prebuilt.security._language_pure import PURE_BUILTINS, pure_eval
from langgraph.prebuilt.security.errors import SecurityConfigurationError
from langgraph.prebuilt.security.execution import HostExecutionDenied
from langgraph.prebuilt.security.language_verification import (
    TerminalContract,
    _signature_snapshot,
    _terminal_contract_snapshot,
    derive_program,
)
from langgraph.prebuilt.security.mediators.contracts import canonical_import_target
from langgraph.prebuilt.security.types import _decision_arguments, _DecisionArguments

_language_cancel: ContextVar[Event | None] = ContextVar("language_cancel", default=None)


def inert_copy(value: Any, depth: int = 0) -> Any:
    """Accept exact data types without invoking conversion or object protocols."""
    if depth > 32:
        raise HostExecutionDenied("language_sandbox:data_depth")
    kind = type(value)
    if kind is str or kind is int or kind is bool or kind is float or value is None:
        return value
    if type(value) is dict and all(type(key) is str for key in value):
        return {key: inert_copy(child, depth + 1) for key, child in value.items()}
    raise HostExecutionDenied("language_sandbox:non_data_result")


@dataclass(frozen=True, slots=True)
class LanguageProgram:
    body: tuple
    signature: Signature
    terminals: Mapping[str, Callable[..., Any]]
    contracts: Mapping[str, TerminalContract]

    def __post_init__(self):
        try:
            terminals = _decision_arguments(self.terminals)
            contracts = _decision_arguments(self.contracts)
        except TypeError:
            raise SecurityConfigurationError("language_proof:invalid_bindings")
        object.__setattr__(self, "terminals", _DecisionArguments(terminals))
        object.__setattr__(self, "contracts", _DecisionArguments(contracts))

    @classmethod
    def lower(
        cls,
        entry,
        terminals,
        positional_defaults,
        keyword_defaults,
        *,
        contracts,
        aliases=None,
    ):
        """Lower only the admitted syntax; an unknown node always rejects."""
        if any(
            isinstance(n, ast.Name) and n.id.startswith("argus_internal_loop_")
            for n in ast.walk(entry)
        ):
            raise SecurityConfigurationError("language_sandbox:reserved_local")
        parameters = []
        positional = [*entry.args.posonlyargs, *entry.args.args]
        first_default = len(positional) - len(positional_defaults)
        for index, arg in enumerate(positional):
            parameters.append(
                Parameter(
                    arg.arg,
                    Parameter.POSITIONAL_ONLY
                    if index < len(entry.args.posonlyargs)
                    else Parameter.POSITIONAL_OR_KEYWORD,
                    default=positional_defaults[index - first_default]
                    if index >= first_default
                    else Parameter.empty,
                )
            )
        for arg in entry.args.kwonlyargs:
            parameters.append(
                Parameter(
                    arg.arg,
                    Parameter.KEYWORD_ONLY,
                    default=keyword_defaults.get(arg.arg, Parameter.empty),
                )
            )
        if entry.args.vararg or entry.args.kwarg:
            raise SecurityConfigurationError("language_sandbox:variadic_parameters")

        def expression(node):
            if isinstance(node, ast.Constant) and any(
                type(node.value) is kind for kind in (str, int, float, bool, type(None))
            ):
                return ("constant", node.value)
            if isinstance(node, ast.Subscript) and not isinstance(
                node.slice, ast.Slice
            ):
                return (
                    "pure",
                    "getitem",
                    (expression(node.value), expression(node.slice)),
                )
            if isinstance(node, ast.Name):
                return ("local", node.id)
            if isinstance(node, ast.JoinedStr):
                return (
                    "join",
                    tuple(
                        expression(part.value)
                        if isinstance(part, ast.FormattedValue)
                        and part.conversion == -1
                        and part.format_spec is None
                        else expression(part)
                        for part in node.values
                    ),
                )
            if isinstance(node, ast.Dict):
                if any(
                    not isinstance(key, ast.Constant) or type(key.value) is not str
                    for key in node.keys
                ):
                    raise SecurityConfigurationError("language_sandbox:dictionary_keys")
                keys = tuple(key.value for key in node.keys)
                if len(set(keys)) != len(keys):
                    raise SecurityConfigurationError(
                        "language_sandbox:duplicate_dictionary_key"
                    )
                return (
                    "dictionary",
                    tuple(zip(keys, (expression(value) for value in node.values))),
                )
            binary = {
                ast.Add: "add",
                ast.Sub: "sub",
                ast.Mult: "mul",
                ast.Div: "div",
                ast.FloorDiv: "floordiv",
                ast.Mod: "mod",
            }
            unary = {ast.USub: "neg", ast.UAdd: "pos", ast.Not: "not"}
            order = {ast.Lt: "lt", ast.LtE: "le", ast.Gt: "gt", ast.GtE: "ge"}
            if isinstance(node, ast.BinOp) and type(node.op) in binary:
                return (
                    "pure",
                    binary[type(node.op)],
                    (expression(node.left), expression(node.right)),
                )
            if isinstance(node, ast.UnaryOp) and type(node.op) in unary:
                return ("pure", unary[type(node.op)], (expression(node.operand),))
            if (
                isinstance(node, ast.Compare)
                and len(node.ops) == 1
                and type(node.ops[0]) in order
            ):
                return (
                    "pure",
                    order[type(node.ops[0])],
                    (expression(node.left), expression(node.comparators[0])),
                )
            if isinstance(node, ast.Call):
                target = canonical_import_target(ast.unparse(node.func), aliases or {})
                if (
                    isinstance(node.func, ast.Name)
                    and target in PURE_BUILTINS
                    and not node.keywords
                ):
                    return ("pure", target, tuple(expression(arg) for arg in node.args))
                if target in terminals and all(
                    kw.arg is not None for kw in node.keywords
                ):
                    return (
                        "call",
                        target,
                        tuple(expression(arg) for arg in node.args),
                        tuple((kw.arg, expression(kw.value)) for kw in node.keywords),
                    )
            if (
                isinstance(node, ast.Compare)
                and len(node.ops) == 1
                and isinstance(node.ops[0], (ast.Eq, ast.NotEq))
            ):
                return (
                    "compare",
                    isinstance(node.ops[0], ast.Eq),
                    expression(node.left),
                    expression(node.comparators[0]),
                )
            raise SecurityConfigurationError(
                f"language_sandbox:unsupported_expression:{type(node).__name__}"
            )

        loop_serial = 0

        def statements(nodes):
            nonlocal loop_serial
            output = []
            for node in nodes:
                if isinstance(node, ast.Return):
                    output.append(
                        (
                            "return",
                            expression(node.value)
                            if node.value is not None
                            else ("constant", None),
                        )
                    )
                elif isinstance(node, ast.Expr):
                    output.append(("expression", expression(node.value)))
                elif isinstance(node, ast.Assign) and all(
                    isinstance(target, ast.Name) for target in node.targets
                ):
                    output.append(
                        (
                            "assign",
                            tuple(target.id for target in node.targets),
                            expression(node.value),
                        )
                    )
                elif isinstance(node, ast.AugAssign) and isinstance(
                    node.target, ast.Name
                ):
                    output.append(
                        (
                            "assign",
                            (node.target.id,),
                            expression(
                                ast.BinOp(
                                    left=node.target, op=node.op, right=node.value
                                )
                            ),
                        )
                    )
                elif isinstance(node, ast.For) and isinstance(node.target, ast.Name):
                    loop_serial += 1
                    prefix = f"argus_internal_loop_{loop_serial}_"
                    index, end, step, data = (
                        prefix + name for name in ("index", "end", "step", "data")
                    )

                    def local(name):
                        return ("local", name)

                    def constant(value):
                        return ("constant", value)

                    def pure(op, *args):
                        return ("pure", op, tuple(args))

                    def assign(name, value):
                        return ("assign", (name,), value)

                    if (
                        isinstance(node.iter, ast.Call)
                        and isinstance(node.iter.func, ast.Name)
                        and node.iter.func.id == "range"
                        and not node.iter.keywords
                        and 1 <= len(node.iter.args) <= 3
                    ):
                        args = [expression(a) for a in node.iter.args]
                        start, stop, stride = (
                            (constant(0), args[0], constant(1))
                            if len(args) == 1
                            else (
                                args[0],
                                args[1],
                                args[2] if len(args) == 3 else constant(1),
                            )
                        )
                        output.extend(
                            (
                                assign(index, start),
                                assign(end, stop),
                                assign(step, pure("range_step", stride)),
                            )
                        )
                        condition = pure(
                            "range_more", local(index), local(end), local(step)
                        )
                        item = local(index)
                    else:
                        output.extend(
                            (
                                assign(data, expression(node.iter)),
                                assign(index, constant(0)),
                                assign(step, constant(1)),
                            )
                        )
                        condition = pure("lt", local(index), pure("len", local(data)))
                        item = pure("getitem", local(data), local(index))
                    # The iterator state is separate from the user's loop target.
                    body = (
                        assign(node.target.id, item),
                        assign(index, pure("add", local(index), local(step))),
                    ) + statements(node.body)
                    output.append(("while", condition, body, statements(node.orelse)))
                elif isinstance(node, ast.While):
                    output.append(
                        (
                            "while",
                            expression(node.test),
                            statements(node.body),
                            statements(node.orelse),
                        )
                    )
                elif isinstance(node, ast.If):
                    output.append(
                        (
                            "if",
                            expression(node.test),
                            statements(node.body),
                            statements(node.orelse),
                        )
                    )
                elif isinstance(node, (ast.Break, ast.Continue)):
                    output.append(
                        ("break" if isinstance(node, ast.Break) else "continue",)
                    )
                elif not isinstance(node, ast.Pass):
                    if isinstance(node, (ast.Import, ast.ImportFrom)):
                        if aliases:
                            continue
                        raise SecurityConfigurationError(
                            "language_sandbox:unregistered_import"
                        )
                    raise SecurityConfigurationError(
                        f"language_sandbox:unsupported_statement:{type(node).__name__}"
                    )
            return tuple(output)

        program = cls(
            statements(entry.body),
            Signature(parameters),
            terminals,
            contracts,
        )
        program.proof()
        return program

    def proof(self) -> dict[str, Any]:
        body, signature, terminals, contracts = self._snapshot()
        return derive_program(body, signature, contracts)

    def _snapshot(self):
        """Capture the exact metadata later used for both proof and execution."""
        body = self.body
        signature = _signature_snapshot(self.signature)
        try:
            terminals = _decision_arguments(self.terminals)
        except TypeError:
            raise SecurityConfigurationError(
                "language_proof:invalid_bindings"
            ) from None
        contracts = _terminal_contract_snapshot(self.contracts)
        if set(terminals) != set(contracts):
            raise SecurityConfigurationError(
                "language_proof:terminal_contract_mismatch"
            )
        return body, signature, terminals, contracts

    def invoke(self, arguments: dict[str, str]) -> Any:
        # No saved certificate or caller-supplied passing flag grants execution.
        body, signature, terminals, contracts = self._snapshot()
        derive_program(body, signature, contracts)
        if type(arguments) is not dict or any(
            type(key) is not str or type(value) is not str
            for key, value in arguments.items()
        ):
            raise HostExecutionDenied("language_proof:arguments_must_be_strings")
        # Binding uses the captured, data-only signature, never a mutable function
        # signature, defaults, globals, descriptors, or a tool schema validator.
        bound = signature.bind(**arguments)
        bound.apply_defaults()
        environment = dict(bound.arguments)

        cancelled = _language_cancel.get()

        def check_cancelled():
            if cancelled is not None and cancelled.is_set():
                raise HostExecutionDenied("language_sandbox:cancelled")

        def expression(node):
            check_cancelled()
            kind = node[0]
            if kind == "constant":
                return node[1]
            if kind == "local":
                if node[1] not in environment:
                    raise HostExecutionDenied("language_sandbox:unbound_local")
                return environment[node[1]]
            if kind == "join":
                parts = [expression(part) for part in node[1]]
                if any(type(part) is not str for part in parts):
                    raise HostExecutionDenied(
                        "language_sandbox:format_requires_strings"
                    )
                return "".join(parts)
            if kind == "dictionary":
                return {key: expression(part) for key, part in node[1]}
            if kind == "compare":
                left, right = expression(node[2]), expression(node[3])
                if type(left) is not str or type(right) is not str:
                    raise HostExecutionDenied(
                        "language_sandbox:comparison_requires_strings"
                    )
                return (left == right) if node[1] else (left != right)
            if kind == "pure":
                return pure_eval(node[1], [expression(part) for part in node[2]])
            if kind == "call":
                args = tuple(expression(part) for part in node[2])
                kwargs = {key: expression(part) for key, part in node[3]}
                value = inert_copy(terminals[node[1]](*args, **kwargs))
                if type(value).__name__ not in contracts[node[1]].result:
                    raise HostExecutionDenied("language_proof:terminal_result_type")
                return value
            raise HostExecutionDenied("language_sandbox:invalid_program")

        def statements(body):
            for node in body:
                check_cancelled()
                if node[0] == "return":
                    return "return", expression(node[1])
                if node[0] in {"break", "continue"}:
                    return node[0], None
                if node[0] == "expression":
                    expression(node[1])
                elif node[0] == "assign":
                    value = expression(node[2])
                    for name in node[1]:
                        environment[name] = value
                elif node[0] == "while":
                    broken = False
                    while expression(node[1]):
                        check_cancelled()
                        returned, value = statements(node[2])
                        if returned == "return":
                            return returned, value
                        if returned == "break":
                            broken = True
                            break
                    if not broken:
                        returned, value = statements(node[3])
                        if returned:
                            return returned, value
                elif node[0] == "if":
                    branch = node[2] if expression(node[1]) else node[3]
                    returned, value = statements(branch)
                    if returned:
                        return returned, value
            return False, None

        return inert_copy(statements(body)[1])
