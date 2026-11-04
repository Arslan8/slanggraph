"""Closed-world effect inference and manifest permission-ceiling checks.

Only statically resolved terminal APIs are supported. Inference overapproximates
effects; manifests must cover them, with resource monitors enforcing the grant.
Operation models are trusted API contracts; unsupported source stays unknown.
"""

from __future__ import annotations

import ast
import hashlib
import os
import re
import sys
from collections.abc import Mapping
from dataclasses import dataclass
from typing import Any

from langgraph.prebuilt.security._language_pure import PURE_BUILTINS
from langgraph.prebuilt.security.object_policy import SecurityManifest

_TEMPLATE = re.compile(r"@\{([A-Za-z_][A-Za-z0-9_]*)\}")
# Keep literals and argument references distinct, even for literal '@{path}'.
_Value = tuple[tuple[str, str], ...]


@dataclass(frozen=True)
class ManifestOperation:
    """Reviewed terminal API with a selector argument or fixed object identity.

    `target` is the fully qualified imported name (or an explicitly trusted
    global name). `parameter` and `position` identify the same resource argument.
    `fixed_resource` instead identifies a framework-bound resource with no selector
    argument. The contract assumes other arguments and the return value are inert data,
    with no additional effects, callbacks, or delayed execution.
    """

    target: str
    class_name: str
    operation: str
    parameter: str | None
    position: int = 0
    parameters: tuple[str, ...] = ()
    parameter_types: tuple[str, ...] = ()
    result_type: str | None = None
    lowering: str | None = None
    fixed_resource: str | None = None

    def __post_init__(self) -> None:
        if (
            not self.target
            or not all(part.isidentifier() for part in self.target.split("."))
            or (
                self.fixed_resource is None
                and (self.parameter is None or not self.parameter.isidentifier())
            )
            or (
                self.fixed_resource is not None
                and (not self.fixed_resource or self.parameter is not None)
            )
            or type(self.position) is not int
            or self.position < 0
        ):
            raise ValueError("invalid operation target or resource argument")
        if self.parameters and (
            len(set(self.parameters)) != len(self.parameters)
            or (
                self.fixed_resource is None
                and (
                    self.parameter not in self.parameters
                    or self.position >= len(self.parameters)
                    or self.parameters[self.position] != self.parameter
                )
            )
            or len(self.parameter_types) != len(self.parameters)
        ):
            raise ValueError("invalid typed operation signature")


def _literal(value: str) -> _Value:
    return (("literal", value),) if value else ()


def _join(parts: list[_Value]) -> _Value:
    result: list[tuple[str, str]] = []
    for part in parts:
        for kind, value in part:
            if result and kind == result[-1][0] == "literal":
                result[-1] = (kind, result[-1][1] + value)
            else:
                result.append((kind, value))
    return tuple(result)


def _pattern(pattern: str, selected: dict[str, str]) -> _Value:
    parts: list[_Value] = []
    start = 0
    for match in _TEMPLATE.finditer(pattern):
        parts.append(_literal(pattern[start : match.start()]))
        name = match[1]
        parts.append(
            _literal(selected[name]) if name in selected else (("argument", name),)
        )
        start = match.end()
    parts.append(_literal(pattern[start:]))
    return _join(parts)


def check_manifest_consistency(
    source: str,
    manifest: SecurityManifest,
    *,
    tool_name: str,
    function: str | None = None,
    operations: tuple[ManifestOperation, ...] = (),
    clients: Mapping[str, object] | None = None,
) -> dict[str, Any]:
    """Require closed-world source and inferred effects contained in the manifest.

    Source is never imported or executed. Supports straight-line expressions,
    local aliases, and branches on the manifest's closed operation selector.
    Every inferred effect must be permitted by the active manifest rules.
    Unused declarations are allowed. Calls must use reviewed terminals;
    resource monitors still enforce the surviving grant.
    Unknown calls, control flow, or resource values prevent a consistent result.
    Input values must be inert strings; module initialization, decorators,
    normalizer equivalence, `runs`, `returns`, and enforcement are outside scope.
    """
    tool = manifest.tools[tool_name]
    from langgraph.prebuilt.security.mediators.contracts import (
        client_binding,
        exported_client_models,
    )

    models = {item.target: item for item in operations}
    if len(models) != len(operations):
        raise ValueError("operation targets must be unique")
    for model in operations:
        cls = manifest.registry.classes.get(model.class_name)
        if cls is None or model.operation not in cls.operations:
            raise ValueError(
                f"unknown modeled operation: {model.class_name}::{model.operation}"
            )
    typed_models = list(exported_client_models())
    for name, client in (clients or {}).items():
        binding = client_binding(client)
        if not name.isidentifier() or binding is None:
            raise ValueError("checker clients must be registered resource instances")
        typed_models.extend(binding.models(name))
    for model in typed_models:
        if model.target in models:
            raise ValueError("operation model cannot override a registered client")
        models[model.target] = model
    issues: list[dict[str, Any]] = []
    observed: list[dict[str, Any]] = []
    used: set[int] = set()

    def issue(node: ast.AST, kind: str, reason: str) -> None:
        item = {"line": getattr(node, "lineno", 0), "kind": kind, "reason": reason}
        if item not in issues:
            issues.append(item)

    try:
        tree = ast.parse(source)
    except SyntaxError as exc:
        tree = ast.Module(body=[], type_ignores=[])
        issues.append({"line": exc.lineno, "kind": "unknown", "reason": str(exc)})
    entries = [
        node
        for node in tree.body
        if isinstance(node, (ast.FunctionDef, ast.AsyncFunctionDef))
        and node.name == (function or tool_name)
    ]
    aliases: dict[str, str] = {}
    for node in tree.body:
        if isinstance(node, ast.Import):
            for alias in node.names:
                aliases[alias.asname or alias.name.split(".")[0]] = (
                    alias.name if alias.asname else alias.name.split(".")[0]
                )
        elif isinstance(node, ast.ImportFrom) and not node.level and node.module:
            for alias in node.names:
                aliases[alias.asname or alias.name] = f"{node.module}.{alias.name}"
    if len(entries) != 1:
        issue(tree, "unknown", "expected exactly one top-level entry function")
    else:
        entry = entries[0]
        parameters = {
            arg.arg
            for arg in (
                *entry.args.posonlyargs,
                *entry.args.args,
                *entry.args.kwonlyargs,
            )
        }
        if entry.args.vararg or entry.args.kwarg:
            issue(entry, "unknown", "variadic entry arguments are unsupported")
        locals_ = parameters | {
            node.id
            for statement in entry.body
            for node in ast.walk(statement)
            if isinstance(node, ast.Name) and isinstance(node.ctx, ast.Store)
        }

        def call_model(node: ast.Call) -> tuple[str, ManifestOperation | None]:
            target = ast.unparse(node.func)
            root, dot, rest = target.partition(".")
            target = aliases.get(root, root) + (dot + rest if dot else "")
            return target, models.get(target) if root not in locals_ else None

        # Validate the entire body, independently of reachability and the
        # manifest. A denied selector or dead branch is no exemption for
        # reflection, imports, or calls to an unmonitored library.
        nodes = [node for statement in entry.body for node in ast.walk(statement)]
        annotations = {
            arg.arg: arg.annotation
            for arg in (
                *entry.args.posonlyargs,
                *entry.args.args,
                *entry.args.kwonlyargs,
            )
        }
        assignments: dict[str, list[ast.expr]] = {}
        for node in nodes:
            if isinstance(node, ast.Assign):
                for target in node.targets:
                    if isinstance(target, ast.Name):
                        assignments.setdefault(target.id, []).append(node.value)

        def value_type(
            node: ast.expr | None, seen: frozenset[str] = frozenset()
        ) -> str | None:
            if isinstance(node, ast.Compare) or (isinstance(node, ast.UnaryOp) and isinstance(node.op, ast.Not)):
                return "bool"
            if isinstance(node, ast.Constant):
                return type(node.value).__name__
            if isinstance(node, ast.JoinedStr):
                return "str"
            if isinstance(node, ast.Call):
                if isinstance(node.func, ast.Name) and node.func.id in PURE_BUILTINS and node.func.id not in locals_:
                    return "int" if node.func.id == "len" else node.func.id
                _, called = call_model(node)
                return called.result_type if called is not None else None
            if isinstance(node, ast.Name) and node.id not in seen:
                sources = assignments.get(node.id, [])
                if sources:
                    kinds = {value_type(source, seen | {node.id}) for source in sources}
                    return next(iter(kinds)) if len(kinds) == 1 else None
                if node.id in parameters:
                    annotation = annotations[node.id]
                    if annotation is None:
                        return "str"  # Existing inert-string input contract.
                    if isinstance(annotation, ast.Name) and annotation.id in {
                        "str",
                        "int",
                        "bool",
                        "float",
                    }:
                        return annotation.id
            return None

        terminal_nodes: set[int] = set()
        for node in nodes:
            if isinstance(node, ast.Call):
                target, model = call_model(node)
                if model is None and target in (PURE_BUILTINS | {"range"}) and isinstance(node.func, ast.Name) and target not in locals_:
                    terminal_nodes.add(id(node.func))
                elif model is None:
                    issue(node, "unknown", f"unmodeled call: {target}")
                else:
                    terminal_nodes.update(id(part) for part in ast.walk(node.func))
                    if model.parameters or model.fixed_resource is not None:
                        declared_class = manifest.registry.classes.get(model.class_name)
                        if (
                            model.lowering is not None
                            and declared_class is not None
                            and (
                                declared_class.lowering != model.lowering
                                or declared_class.enforced_by.value
                                not in (
                                    {"broker", "language_sandbox"}
                                    if model.fixed_resource is not None
                                    else {"broker"}
                                )
                            )
                        ):
                            issue(
                                node,
                                "mismatch",
                                f"manifest class does not match typed contract: {target}",
                            )
                        arguments = dict(zip(model.parameters, node.args))
                        invalid = len(node.args) > len(model.parameters)
                        for keyword in node.keywords:
                            if (
                                keyword.arg not in model.parameters
                                or keyword.arg in arguments
                            ):
                                invalid = True
                            else:
                                arguments[keyword.arg] = keyword.value
                        if invalid or set(arguments) != set(model.parameters):
                            issue(
                                node,
                                "mismatch",
                                f"arguments do not match typed API: {target}",
                            )
                        for name, kind in zip(model.parameters, model.parameter_types):
                            argument = arguments.get(name)
                            inferred_type = value_type(argument)
                            if argument is not None and inferred_type is None:
                                issue(
                                    argument,
                                    "unknown",
                                    f"unresolved typed argument: {target}.{name}",
                                )
                            elif argument is not None and inferred_type != kind:
                                issue(
                                    argument,
                                    "mismatch",
                                    f"{target}.{name} requires {kind}",
                                )
        for node in nodes:
            if isinstance(node, ast.stmt) and not isinstance(
                node, (ast.Return, ast.Expr, ast.Assign, ast.AugAssign, ast.If, ast.While, ast.For, ast.Pass)
            ):
                issue(node, "unknown", f"unsupported statement: {type(node).__name__}")
            if isinstance(node, ast.expr) and not isinstance(
                node,
                (
                    ast.Constant,
                    ast.Name,
                    ast.JoinedStr,
                    ast.FormattedValue,
                    ast.Call,
                    ast.Compare,
                    ast.BinOp,
                    ast.UnaryOp,
                    ast.Subscript,
                    ast.Attribute,
                ),
            ):
                issue(node, "unknown", f"unsupported expression: {type(node).__name__}")
            if isinstance(node, ast.Attribute) and id(node) not in terminal_nodes:
                issue(node, "unknown", "attribute access outside a terminal API")
            if (
                isinstance(node, ast.Name)
                and isinstance(node.ctx, ast.Load)
                and node.id not in locals_
                and id(node) not in terminal_nodes
            ):
                issue(node, "unknown", f"unmodeled global: {node.id}")
            if isinstance(node, ast.FormattedValue) and (
                node.conversion != -1 or node.format_spec is not None
            ):
                issue(node, "unknown", "formatted conversions are unsupported")
            if isinstance(node, ast.Assign) and not all(
                isinstance(target, ast.Name) for target in node.targets
            ):
                issue(node, "unknown", "assignment must target local names")
            if isinstance(node, (ast.If, ast.While)) and value_type(node.test) != "bool":
                issue(node, "unknown", "condition must produce an inert boolean")
        for rule in tool.rules:
            names = set(_TEMPLATE.findall(rule.pattern))
            if rule.selector_arg:
                names.add(rule.selector_arg)
            for name in sorted(names - parameters):
                issue(entry, "mismatch", f"manifest refers to missing argument: {name}")
        selectors = sorted(
            {
                (rule.selector_arg, rule.selector_value)
                for rule in tool.rules
                if rule.selector_arg is not None and rule.selector_value is not None
            }
        )
        # Runtime binding rejects values outside the closed selector map before
        # dispatch. Check every admitted value against its own active rules;
        # without a closed map, conservatively explore all supported branches.
        # The separate whole-body audit still rejects unapproved calls anywhere.
        cases = [dict([pair]) for pair in selectors] if selectors else [{}]
        for selected in cases:
            env: dict[str, _Value | None] = {
                name: _literal(selected[name])
                if name in selected
                else (("argument", name),)
                for name in parameters
            }
            active = [
                (index, rule)
                for index, rule in enumerate(tool.rules)
                if rule.selector_arg is None
                or selected.get(rule.selector_arg) == rule.selector_value
            ]

            def expression(node: ast.AST) -> _Value | None:
                if isinstance(node, ast.Constant):
                    return _literal(node.value) if isinstance(node.value, str) else None
                if isinstance(node, ast.Name) and node.id in env:
                    return env[node.id]
                if isinstance(node, ast.JoinedStr):
                    values = []
                    for value in node.values:
                        if isinstance(value, ast.FormattedValue):
                            if value.conversion != -1 or value.format_spec is not None:
                                issue(
                                    value,
                                    "unknown",
                                    "formatted conversions are unsupported",
                                )
                                return None
                            value = value.value
                        resolved = expression(value)
                        if resolved is None:
                            return None
                        values.append(resolved)
                    return _join(values)
                if isinstance(node, (ast.BinOp, ast.UnaryOp, ast.Compare, ast.Subscript)):
                    for child in ast.iter_child_nodes(node):
                        if isinstance(child, ast.expr):
                            expression(child)
                    return None
                if isinstance(node, ast.Call):
                    target, model = call_model(node)
                    values = [expression(arg) for arg in node.args]
                    keywords = {kw.arg: expression(kw.value) for kw in node.keywords}
                    if model is None and target in (PURE_BUILTINS | {"range"}) and isinstance(node.func, ast.Name) and target not in locals_:
                        return None
                    if model is None:
                        issue(node, "unknown", f"unmodeled call: {target}")
                        return None
                    if None in keywords or any(
                        isinstance(arg, ast.Starred) for arg in node.args
                    ):
                        issue(
                            node, "unknown", "expanded call arguments are unsupported"
                        )
                        return None
                    resource = keywords.get(model.parameter)
                    if model.fixed_resource is None and model.position < len(values):
                        if model.parameter in keywords:
                            issue(node, "unknown", "duplicate resource argument")
                            return None
                        resource = values[model.position]
                    if model.fixed_resource is not None:
                        resource = _literal(model.fixed_resource)
                    if resource is None:
                        issue(node, "unknown", f"unresolved resource for {target}")
                        return None
                    matches = [
                        index
                        for index, rule in active
                        if rule.class_name == model.class_name
                        and rule.operation == model.operation
                        and _pattern(rule.pattern, selected) == resource
                    ]
                    observed.append(
                        {
                            "line": node.lineno,
                            "target": target,
                            "class_name": model.class_name,
                            "operation": model.operation,
                            "resource": resource,
                            "selector": selected,
                            "rules": matches,
                        }
                    )
                    used.update(matches)
                    return None
                issue(node, "unknown", f"unsupported expression: {type(node).__name__}")
                return None

            def statements(body: list[ast.stmt]) -> bool:
                for node in body:
                    if isinstance(node, ast.Return):
                        if node.value:
                            expression(node.value)
                        return True
                    if isinstance(node, ast.Expr):
                        expression(node.value)
                    elif isinstance(node, ast.Assign) and all(
                        isinstance(t, ast.Name) for t in node.targets
                    ):
                        value = expression(node.value)
                        for target in node.targets:
                            assert isinstance(target, ast.Name)
                            env[target.id] = value
                    elif isinstance(node, ast.AugAssign) and isinstance(node.target, ast.Name):
                        expression(node.value)
                        env[node.target.id] = None
                    elif isinstance(node, (ast.While, ast.For)):
                        # A loop-carried selector cannot be treated as its entry
                        # value. Forget every assigned local before inspecting
                        # the condition/body, then retain only invariant values.
                        changed = {part.id for part in ast.walk(node)
                                   if isinstance(part, ast.Name) and isinstance(part.ctx, ast.Store)}
                        for name in changed:
                            env[name] = None
                        invariant = dict(env)
                        expression(node.test if isinstance(node, ast.While) else node.iter)
                        statements(node.body)
                        env.clear()
                        env.update(invariant)
                        statements(node.orelse)
                        for name in changed:
                            env[name] = None
                    elif isinstance(node, ast.If):
                        expression(node.test)
                        test = node.test
                        if (
                            isinstance(test, ast.Compare)
                            and len(test.ops) == 1
                            and isinstance(test.ops[0], (ast.Eq, ast.NotEq))
                            and isinstance(test.left, ast.Name)
                            and test.left.id in env
                            and isinstance(test.comparators[0], ast.Constant)
                            and isinstance(test.comparators[0].value, str)
                        ):
                            value = env[test.left.id]
                            if value is not None and all(
                                kind == "literal" for kind, _ in value
                            ):
                                equal = value == _literal(test.comparators[0].value)
                                taken = (
                                    equal
                                    if isinstance(test.ops[0], ast.Eq)
                                    else not equal
                                )
                                if statements(node.body if taken else node.orelse):
                                    return True
                            else:
                                before = dict(env)
                                left_returns = statements(node.body)
                                left = dict(env)
                                env.clear()
                                env.update(before)
                                right_returns = statements(node.orelse)
                                right = dict(env)
                                env.clear()
                                if left_returns and right_returns:
                                    return True
                                if left_returns:
                                    env.update(right)
                                elif right_returns:
                                    env.update(left)
                                else:
                                    env.update(
                                        {
                                            name: left.get(name)
                                            if left.get(name) == right.get(name)
                                            else None
                                            for name in left.keys() | right.keys()
                                        }
                                    )
                        else:
                            before = dict(env)
                            left_returns = statements(node.body)
                            left = dict(env)
                            env.clear()
                            env.update(before)
                            right_returns = statements(node.orelse)
                            right = dict(env)
                            env.clear()
                            if left_returns and right_returns:
                                return True
                            if left_returns:
                                env.update(right)
                            elif right_returns:
                                env.update(left)
                            else:
                                env.update({name: left.get(name) if left.get(name) == right.get(name) else None
                                            for name in left.keys() | right.keys()})
                    elif isinstance(node, ast.Pass):
                        continue
                    else:
                        issue(
                            node,
                            "unknown",
                            f"unsupported statement: {type(node).__name__}",
                        )
                return False

            statements(entry.body)
    inference_complete = not any(item["kind"] == "unknown" for item in issues)
    unused_rules = [index for index in range(len(tool.rules)) if index not in used]
    outside_manifest = [
        index for index, item in enumerate(observed) if not item["rules"]
    ]
    for index in outside_manifest:
        effect = observed[index]
        resource = "".join(
            f"@{{{value}}}" if kind == "argument" else value
            for kind, value in effect["resource"]
        )
        condition = (
            " when "
            + ", ".join(f"{key}={value}" for key, value in effect["selector"].items())
            if effect["selector"]
            else ""
        )
        issues.append(
            {
                "line": effect["line"],
                "kind": "mismatch",
                "reason": (
                    f"inferred {effect['class_name']}::{effect['operation']} on {resource}"
                    f"{condition} is not permitted by the manifest"
                ),
            }
        )
    status = (
        "mismatch"
        if any(i["kind"] == "mismatch" for i in issues)
        else "unknown"
        if issues
        else "consistent"
    )
    return {
        "schema_version": 3,
        "verified_scope": "function_body_only",
        "initialization_verified": False,
        "tool": tool_name,
        "status": status,
        "consistent": status == "consistent",
        "source_sha256": hashlib.sha256(source.encode()).hexdigest(),
        "issues": issues,
        "observed": observed,
        "inferred": observed,
        "inference_complete": inference_complete,
        "inferred_subset_of_manifest": not outside_manifest
        if inference_complete
        else None,
        "outside_manifest": outside_manifest,
        "unused_rules": unused_rules,
        "scope": "Closed-world function-body analysis and inferred effects covered by the manifest under reviewed monitored terminal models and inert strings; excludes module initialization, decorators, run locus, return classification, normalization equivalence, and runtime enforcement.",
    }


def format_manifest_diagnostics(
    report: Mapping[str, Any], *, source_name: str = "<source>"
) -> str:
    """Format verifier failures for CLI output or admission exceptions.

    Labels are red and messages yellow on terminals unless NO_COLOR is set.
    Successful reports produce no diagnostic. Reports are not certificates.
    """
    if report["consistent"]:
        return ""
    color = sys.stderr.isatty() and "NO_COLOR" not in os.environ

    def highlight(text: str, style: str) -> str:
        return f"\033[{style}m{text}\033[0m" if color else text

    def diagnostic(label: str, message: str) -> str:
        return f"{highlight(label + ':', '1;31')} {highlight(message, '1;33')}"

    tool = report.get("tool", "<unknown tool>")
    message = f"manifest verification failed for {tool} ({report['status']})"
    lines = [f"{source_name}: {diagnostic('error', message)}"]
    kinds = {issue.get("kind") for issue in report["issues"]}
    if "mismatch" in kinds:
        lines.append(diagnostic("Failed subset check", "inferred ⊆ manifest."))
    if "unknown" in kinds:
        lines.append(
            diagnostic(
                "Cannot establish subset check",
                "inferred ⊆ allowed operations "
                "(unsupported or unapproved code; inference is incomplete).",
            )
        )
        if "mismatch" not in kinds:
            lines.append(
                diagnostic(
                    "Subset check not established",
                    "inferred ⊆ manifest (inference is incomplete).",
                )
            )
    for issue in report["issues"]:
        line = issue.get("line", 0)
        location = f"{source_name}:{line}" if line else source_name
        lines.append(f"{location}: {diagnostic('error', issue['reason'])}")
    for effect in report.get("inferred", []):
        resource = "".join(
            f"@{{{value}}}" if kind == "argument" else value
            for kind, value in effect["resource"]
        )
        message = (
            f"{effect['class_name']}::{effect['operation']} on {resource} "
            f"from {effect['target']}"
        )
        lines.append(
            f"{source_name}:{effect['line']}: {diagnostic('inferred', message)}"
        )
    if report.get("inference_complete") and not report.get("inferred"):
        lines.append(diagnostic("Inferred", "no resource operations in the tool body."))
    lines.append(diagnostic("Static verification", "rejected this tool body."))
    return "\n".join(lines)


def manifest_verification_exit_code(
    report: Mapping[str, Any], *, source_name: str = "<source>"
) -> int:
    """Emit framework diagnostics on stderr and return 0 on success or 1 on failure."""
    diagnostic = format_manifest_diagnostics(report, source_name=source_name)
    if not diagnostic:
        return 0
    print(diagnostic, file=sys.stderr)
    return 1


def _main() -> int:
    import argparse
    import json
    from pathlib import Path

    from langgraph.prebuilt.security.object_policy import parse_security_manifest

    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("source", type=Path)
    parser.add_argument("manifest", type=Path)
    parser.add_argument("--tool", required=True)
    parser.add_argument("--function")
    parser.add_argument(
        "--operations", type=Path, help="JSON array of reviewed API models"
    )
    parser.add_argument("--output", type=Path)
    args = parser.parse_args()
    try:
        models = (
            tuple(
                ManifestOperation(**item)
                for item in json.loads(args.operations.read_text())
            )
            if args.operations
            else ()
        )
        report = check_manifest_consistency(
            args.source.read_text(encoding="utf-8"),
            parse_security_manifest(args.manifest.read_text(encoding="utf-8")),
            tool_name=args.tool,
            function=args.function,
            operations=models,
        )
    except (OSError, ValueError, TypeError, KeyError) as exc:
        report = {
            "consistent": False,
            "status": "unknown",
            "issues": [{"reason": str(exc)}],
        }
    rendered = json.dumps(report, indent=2, sort_keys=True) + "\n"
    if args.output:
        args.output.write_text(rendered, encoding="utf-8")
    else:
        print(rendered, end="")
    return manifest_verification_exit_code(report, source_name=str(args.source))


if __name__ == "__main__":
    raise SystemExit(_main())
