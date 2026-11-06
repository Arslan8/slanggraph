"""Route evidence for language-sandbox tools under the documented threat model.

The interpreter, registered terminals and admission code are trusted (see
`docs/security/threat-model.md`). Under those premises the route claim is:
every execution of an admitted program is preceded, on the same captured
snapshot, by a successful `derive_program` derivation, which admits only
registered terminal calls over inert data. This module checks that claim's two
parts against the current sources: the execution choke point, derived from the
source text, and the checker's behavior on fixed useful and forbidden programs.
It does not prove the interpreter or the terminals; those are premises.
"""

from __future__ import annotations

import ast
import hashlib
from pathlib import Path
from typing import Any

_SANDBOX = "langgraph.prebuilt.security._language_sandbox"
_INPROCESS = "langgraph.prebuilt.security.inprocess"

PREMISES = (
    "The language-sandbox interpreter (LanguageProgram.invoke) executes exactly the instructions derive_program admitted (trusted computing base).",
    "Registered terminals implement their TerminalContract and their authorization contracts (trusted computing base).",
    "Admission code, CPython and module initialization behave as documented (trusted computing base).",
)

# Fixed controls. Useful programs must derive; forbidden ones must be refused.
_USEFUL = {
    "loop": "def repeated(path):\n    i = 0\n    while i < 3:\n        read_text(path)\n        i += 1\n    return path\n",
    "reader": "def reader(path: str) -> str:\n    return read_text(path)\n",
    "two_reads": (
        "def two_reads(first: str, second: str) -> str:\n"
        "    return f'{read_text(first)}{read_text(second)}'\n"
    ),
    "select": (
        "def select(path: str, mode: str) -> str:\n"
        "    if mode == 'full':\n"
        "        return read_text(path)\n"
        "    return 'skipped'\n"
    ),
}
_FORBIDDEN = {
    "import": "def bad(path: str) -> str:\n    import os\n    return path\n",
    "attribute": "def bad(path: str) -> str:\n    return path.upper()\n",
    "unregistered_call": "def bad(path: str) -> str:\n    return open(path)\n",
    "builtin_eval": "def bad(path: str) -> str:\n    return eval(path)\n",
    "lambda": "def bad(path: str) -> str:\n    f = lambda: path\n    return path\n",
    "subscript": "def bad(path: str) -> str:\n    return path[open(path)]\n",
    "loop": "def bad(path: str) -> str:\n    while True:\n        open(path)\n",
    "global": "def bad(path: str) -> str:\n    global x\n    return path\n",
}


def _method(
    tree: ast.Module, cls: str, name: str
) -> ast.FunctionDef | ast.AsyncFunctionDef | None:
    for node in tree.body:
        if isinstance(node, ast.ClassDef) and node.name == cls:
            for member in node.body:
                if (
                    isinstance(member, (ast.FunctionDef, ast.AsyncFunctionDef))
                    and member.name == name
                ):
                    return member
    return None


def _choke_point(sandbox: str, inprocess: str) -> list[str]:
    """Return issues; empty means the execution choke point holds."""
    issues = []
    tree = ast.parse(sandbox)
    if not any(
        isinstance(node, ast.ImportFrom)
        and node.module == "langgraph.prebuilt.security.language_verification"
        and any(
            alias.name == "derive_program" and not alias.asname for alias in node.names
        )
        for node in tree.body
    ):
        issues.append("derive_program is not imported from language_verification")
    if any(
        isinstance(node, (ast.FunctionDef, ast.Assign, ast.ClassDef))
        and (
            getattr(node, "name", None) == "derive_program"
            or any(
                isinstance(target, ast.Name) and target.id == "derive_program"
                for target in getattr(node, "targets", [])
            )
        )
        for node in tree.body
    ):
        issues.append("derive_program is rebound in the sandbox module")
    invoke = _method(tree, "LanguageProgram", "invoke")
    if invoke is None or len(invoke.body) < 2:
        return [*issues, "LanguageProgram.invoke is missing"]
    first, second = invoke.body[0], invoke.body[1]
    names = ("body", "signature", "terminals", "contracts")
    if not (
        isinstance(first, ast.Assign)
        and len(first.targets) == 1
        and isinstance(first.targets[0], ast.Tuple)
        and [getattr(e, "id", None) for e in first.targets[0].elts] == list(names)
        and isinstance(first.value, ast.Call)
        and ast.unparse(first.value) == "self._snapshot()"
    ):
        issues.append("invoke does not start by capturing the program snapshot")
    if not (
        isinstance(second, ast.Expr)
        and isinstance(second.value, ast.Call)
        and ast.unparse(second.value) == "derive_program(body, signature, contracts)"
    ):
        issues.append("invoke does not derive the captured snapshot before execution")
    # Each captured field is bound exactly once: by the snapshot assignment.
    bindings = [
        node.id
        for node in ast.walk(invoke)
        if isinstance(node, ast.Name)
        and isinstance(node.ctx, (ast.Store, ast.Del))
        and node.id in names
    ]
    if sorted(bindings) != sorted(names):
        issues.append("invoke rebinds a captured snapshot field")
    executes = [
        node
        for node in ast.walk(tree)
        if isinstance(node, ast.Call)
        and isinstance(node.func, ast.Subscript)
        and ast.unparse(node.func.value) == "terminals"
    ]
    inside = {id(node) for node in ast.walk(invoke)}
    if not executes or any(id(node) not in inside for node in executes):
        issues.append("a terminal is executed outside LanguageProgram.invoke")
    lower = _method(tree, "LanguageProgram", "lower")
    if lower is None or not any(
        isinstance(node, ast.Call) and ast.unparse(node) == "program.proof()"
        for node in ast.walk(lower)
    ):
        issues.append("lower does not prove the program at admission")

    admission = ast.parse(inprocess)
    for name in ("invoke", "ainvoke"):
        method = _method(admission, "ManifestAdmission", name)
        if method is None:
            issues.append(f"ManifestAdmission.{name} is missing")
            continue
        if ast.unparse(method.body[1 if ast.get_docstring(method) else 0]) != (
            "self.validate()"
        ):
            issues.append(f"ManifestAdmission.{name} does not validate first")
        execution_methods = [method]
        delegates = [
            node
            for node in ast.walk(method)
            if isinstance(node, ast.Call)
            and ast.unparse(node.func) == "self._invoke_validated"
        ]
        if delegates:
            validated = _method(admission, "ManifestAdmission", "_invoke_validated")
            if len(delegates) != 1 or validated is None:
                issues.append(
                    "ManifestAdmission.invoke has an invalid validated execution path"
                )
            else:
                execution_methods.append(validated)
        reaches = [
            node
            for selected in execution_methods
            for node in ast.walk(selected)
            if isinstance(node, ast.Attribute) and node.attr == "invoke"
        ]
        if not reaches or any(
            ast.unparse(node) != "program.invoke" for node in reaches
        ):
            issues.append(
                f"ManifestAdmission.{name} does not execute through program.invoke"
            )
    return issues


def _controls() -> tuple[dict[str, Any], list[str]]:
    from langgraph.prebuilt.security._language_sandbox import LanguageProgram
    from langgraph.prebuilt.security.errors import SecurityConfigurationError
    from langgraph.prebuilt.security.inprocess import read_text
    from langgraph.prebuilt.security.language_verification import TerminalContract

    contracts = {"read_text": TerminalContract((("path", "str"),), frozenset({"str"}))}
    terminals = {"read_text": read_text}
    results: dict[str, Any] = {"useful": {}, "forbidden": {}}
    issues = []
    for name, source in _USEFUL.items():
        entry = ast.parse(source).body[0]
        try:
            proof = LanguageProgram.lower(
                entry, terminals, (), {}, contracts=contracts
            ).proof()
        except Exception as exc:  # any refusal of a useful program is a failure
            issues.append(f"useful program {name} refused: {type(exc).__name__}")
            continue
        ok = proof.get("proved") is True and set(proof.get("effects", [])) <= {
            "read_text"
        }
        results["useful"][name] = {
            "proved": ok,
            "effects": sorted(proof.get("effects", [])),
        }
        if not ok:
            issues.append(f"useful program {name} not proved")
    for name, source in _FORBIDDEN.items():
        entry = ast.parse(source).body[0]
        try:
            LanguageProgram.lower(entry, terminals, (), {}, contracts=contracts)
        except SecurityConfigurationError as exc:
            results["forbidden"][name] = {"refused": True, "code": str(exc)}
            continue
        except Exception as exc:
            issues.append(
                f"forbidden program {name} raised {type(exc).__name__}, not a refusal"
            )
            continue
        results["forbidden"][name] = {"refused": False}
        issues.append(f"forbidden program {name} was admitted")
    return results, issues


def verify_language_route(sandbox_source: str, inprocess_source: str) -> dict[str, Any]:
    """Check the language-sandbox route claim against the supplied sources."""
    report: dict[str, Any] = {
        "kind": "language-route",
        "schema_version": 1,
        "proved": False,
        "claim": "Every admitted language-sandbox program runs only after a successful derivation of the same captured snapshot; derivation admits only registered terminal calls over inert data.",
        "premises": list(PREMISES),
        "system_complete": False,
        "source_sha256": {
            _SANDBOX: hashlib.sha256(sandbox_source.encode()).hexdigest(),
            _INPROCESS: hashlib.sha256(inprocess_source.encode()).hexdigest(),
        },
        "checker_sha256": hashlib.sha256(Path(__file__).read_bytes()).hexdigest(),
        "issues": [],
    }
    try:
        report["issues"].extend(_choke_point(sandbox_source, inprocess_source))
    except SyntaxError as exc:
        report["issues"].append(f"unparsable source: {exc.lineno}")
        return report
    controls, issues = _controls()
    report["controls"] = controls
    report["issues"].extend(issues)
    report["proved"] = not report["issues"]
    return report
