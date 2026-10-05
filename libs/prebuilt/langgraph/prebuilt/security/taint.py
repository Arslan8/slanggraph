"""Conservative static analysis for escapes from tool security mediation.

This module does not prove that Python code is confined. It identifies code paths
where graph-controlled values can reach capabilities outside `ToolNode` or
`guarded_tool`. Unknown dynamic behavior is reported as an escape instead of
being treated as safe.
"""

from __future__ import annotations

import argparse
import ast
import json
from collections import deque
from collections.abc import Iterable, Sequence
from dataclasses import asdict, dataclass
from enum import Enum
from pathlib import Path
from typing import Any


class EscapeKind(str, Enum):
    """Classes of operations that can bypass tool mediation."""

    UNMEDIATED_NODE = "unmediated_node"
    UNKNOWN_CALLBACK = "unknown_callback"
    UNKNOWN_CALL = "unknown_call"
    UNPROTECTED_COMPILE = "unprotected_compile"
    DIRECT_INVOKE = "direct_invoke"
    FILESYSTEM = "filesystem"
    PROCESS = "process"
    NETWORK = "network"
    DATABASE = "database"
    DYNAMIC_CODE = "dynamic_code"
    DESERIALIZATION = "deserialization"
    NATIVE_CODE = "native_code"
    DYNAMIC_DISPATCH = "dynamic_dispatch"
    RETAINED_CAPABILITY = "retained_capability"
    UNDECLARED_EFFECT = "undeclared_effect"


class EscapeSeverity(str, Enum):
    """Review priority for an escape finding."""

    CRITICAL = "critical"
    HIGH = "high"
    MEDIUM = "medium"


@dataclass(frozen=True, slots=True, order=True)
class EscapeFinding:
    """One potential route around the security mediation boundary."""

    path: str
    line: int
    column: int
    kind: EscapeKind
    severity: EscapeSeverity
    symbol: str
    function: str | None
    tainted: bool
    message: str

    @property
    def fingerprint(self) -> str:
        """Return a stable-enough identifier for review baselines."""
        scope = self.function or "<module>"
        return f"{self.path}:{scope}:{self.kind.value}:{self.symbol}"


@dataclass(frozen=True, slots=True)
class TaintReport:
    """Results from scanning one or more Python source trees."""

    findings: tuple[EscapeFinding, ...]
    parse_errors: tuple[str, ...] = ()

    @property
    def safe(self) -> bool:
        """Whether the analysis found no escapes or incomplete inputs."""
        return not self.findings and not self.parse_errors

    def to_json(self) -> str:
        """Serialize the report for CI and code-review artifacts."""
        return json.dumps(
            {
                "findings": [
                    {
                        **asdict(finding),
                        "kind": finding.kind.value,
                        "severity": finding.severity.value,
                        "fingerprint": finding.fingerprint,
                    }
                    for finding in self.findings
                ],
                "parse_errors": list(self.parse_errors),
                "safe": self.safe,
            },
            indent=2,
            sort_keys=True,
        )


@dataclass(frozen=True, slots=True)
class _Registration:
    callback: ast.expr
    kind: str
    call: ast.Call


_DIRECT_INVOKE_METHODS = {"ainvoke", "arun", "invoke", "run"}
_FILESYSTEM_METHODS = {
    "chmod",
    "chown",
    "link",
    "mkdir",
    "open",
    "read",
    "read_bytes",
    "read_text",
    "rmdir",
    "symlink_to",
    "touch",
    "truncate",
    "unlink",
    "write_bytes",
    "write_text",
    "write",
}
_FILESYSTEM_FUNCTIONS = {
    "os.chmod",
    "os.chown",
    "os.link",
    "os.makedirs",
    "os.mkdir",
    "os.remove",
    "os.removedirs",
    "os.rename",
    "os.renames",
    "os.replace",
    "os.rmdir",
    "os.symlink",
    "os.truncate",
    "os.unlink",
    "shutil.copy",
    "shutil.copy2",
    "shutil.copyfile",
    "shutil.copytree",
    "shutil.move",
    "shutil.rmtree",
}
_DATABASE_METHODS = {"execute", "executemany", "executescript"}
_NETWORK_METHODS = {
    "connect",
    "delete",
    "get",
    "head",
    "open_connection",
    "patch",
    "post",
    "put",
    "request",
    "send",
    "sendmail",
    "urlopen",
}
_PROCESS_PREFIXES = (
    "asyncio.create_subprocess_",
    "multiprocessing.",
    "os.exec",
    "os.fork",
    "os.popen",
    "os.posix_spawn",
    "os.spawn",
    "os.system",
    "subprocess.",
)
_NETWORK_PREFIXES = (
    "aiohttp.",
    "asyncio.open_connection",
    "boto3.",
    "botocore.",
    "ftplib.",
    "grpc.",
    "http.client.",
    "httpx.",
    "requests.",
    "paramiko.",
    "smtplib.",
    "socket.",
    "urllib.",
    "urllib3.",
    "websockets.",
)
_DATABASE_PREFIXES = (
    "aiosqlite.",
    "asyncpg.",
    "mysql.",
    "psycopg.",
    "pymongo.",
    "redis.",
    "sqlite3.",
    "sqlalchemy.",
)
_DESERIALIZATION_PREFIXES = (
    "cloudpickle.load",
    "dill.load",
    "joblib.load",
    "marshal.load",
    "pickle.load",
    "shelve.open",
    "torch.load",
    "yaml.load",
)
_NATIVE_PREFIXES = ("cffi.", "ctypes.")
_DYNAMIC_CODE = {
    "builtins.__import__",
    "builtins.compile",
    "builtins.eval",
    "builtins.exec",
    "importlib.import_module",
    "runpy.run_module",
    "runpy.run_path",
}
_BUILTINS = {
    "__import__",
    "compile",
    "delattr",
    "eval",
    "exec",
    "getattr",
    "open",
    "setattr",
}
_SAFE_CALLS = {
    "all",
    "any",
    "bool",
    "builtins.all",
    "builtins.any",
    "builtins.bool",
    "builtins.dict",
    "builtins.enumerate",
    "builtins.float",
    "builtins.int",
    "builtins.isinstance",
    "builtins.len",
    "builtins.list",
    "builtins.max",
    "builtins.min",
    "builtins.reversed",
    "builtins.set",
    "builtins.sorted",
    "builtins.str",
    "builtins.tuple",
    "dict",
    "enumerate",
    "float",
    "int",
    "isinstance",
    "len",
    "list",
    "max",
    "min",
    "reversed",
    "set",
    "sorted",
    "str",
    "tuple",
    "typing.cast",
}
_SAFE_METHODS = {
    "copy",
    "count",
    "endswith",
    "get",
    "index",
    "items",
    "join",
    "keys",
    "lower",
    "removeprefix",
    "removesuffix",
    "rsplit",
    "split",
    "startswith",
    "strip",
    "upper",
    "values",
}


def analyze_source(
    *roots: str | Path,
    exclude: Sequence[str | Path] = (),
) -> TaintReport:
    """Analyze Python files for paths around LangGraph tool mediation.

    Function parameters of callbacks registered with graph execution APIs are
    taint sources. The analysis follows local assignments and calls to local
    helpers. It reports the callback boundary itself because ordinary graph
    nodes execute unrestricted Python, even when no known sink is visible.

    Args:
        roots: Python files or directories to scan recursively.
        exclude: Files or directories to omit after path resolution.
    """
    files = _python_files(roots or (Path.cwd(),), exclude)
    findings: list[EscapeFinding] = []
    errors: list[str] = []
    common_root = _common_root(files)
    for source_path in files:
        try:
            source = source_path.read_text(encoding="utf-8")
            tree = ast.parse(source, filename=str(source_path))
        except (OSError, SyntaxError, UnicodeError) as exc:
            errors.append(f"{source_path}: {exc}")
            continue
        display_path = _display_path(source_path, common_root)
        findings.extend(_ModuleAnalyzer(display_path, tree).analyze())
    findings.sort(
        key=lambda item: (
            item.path,
            item.line,
            item.column,
            item.kind.value,
            item.symbol,
        )
    )
    return TaintReport(tuple(findings), tuple(sorted(errors)))


def _python_files(
    roots: Sequence[str | Path], exclude: Sequence[str | Path]
) -> list[Path]:
    excluded = {Path(item).resolve() for item in exclude}

    def omitted(path: Path) -> bool:
        resolved = path.resolve()
        return any(resolved == item or item in resolved.parents for item in excluded)

    files: set[Path] = set()
    for item in roots:
        path = Path(item)
        if path.is_file() and path.suffix == ".py" and not omitted(path):
            files.add(path.resolve())
        elif path.is_dir():
            files.update(
                candidate.resolve()
                for candidate in path.rglob("*.py")
                if not omitted(candidate)
                and not any(
                    part in {".git", ".mypy_cache", ".pytest_cache", ".venv"}
                    for part in candidate.parts
                )
            )
    return sorted(files)


def _common_root(files: Sequence[Path]) -> Path | None:
    if not files:
        return None
    common = Path(files[0]).parent
    for path in files[1:]:
        while common not in path.parents and common != path:
            if common == common.parent:
                return None
            common = common.parent
    return common


def _display_path(path: Path, common_root: Path | None) -> str:
    if common_root is None:
        return str(path)
    try:
        return str(path.relative_to(common_root))
    except ValueError:
        return str(path)


class _ModuleAnalyzer:
    def __init__(self, path: str, tree: ast.Module) -> None:
        self.path = path
        self.tree = tree
        self.imports: dict[str, str] = {}
        self.functions: dict[str, ast.FunctionDef | ast.AsyncFunctionDef] = {}
        self.capability_names: set[str] = set()
        self.guarded_names: set[str] = set()
        self.tool_effects: dict[str, set[str]] = {}
        self.graph_names: set[str] = set()
        self.non_execution_graph_names: set[str] = set()
        self.registrations: list[_Registration] = []
        self.findings: dict[tuple[int, int, EscapeKind, str], EscapeFinding] = {}

    def analyze(self) -> Iterable[EscapeFinding]:
        self._collect_definitions()
        self._collect_registrations()
        pending: deque[str] = deque()
        analyzed: set[str] = set()

        for registration in self.registrations:
            callback = registration.callback
            if isinstance(callback, ast.Name) and callback.id in self.guarded_names:
                continue
            if isinstance(callback, ast.Name) and callback.id in self.capability_names:
                continue
            self._finding(
                callback,
                EscapeKind.UNMEDIATED_NODE,
                EscapeSeverity.CRITICAL,
                _expression_name(callback),
                None,
                True,
                f"{registration.kind} executes outside the tool mediation boundary",
            )
            if isinstance(callback, ast.Name) and callback.id in self.functions:
                pending.append(callback.id)
            elif isinstance(callback, ast.Call) and self._qualified_name(
                callback.func
            ).endswith("RunnableCallable"):
                unresolved = False
                for wrapped in callback.args[:2]:
                    if isinstance(wrapped, ast.Name) and wrapped.id in self.functions:
                        pending.append(wrapped.id)
                    elif not _is_none(wrapped):
                        unresolved = True
                if unresolved:
                    self._unknown_callback(callback)
            elif isinstance(callback, ast.Lambda):
                _FunctionAnalyzer(self, "<lambda>", callback).analyze()
            else:
                self._unknown_callback(callback)

        while pending:
            name = pending.popleft()
            if name in analyzed:
                continue
            analyzed.add(name)
            analyzer = _FunctionAnalyzer(self, name, self.functions[name])
            analyzer.analyze()
            pending.extend(
                helper for helper in analyzer.local_calls if helper not in analyzed
            )

        self._find_retained_capabilities()
        self._analyze_tool_effects()
        return self.findings.values()

    def _collect_definitions(self) -> None:
        for node in ast.walk(self.tree):
            if isinstance(node, ast.Import):
                for alias in node.names:
                    self.imports[alias.asname or alias.name.split(".")[0]] = alias.name
            elif isinstance(node, ast.ImportFrom):
                module = node.module or ""
                for alias in node.names:
                    name = alias.asname or alias.name
                    self.imports[name] = f"{module}.{alias.name}".strip(".")
            elif isinstance(node, (ast.FunctionDef, ast.AsyncFunctionDef)):
                self.functions.setdefault(node.name, node)
                decorators = {_decorator_name(item) for item in node.decorator_list}
                if any(name.endswith("guarded_tool") for name in decorators):
                    self.guarded_names.add(node.name)
                if any(name == "tool" or name.endswith(".tool") for name in decorators):
                    self.capability_names.add(node.name)
                if (
                    node.name in self.guarded_names
                    or node.name in self.capability_names
                ):
                    self.tool_effects[node.name] = _declared_effects(node)
            elif isinstance(node, (ast.Assign, ast.AnnAssign)):
                value = node.value
                if not isinstance(value, ast.Call):
                    continue
                targets = (
                    node.targets if isinstance(node, ast.Assign) else [node.target]
                )
                names = {
                    item.id
                    for target in targets
                    for item in ast.walk(target)
                    if isinstance(item, ast.Name)
                }
                called = self._qualified_name(value.func)
                if called.endswith("ToolNode"):
                    self.capability_names.update(names)
                elif called.endswith("guarded_tool"):
                    self.guarded_names.update(names)
                elif called.endswith("StateGraph"):
                    self.graph_names.update(names)
                elif called.endswith("Graph"):
                    self.non_execution_graph_names.update(names)

    def _collect_registrations(self) -> None:
        for node in ast.walk(self.tree):
            if not isinstance(node, ast.Call):
                continue
            method = _attribute_name(node.func)
            if method == "add_node":
                if not self._is_execution_graph_call(node):
                    continue
                callback = _keyword(node, "action")
                if callback is None:
                    if len(node.args) >= 2:
                        callback = node.args[1]
                    elif node.args and not isinstance(node.args[0], ast.Constant):
                        callback = node.args[0]
                if callback is not None:
                    self.registrations.append(
                        _Registration(callback, "graph node", node)
                    )
                error_handler = _keyword(node, "error_handler")
                if error_handler is not None and not _is_none(error_handler):
                    self.registrations.append(
                        _Registration(error_handler, "error handler", node)
                    )
            elif method == "add_conditional_edges":
                if not self._is_execution_graph_call(node):
                    continue
                callback = _keyword(node, "path")
                if callback is None and len(node.args) >= 2:
                    callback = node.args[1]
                if callback is not None:
                    self.registrations.append(
                        _Registration(callback, "conditional edge", node)
                    )
            elif method == "set_conditional_entry_point":
                if not self._is_execution_graph_call(node):
                    continue
                callback = _keyword(node, "path")
                if callback is None and node.args:
                    callback = node.args[0]
                if callback is not None:
                    self.registrations.append(
                        _Registration(callback, "conditional entry point", node)
                    )
            elif method == "set_node_defaults":
                if not self._is_execution_graph_call(node):
                    continue
                error_handler = _keyword(node, "error_handler")
                if error_handler is not None and not _is_none(error_handler):
                    self.registrations.append(
                        _Registration(error_handler, "default error handler", node)
                    )
            elif method == "add_sequence":
                if not self._is_execution_graph_call(node):
                    continue
                sequence = _keyword(node, "nodes")
                if sequence is None and node.args:
                    sequence = node.args[0]
                if sequence is not None:
                    callbacks = _sequence_callbacks(sequence)
                    if callbacks is None:
                        self.registrations.append(
                            _Registration(sequence, "dynamic node sequence", node)
                        )
                    else:
                        self.registrations.extend(
                            _Registration(callback, "graph node sequence", node)
                            for callback in callbacks
                        )
            elif method == "compile" and self._is_execution_graph_call(node):
                security = _keyword(node, "security")
                if security is None or _is_none(security):
                    self._finding(
                        node,
                        EscapeKind.UNPROTECTED_COMPILE,
                        EscapeSeverity.CRITICAL,
                        _expression_name(node.func),
                        None,
                        False,
                        "graph is compiled without a security configuration",
                    )

    def _is_execution_graph_call(self, call: ast.Call) -> bool:
        if not isinstance(call.func, ast.Attribute):
            return False
        receiver = call.func.value
        if isinstance(receiver, ast.Name):
            if receiver.id in self.non_execution_graph_names:
                return False
            if receiver.id in self.graph_names or receiver.id == "self":
                return True
            return receiver.id in {"builder", "graph", "workflow"}
        if isinstance(receiver, ast.Call):
            return self._qualified_name(receiver.func).endswith("StateGraph")
        return False

    def _unknown_callback(self, callback: ast.expr) -> None:
        self._finding(
            callback,
            EscapeKind.UNKNOWN_CALLBACK,
            EscapeSeverity.HIGH,
            _expression_name(callback),
            None,
            True,
            "callback implementation cannot be resolved statically",
        )

    def _find_retained_capabilities(self) -> None:
        for node in ast.walk(self.tree):
            if not isinstance(node, ast.Call):
                continue
            if not self._qualified_name(node.func).endswith("ToolNode"):
                continue
            tools = _keyword(node, "tools")
            if tools is None and node.args:
                tools = node.args[0]
            if not isinstance(tools, (ast.List, ast.Set, ast.Tuple)):
                continue
            for element in tools.elts:
                if isinstance(element, ast.Name):
                    if element.id in self.functions:
                        self.tool_effects.setdefault(
                            element.id, _declared_effects(self.functions[element.id])
                        )
                    self._finding(
                        element,
                        EscapeKind.RETAINED_CAPABILITY,
                        EscapeSeverity.MEDIUM,
                        element.id,
                        None,
                        False,
                        "tool remains directly reachable outside its mediated ToolNode",
                    )

    def _analyze_tool_effects(self) -> None:
        for tool_name, declared in self.tool_effects.items():
            if tool_name not in self.functions:
                continue
            pending = deque([tool_name])
            visited: set[str] = set()
            while pending:
                function_name = pending.popleft()
                if function_name in visited or function_name not in self.functions:
                    continue
                visited.add(function_name)
                analyzer = _ToolEffectAnalyzer(
                    self, tool_name, declared, self.functions[function_name]
                )
                analyzer.analyze()
                pending.extend(analyzer.local_calls)

    def _qualified_name(self, expression: ast.expr) -> str:
        raw = _expression_name(expression)
        first, separator, rest = raw.partition(".")
        imported = self.imports.get(first)
        if imported is None:
            if first in _BUILTINS:
                return f"builtins.{raw}"
            return raw
        return imported + (separator + rest if separator else "")

    def _finding(
        self,
        node: ast.AST,
        kind: EscapeKind,
        severity: EscapeSeverity,
        symbol: str,
        function: str | None,
        tainted: bool,
        message: str,
    ) -> None:
        key = (node.lineno, node.col_offset, kind, symbol)
        self.findings[key] = EscapeFinding(
            self.path,
            node.lineno,
            node.col_offset,
            kind,
            severity,
            symbol,
            function,
            tainted,
            message,
        )


class _FunctionAnalyzer(ast.NodeVisitor):
    def __init__(
        self,
        module: _ModuleAnalyzer,
        name: str,
        function: ast.FunctionDef | ast.AsyncFunctionDef | ast.Lambda,
    ) -> None:
        self.module = module
        self.name = name
        self.function = function
        self.tainted = {argument.arg for argument in _arguments(function.args)}
        self.local_calls: set[str] = set()

    def analyze(self) -> None:
        body: Iterable[ast.AST]
        if isinstance(self.function, ast.Lambda):
            body = (self.function.body,)
        else:
            body = self.function.body
        for statement in body:
            self.visit(statement)

    def visit_Assign(self, node: ast.Assign) -> Any:
        self.visit(node.value)
        if self._is_tainted(node.value):
            for target in node.targets:
                self._mark_tainted(target)

    def visit_AnnAssign(self, node: ast.AnnAssign) -> Any:
        if node.value is not None:
            self.visit(node.value)
            if self._is_tainted(node.value):
                self._mark_tainted(node.target)

    def visit_NamedExpr(self, node: ast.NamedExpr) -> Any:
        self.visit(node.value)
        if self._is_tainted(node.value):
            self._mark_tainted(node.target)

    def visit_For(self, node: ast.For) -> Any:
        self.visit(node.iter)
        if self._is_tainted(node.iter):
            self._mark_tainted(node.target)
        for statement in (*node.body, *node.orelse):
            self.visit(statement)

    def visit_AsyncFor(self, node: ast.AsyncFor) -> Any:
        self.visit(node.iter)
        if self._is_tainted(node.iter):
            self._mark_tainted(node.target)
        for statement in (*node.body, *node.orelse):
            self.visit(statement)

    def visit_FunctionDef(self, node: ast.FunctionDef) -> Any:
        return None

    def visit_AsyncFunctionDef(self, node: ast.AsyncFunctionDef) -> Any:
        return None

    def visit_Lambda(self, node: ast.Lambda) -> Any:
        return None

    def visit_Call(self, node: ast.Call) -> Any:
        qualified = self.module._qualified_name(node.func)
        method = _attribute_name(node.func)
        receiver = node.func.value if isinstance(node.func, ast.Attribute) else None
        tainted = any(self._is_tainted(value) for value in node.args) or any(
            self._is_tainted(keyword.value) for keyword in node.keywords
        )
        tainted = tainted or (receiver is not None and self._is_tainted(receiver))

        kind = _sink_kind(qualified, method)
        if kind is not None:
            severity = (
                EscapeSeverity.CRITICAL
                if kind
                in {
                    EscapeKind.DIRECT_INVOKE,
                    EscapeKind.DYNAMIC_CODE,
                    EscapeKind.NATIVE_CODE,
                    EscapeKind.PROCESS,
                }
                else EscapeSeverity.HIGH
            )
            self.module._finding(
                node,
                kind,
                severity,
                qualified,
                self.name,
                tainted,
                "tainted graph callback can reach an unmediated capability"
                if tainted
                else "graph callback can reach an unmediated capability",
            )

        is_local = (
            isinstance(node.func, ast.Name) and node.func.id in self.module.functions
        )
        if (
            kind is None
            and tainted
            and not is_local
            and qualified not in _SAFE_CALLS
            and method not in _SAFE_METHODS
        ):
            self.module._finding(
                node,
                EscapeKind.UNKNOWN_CALL,
                EscapeSeverity.HIGH,
                qualified,
                self.name,
                True,
                "tainted value reaches a call whose effects cannot be resolved",
            )

        if _is_tainted_callable(node.func, self.tainted) or (
            qualified in {"builtins.delattr", "builtins.getattr", "builtins.setattr"}
            and tainted
        ):
            self.module._finding(
                node,
                EscapeKind.DYNAMIC_DISPATCH,
                EscapeSeverity.CRITICAL,
                qualified,
                self.name,
                True,
                "graph-controlled value is used as a callable",
            )

        if is_local:
            self.local_calls.add(node.func.id)

        self.generic_visit(node)

    def _is_tainted(self, node: ast.AST) -> bool:
        if isinstance(node, ast.Name):
            return node.id in self.tainted
        if isinstance(node, ast.Constant):
            return False
        if isinstance(node, ast.Attribute):
            return self._is_tainted(node.value)
        if isinstance(node, ast.Subscript):
            return self._is_tainted(node.value) or self._is_tainted(node.slice)
        if isinstance(node, ast.Call):
            return (
                self._is_tainted(node.func)
                or any(self._is_tainted(value) for value in node.args)
                or any(self._is_tainted(item.value) for item in node.keywords)
            )
        return any(self._is_tainted(child) for child in ast.iter_child_nodes(node))

    def _mark_tainted(self, node: ast.AST) -> None:
        for item in ast.walk(node):
            if isinstance(item, ast.Name):
                self.tainted.add(item.id)


class _ToolEffectAnalyzer(ast.NodeVisitor):
    def __init__(
        self,
        module: _ModuleAnalyzer,
        tool_name: str,
        declared: set[str],
        function: ast.FunctionDef | ast.AsyncFunctionDef,
    ) -> None:
        self.module = module
        self.tool_name = tool_name
        self.declared = declared
        self.function = function
        self.local_calls: set[str] = set()

    def analyze(self) -> None:
        for statement in self.function.body:
            self.visit(statement)

    def visit_FunctionDef(self, node: ast.FunctionDef) -> Any:
        return None

    def visit_AsyncFunctionDef(self, node: ast.AsyncFunctionDef) -> Any:
        return None

    def visit_Lambda(self, node: ast.Lambda) -> Any:
        return None

    def visit_Call(self, node: ast.Call) -> Any:
        qualified = self.module._qualified_name(node.func)
        kind = _sink_kind(qualified, _attribute_name(node.func))
        required = _required_effect(kind, qualified, node)
        if required is not None and required not in self.declared:
            self.module._finding(
                node,
                EscapeKind.UNDECLARED_EFFECT,
                EscapeSeverity.CRITICAL,
                qualified,
                self.tool_name,
                any(
                    isinstance(item, ast.Name)
                    and item.id
                    in {argument.arg for argument in _arguments(self.function.args)}
                    for item in ast.walk(node)
                ),
                f"tool reaches {required!r} behavior but does not declare Effect.{required.upper()}",
            )
        if isinstance(node.func, ast.Name) and node.func.id in self.module.functions:
            self.local_calls.add(node.func.id)
        self.generic_visit(node)


def _arguments(arguments: ast.arguments) -> Iterable[ast.arg]:
    yield from arguments.posonlyargs
    yield from arguments.args
    if arguments.vararg is not None:
        yield arguments.vararg
    yield from arguments.kwonlyargs
    if arguments.kwarg is not None:
        yield arguments.kwarg


def _sink_kind(qualified: str, method: str | None) -> EscapeKind | None:
    if qualified in _DYNAMIC_CODE:
        return EscapeKind.DYNAMIC_CODE
    if any(qualified.startswith(prefix) for prefix in _PROCESS_PREFIXES):
        return EscapeKind.PROCESS
    if any(qualified.startswith(prefix) for prefix in _DESERIALIZATION_PREFIXES):
        return EscapeKind.DESERIALIZATION
    if any(qualified.startswith(prefix) for prefix in _NATIVE_PREFIXES):
        return EscapeKind.NATIVE_CODE
    if any(qualified.startswith(prefix) for prefix in _NETWORK_PREFIXES):
        return EscapeKind.NETWORK
    if any(qualified.startswith(prefix) for prefix in _DATABASE_PREFIXES):
        return EscapeKind.DATABASE
    if method in _DIRECT_INVOKE_METHODS:
        return EscapeKind.DIRECT_INVOKE
    if (
        qualified == "builtins.open"
        or qualified in _FILESYSTEM_FUNCTIONS
        or method in _FILESYSTEM_METHODS
    ):
        return EscapeKind.FILESYSTEM
    if method in _DATABASE_METHODS:
        return EscapeKind.DATABASE
    if method in _NETWORK_METHODS and qualified.split(".", 1)[0] in {
        "client",
        "connection",
        "session",
        "socket",
    }:
        return EscapeKind.NETWORK
    return None


def _required_effect(
    kind: EscapeKind | None, qualified: str, call: ast.Call
) -> str | None:
    if kind is EscapeKind.FILESYSTEM:
        method = _attribute_name(call.func)
        if method in {
            "chmod",
            "mkdir",
            "rename",
            "replace",
            "rmdir",
            "symlink_to",
            "touch",
            "unlink",
            "write_bytes",
            "write_text",
            "write",
        }:
            return "write"
        if method == "open" or qualified == "builtins.open":
            mode: ast.expr | None = _keyword(call, "mode")
            if mode is None and len(call.args) >= 2:
                mode = call.args[1]
            if isinstance(mode, ast.Constant) and isinstance(mode.value, str):
                return "write" if set(mode.value) & set("wax+") else "read"
            return "write"
        return "read"
    if kind is EscapeKind.NETWORK:
        return "network"
    if kind is EscapeKind.DATABASE:
        return "write"
    if kind in {
        EscapeKind.DESERIALIZATION,
        EscapeKind.DIRECT_INVOKE,
        EscapeKind.DYNAMIC_CODE,
        EscapeKind.DYNAMIC_DISPATCH,
        EscapeKind.NATIVE_CODE,
        EscapeKind.PROCESS,
    }:
        return "exec"
    return None


def _is_tainted_callable(expression: ast.expr, tainted: set[str]) -> bool:
    if isinstance(expression, ast.Name):
        return expression.id in tainted
    if isinstance(expression, ast.Subscript):
        return any(
            isinstance(item, ast.Name) and item.id in tainted
            for item in ast.walk(expression)
        )
    if isinstance(expression, ast.Call):
        return any(
            isinstance(item, ast.Name) and item.id in tainted
            for item in ast.walk(expression)
        )
    return False


def _attribute_name(expression: ast.expr) -> str | None:
    return expression.attr if isinstance(expression, ast.Attribute) else None


def _decorator_name(decorator: ast.expr) -> str:
    return _expression_name(
        decorator.func if isinstance(decorator, ast.Call) else decorator
    )


def _declared_effects(
    function: ast.FunctionDef | ast.AsyncFunctionDef,
) -> set[str]:
    declared: set[str] = set()
    for decorator in function.decorator_list:
        if not isinstance(decorator, ast.Call) or not _decorator_name(
            decorator
        ).endswith("effects"):
            continue
        for argument in decorator.args:
            name = _expression_name(argument).rsplit(".", 1)[-1].lower()
            if name in {"delegate", "exec", "network", "read", "send", "write"}:
                declared.add(name)
    return declared


def _expression_name(expression: ast.expr) -> str:
    if isinstance(expression, ast.Name):
        return expression.id
    if isinstance(expression, ast.Attribute):
        base = _expression_name(expression.value)
        return f"{base}.{expression.attr}" if base else expression.attr
    if isinstance(expression, ast.Subscript):
        return f"{_expression_name(expression.value)}[...]"
    if isinstance(expression, ast.Lambda):
        return "<lambda>"
    if isinstance(expression, ast.Call):
        return f"{_expression_name(expression.func)}(...)"
    return expression.__class__.__name__


def _keyword(call: ast.Call, name: str) -> ast.expr | None:
    return next((item.value for item in call.keywords if item.arg == name), None)


def _sequence_callbacks(sequence: ast.expr) -> list[ast.expr] | None:
    if not isinstance(sequence, (ast.List, ast.Set, ast.Tuple)):
        return None
    callbacks: list[ast.expr] = []
    for element in sequence.elts:
        if isinstance(element, ast.Tuple) and len(element.elts) == 2:
            callbacks.append(element.elts[1])
        else:
            callbacks.append(element)
    return callbacks


def _is_none(expression: ast.expr) -> bool:
    return isinstance(expression, ast.Constant) and expression.value is None


def _main(argv: Sequence[str] | None = None) -> int:
    parser = argparse.ArgumentParser(
        description="Find Python paths that escape LangGraph tool mediation."
    )
    parser.add_argument("paths", nargs="+", help="Python files or source directories")
    parser.add_argument(
        "--exclude", action="append", default=[], help="file or directory to omit"
    )
    parser.add_argument("--json", action="store_true", help="emit JSON")
    arguments = parser.parse_args(argv)
    report = analyze_source(*arguments.paths, exclude=arguments.exclude)
    if arguments.json:
        print(report.to_json())
    else:
        for finding in report.findings:
            print(
                f"{finding.path}:{finding.line}:{finding.column + 1}: "
                f"{finding.severity.value} {finding.kind.value} "
                f"{finding.symbol}: {finding.message}"
            )
        for error in report.parse_errors:
            print(f"error: {error}")
        print(
            f"{len(report.findings)} escape(s), "
            f"{len(report.parse_errors)} parse error(s)"
        )
    return 0 if report.safe else 1


if __name__ == "__main__":
    raise SystemExit(_main())
