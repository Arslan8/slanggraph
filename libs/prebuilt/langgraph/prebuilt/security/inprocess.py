"""Source admission and grant-bound APIs for language-sandbox tools.

`inprocess` describes execution location only. Admitted bodies execute as a
restricted data program, never by invoking the original Python function. The
coordinator, tool construction, and framework terminals are enforcement code.
"""

from __future__ import annotations

import ast
import asyncio
import inspect
import os
import stat
import struct
import sys
import textwrap
from collections.abc import Mapping
from contextvars import ContextVar
from functools import partial
from pathlib import Path
from types import CellType, CodeType, FunctionType
from typing import TYPE_CHECKING

from langchain_core.tools import BaseTool, StructuredTool

from langgraph.prebuilt.security._language_sandbox import LanguageProgram
from langgraph.prebuilt.security._pinned_file import open_path_descriptor
from langgraph.prebuilt.security.errors import SecurityConfigurationError
from langgraph.prebuilt.security.execution import HostExecutionDenied
from langgraph.prebuilt.security.language_verification import TerminalContract
from langgraph.prebuilt.security.manifest_consistency import (
    ManifestOperation,
    check_manifest_consistency,
    format_manifest_diagnostics,
)
from langgraph.prebuilt.security.mediators.contracts import client_binding
from langgraph.prebuilt.security.object_policy import ObjectGrant, SecurityManifest

if TYPE_CHECKING:
    from langgraph.prebuilt.analysis.static_flow import StaticFlowPolicy


_active_grant: ContextVar[ObjectGrant | None] = ContextVar(
    "inprocess_object_grant", default=None
)


def read_text(path: str) -> str:
    """Read a grant-named regular file through a pinned native descriptor.

    The policy names a canonical path, not a historical inode or content
    snapshot. Binding selects that path's object at this operation. Linux
    `openat2`, or Darwin's descriptor-relative `O_SEARCH | O_NOFOLLOW` walk,
    rejects symlinks in every canonical path component; subsequent
    pathname replacement cannot redirect the descriptor read. Unsupported
    platforms or descriptor mechanisms fail closed without a pathname fallback.
    """
    if type(path) is not str:
        raise HostExecutionDenied("inprocess:resource_must_be_string")
    grant = _active_grant.get()
    if grant is None:
        raise HostExecutionDenied("inprocess:resource_not_granted")
    if sys.platform not in {"linux", "darwin"}:
        raise HostExecutionDenied("inprocess:descriptor_read_unsupported")
    try:
        canonical = str(Path(path).resolve(strict=True))
    except (OSError, RuntimeError, ValueError) as exc:
        raise HostExecutionDenied("inprocess:resource_unavailable") from exc
    if not any(
        line.class_name == "fs"
        and line.operation == "read"
        and line.selector == canonical
        for line in grant.lines
    ):
        raise HostExecutionDenied("inprocess:resource_not_granted")
    pinned = None
    readable = None
    try:
        pinned = open_path_descriptor(canonical, no_symlinks=True)
        identity = os.fstat(pinned)
        if not stat.S_ISREG(identity.st_mode):
            raise HostExecutionDenied("inprocess:regular_file_required")
        # This path contains only our live kernel-assigned descriptor number.
        # It never re-resolves the candidate's pathname. Procfs and the native
        # descriptor API remain host primitives, unavailable to the admitted IR.
        readable = (
            os.dup(pinned)
            if sys.platform == "darwin"
            else os.open(
                f"/proc/self/fd/{pinned}",
                os.O_RDONLY | os.O_CLOEXEC | os.O_NONBLOCK | os.O_NOCTTY,
            )
        )
        opened = os.fstat(readable)
        if not stat.S_ISREG(opened.st_mode) or (
            opened.st_dev,
            opened.st_ino,
        ) != (identity.st_dev, identity.st_ino):
            raise HostExecutionDenied("inprocess:resource_identity_changed")
        # Keep ownership explicit even if text-wrapper creation or decoding
        # fails. Closing the wrapper cannot close/recycle the underlying fd.
        with os.fdopen(readable, "r", encoding="utf-8", closefd=False) as stream:
            return stream.read()
    except HostExecutionDenied:
        raise
    except UnicodeDecodeError:
        # The decoder's exception owns the original file bytes. Leave its
        # handler before raising so the public failure has no implicit context
        # containing those bytes ("from None" alone only hides that context).
        pass
    except OSError as exc:
        raise HostExecutionDenied("inprocess:descriptor_read_unavailable") from exc
    finally:
        try:
            if readable is not None:
                os.close(readable)
        finally:
            if pinned is not None:
                os.close(pinned)
    raise HostExecutionDenied("inprocess:invalid_text_encoding")


_READ_TEXT_CODE = read_text.__code__


def _code_identity(code: CodeType) -> tuple:
    """Compare loaded code using native data without candidate equality hooks."""
    budget = 10_000

    def constant(value, depth):
        nonlocal budget
        budget -= 1
        if budget < 0 or depth > 64:
            raise SecurityConfigurationError("language_sandbox:code_budget")
        kind = type(value)
        if value is None:
            return ("none",)
        if value is Ellipsis:
            return ("ellipsis",)
        if kind is str:
            return ("str", value)
        if kind is bytes:
            return ("bytes", value)
        if kind is bool:
            return ("bool", value)
        if kind is int:
            return ("int", value)
        if kind is float:
            return ("float", struct.pack("!d", value))
        if kind is complex:
            return ("complex", struct.pack("!dd", value.real, value.imag))
        if kind is tuple:
            return ("tuple", tuple(constant(item, depth + 1) for item in value))
        if kind is frozenset:
            return ("frozenset", frozenset(constant(item, depth + 1) for item in value))
        if kind is CodeType:
            return ("code", code_key(value, depth + 1))
        raise SecurityConfigurationError("language_sandbox:non_native_code_constant")

    def code_key(value, depth):
        if type(value) is not CodeType or type(value.co_filename) is not str:
            raise SecurityConfigurationError("language_sandbox:invalid_code_metadata")
        return tuple(
            constant(getattr(value, name, None), depth + 1)
            for name in (
                "co_code",
                "co_consts",
                "co_names",
                "co_varnames",
                "co_argcount",
                "co_posonlyargcount",
                "co_kwonlyargcount",
                "co_flags",
                "co_freevars",
                "co_cellvars",
                "co_name",
                "co_exceptiontable",
            )
        )

    return code_key(code, 0)


def _native_function_metadata(function: FunctionType) -> None:
    """Refuse foreign containers before reading function globals or defaults."""
    if type(function.__name__) is not str or type(function.__globals__) is not dict:
        raise SecurityConfigurationError("language_sandbox:invalid_function_metadata")
    if any(type(key) is not str for key in function.__globals__):
        raise SecurityConfigurationError("language_sandbox:invalid_global_key")
    positional = function.__defaults__
    if positional is not None and type(positional) is not tuple:
        raise SecurityConfigurationError("language_sandbox:invalid_defaults")
    keywords = function.__kwdefaults__
    if keywords is not None:
        if type(keywords) is not dict or any(type(key) is not str for key in keywords):
            raise SecurityConfigurationError("language_sandbox:invalid_defaults")


def _freeze_terminal(function: FunctionType) -> FunctionType:
    # Snapshot reviewed terminal code and bindings. Candidate code never receives
    # this function, its globals, a client instance, or a privileged return object.
    return FunctionType(
        function.__code__,
        dict(function.__globals__),
        function.__name__,
        function.__defaults__,
        tuple(CellType(item.cell_contents) for item in function.__closure__)
        if function.__closure__
        else None,
    )


class ManifestAdmission:
    """Check actual tool bodies and reject changes to admitted callables/APIs."""

    def __init__(
        self,
        tool: BaseTool,
        manifest: SecurityManifest,
        *,
        static_flow: StaticFlowPolicy | None = None,
    ) -> None:
        # Subclasses can override invocation and execute an unchecked body.
        if type(tool) is not StructuredTool:
            raise SecurityConfigurationError(
                "manifest_consistency: requires a standard StructuredTool"
            )
        self.tool = tool
        self.bindings = []
        self.reports = []
        self.flow_reports = []
        self.defaults = []
        self.clients = []
        self.programs = {}
        self.program_sources = {}
        self.terminal_codes = []
        for attribute in ("func", "coroutine"):
            function = getattr(tool, attribute)
            if function is None:
                continue
            if type(function) is not FunctionType or hasattr(function, "__wrapped__"):
                raise SecurityConfigurationError(
                    "manifest_consistency: wrapped or non-function body is unsupported"
                )
            _native_function_metadata(function)
            loaded_code = _code_identity(function.__code__)
            if function.__closure__:
                raise SecurityConfigurationError(
                    "manifest_consistency: captured closure state is unsupported"
                )
            try:
                # Passing the code object avoids inspect's automatic unwrapping.
                source = textwrap.dedent(inspect.getsource(function.__code__))
            except (OSError, TypeError) as exc:
                raise SecurityConfigurationError(
                    "manifest_consistency: source unavailable"
                ) from exc
            # Source may have changed on disk since import. A report about that
            # new text must not admit the previously loaded executable body.
            tree = ast.parse(source)
            # Python can choose different method-call bytecode based on the
            # complete compilation unit. Recompile that unit without executing
            # it, and bind the extracted body to the same source location.
            try:
                module_tree = ast.parse(Path(function.__code__.co_filename).read_text())
                compiled = compile(
                    module_tree,
                    function.__code__.co_filename,
                    "exec",
                    dont_inherit=True,
                )
            except (OSError, SyntaxError) as exc:
                raise SecurityConfigurationError(
                    "manifest_consistency: source unavailable"
                ) from exc
            entries = [
                node
                for node in ast.walk(module_tree)
                if isinstance(node, (ast.FunctionDef, ast.AsyncFunctionDef))
                and node.name == function.__name__
                and min([node.lineno, *(item.lineno for item in node.decorator_list)])
                == function.__code__.co_firstlineno
            ]
            candidates = []
            pending = [compiled]
            while pending:
                code = pending.pop()
                if (
                    code.co_name == function.__name__
                    and code.co_firstlineno == function.__code__.co_firstlineno
                ):
                    candidates.append(code)
                pending.extend(
                    value for value in code.co_consts if isinstance(value, CodeType)
                )
            if (
                len(entries) != 1
                or len(tree.body) != 1
                or ast.dump(entries[0]) != ast.dump(tree.body[0])
                or len(candidates) != 1
            ) or _code_identity(candidates[0]) != loaded_code:
                raise SecurityConfigurationError(
                    "manifest_consistency: source does not match loaded code"
                )
            defaults = (
                *(function.__defaults__ or ()),
                *(function.__kwdefaults__ or {}).values(),
            )
            if any(type(value) is not str for value in defaults):
                raise SecurityConfigurationError(
                    "manifest_consistency: defaults must be inert strings"
                )
            # Only framework resource APIs are terminals, not arbitrary helpers
            # supplied by the tool author. Bind their actual identities as well
            # as their source spelling. Other calls remain unknown.
            terminals = {
                name: value
                for name, value in function.__globals__.items()
                if value is read_text and name in function.__code__.co_names
            }
            if terminals and read_text.__code__ is not _READ_TEXT_CODE:
                raise SecurityConfigurationError("language_sandbox:monitor_changed")
            execution_terminals = {
                name: _freeze_terminal(value) for name, value in terminals.items()
            }
            terminal_contracts = {
                name: TerminalContract((("path", "str"),), frozenset({"str"}))
                for name in terminals
            }
            self.terminal_codes.extend(
                (value, value.__code__) for value in terminals.values()
            )
            operations = tuple(
                ManifestOperation(name, "fs", "read", "path") for name in terminals
            )
            clients = {}
            for name in function.__code__.co_names:
                value = function.__globals__.get(name)
                binding = client_binding(value)
                if binding is not None:
                    binding.validate()
                    clients[name] = value
                    self.clients.append((function, name, binding))
                    execution_terminals.update(
                        {
                            f"{name}.{method}": partial(_freeze_terminal(target), value)
                            for method, target in binding.methods.items()
                        }
                    )
                    terminal_contracts.update(
                        {
                            model.target: TerminalContract(
                                tuple(zip(model.parameters, model.parameter_types)),
                                frozenset({model.result_type})
                                if model.result_type
                                in {"str", "int", "float", "bool", "NoneType", "dict"}
                                else frozenset(
                                    {"str", "int", "float", "bool", "NoneType", "dict"}
                                ),
                            )
                            for model in binding.models(name)
                        }
                    )
            report = check_manifest_consistency(
                source,
                manifest,
                tool_name=tool.name,
                function=function.__name__,
                operations=operations,
                clients=clients,
            )
            if not report["consistent"]:
                diagnostic = format_manifest_diagnostics(
                    report,
                    source_name=f"{function.__code__.co_filename} ({function.__name__} body)",
                )
                raise SecurityConfigurationError(
                    f"manifest_consistency:{report['status']}:{tool.name}:\n{diagnostic}"
                )
            if static_flow is not None:
                self.flow_reports.append(
                    static_flow.require(
                        source,
                        manifest,
                        tool_name=tool.name,
                        function=function.__name__,
                        operations=operations,
                        clients=clients,
                    )
                )
            self.bindings.append((attribute, function, function.__code__, terminals))
            self.defaults.append(
                (function, function.__defaults__, dict(function.__kwdefaults__ or {}))
            )
            self.reports.append(report)
            self.programs[attribute] = LanguageProgram.lower(
                tree.body[0],
                execution_terminals,
                function.__defaults__ or (),
                function.__kwdefaults__ or {},
                contracts=terminal_contracts,
            )
            self.program_sources[attribute] = report["source_sha256"]
        if not self.bindings:
            raise SecurityConfigurationError("manifest_consistency: missing tool body")
        self.functions = (tool.func, tool.coroutine)

    def language_proofs(self) -> dict[str, dict]:
        """Recompute program derivations; these do not certify host composition."""
        self.validate()
        return {
            name: {**program.proof(), "source_sha256": self.program_sources[name]}
            for name, program in self.programs.items()
        }

    def validate(self) -> None:
        if (
            self.tool.func is not self.functions[0]
            or self.tool.coroutine is not self.functions[1]
        ):
            raise HostExecutionDenied("manifest_consistency:tool_changed")
        for _, function, _, _ in self.bindings:
            try:
                _native_function_metadata(function)
            except SecurityConfigurationError as exc:
                raise HostExecutionDenied(
                    "manifest_consistency:metadata_changed"
                ) from exc
        if any(function.__code__ is not code for function, code in self.terminal_codes):
            raise HostExecutionDenied("language_sandbox:monitor_changed")
        for function, name, binding in self.clients:
            if function.__globals__.get(name) is not binding.client:
                raise HostExecutionDenied("manifest_consistency:client_changed")
            try:
                binding.validate()
            except PermissionError as exc:
                raise HostExecutionDenied(
                    "manifest_consistency:client_method_changed"
                ) from exc
        for _, function, code, terminals in self.bindings:
            if function.__code__ is not code or any(
                function.__globals__.get(name) is not value
                for name, value in terminals.items()
            ):
                raise HostExecutionDenied("manifest_consistency:binding_changed")
        for function, positional, keywords in self.defaults:
            current = function.__kwdefaults__ or {}
            if (
                function.__defaults__ is not positional
                or current.keys() != keywords.keys()
                or any(current[name] is not value for name, value in keywords.items())
            ):
                raise HostExecutionDenied("manifest_consistency:defaults_changed")

    def invoke(self, arguments: Mapping[str, object]) -> object:
        """Interpret the admitted program without invoking Python tool code."""
        self.validate()
        program = self.programs.get("func")
        if program is None:
            raise HostExecutionDenied(
                "manifest_consistency:async_tool_requires_ainvoke"
            )
        self._validate_arguments(arguments)
        return program.invoke(dict(arguments))

    async def ainvoke(self, arguments: Mapping[str, object]) -> object:
        self.validate()
        self._validate_arguments(arguments)
        program = self.programs.get("coroutine") or self.programs.get("func")
        pending = asyncio.create_task(
            asyncio.to_thread(program.invoke, dict(arguments))
        )
        cancelled = False
        # Cancellation must not release the resource scope while a synchronous
        # mediated terminal is still running in the worker thread.
        while True:
            try:
                result = await asyncio.shield(pending)
                break
            except asyncio.CancelledError:
                cancelled = True
                if pending.done():
                    # Retrieve terminal exceptions without publishing a result.
                    await asyncio.gather(pending, return_exceptions=True)
                    raise
            except BaseException:
                if cancelled:
                    raise asyncio.CancelledError from None
                raise
        if cancelled:
            raise asyncio.CancelledError
        return result

    @staticmethod
    def _validate_arguments(arguments: Mapping[str, object]) -> None:
        if type(arguments) is not dict or any(
            type(key) is not str or type(value) is not str
            for key, value in arguments.items()
        ):
            raise HostExecutionDenied("manifest_consistency:arguments_must_be_strings")
