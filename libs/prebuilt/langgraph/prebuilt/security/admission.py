"""Closed admission of secured graph bodies by exact type identity.

Every node and branch of a graph compiled with `closed_admission=True` must
reference an admitted execution descriptor: an exact validated language IR
program with closed terminal IDs, an exact framework dispatch primitive with no
arbitrary callback payload, a validated native deployment handled by a concrete
confined host, an exact allowlisted chat-model class (a modeled LLM call whose
capability the policy decides at the model-invocation hook), an exact
framework branch function, or a trusted application node the deployer declared
by exact name in `SecurityConfig.trusted_application_nodes`. Undeclared
ordinary callables, arbitrary `Runnable` subclasses, module-name trust,
metadata promotion and wrappers that merely contain a `ToolNode` are refused.

Trusted application nodes follow advisor decision D11: the developer's own node
functions are trusted code, like the framework. Admission never infers that
kind; it binds the declared function's identity (node name, module, qualname
and loaded code) into the inventory so a swapped function is refused, and makes
no claim that the code is safe. Tool implementations and generated code stay
contained: a declared name whose body is a `ToolNode` is refused, and a
declared allowlisted model keeps its `MODEL_CALL` kind and hook.

Conditional-edge functions written by the developer are application code too.
A branch whose inventory name `<source>:branch:<branch_name>` is a member of
`SecurityConfig.trusted_application_branches` is admitted as
`TRUSTED_APPLICATION_BRANCH`, a kind distinct from `FRAMEWORK_BRANCH` so the
evidence never presents developer code as a pinned framework function.

Admission reads candidate objects only after an exact-type check (`type(x) is`)
on framework classes whose storage is native. It never calls `isinstance`,
`getattr` with defaults, `get_name`, `inspect.signature` or schema construction
on a candidate before that check, so a refused body runs no protocol here.
Effects incurred earlier by graph construction (`StateGraph.add_node` naming,
type-hint and signature inspection) are outside this module's control.

Refusals are plain `PermissionError` values carrying one of the registered
codes: `admission:unsupported_node_body`, `admission:unsupported_branch`,
`admission:descriptor_changed`, `admission:unsupported_async` and
`admission:closed_admission_required`.
"""

from __future__ import annotations

import hashlib
import json
import struct
from dataclasses import dataclass, field
from enum import Enum
from functools import partial
from inspect import CO_COROUTINE, Parameter
from pathlib import PosixPath, WindowsPath
from types import CodeType, FunctionType, MappingProxyType, MethodType
from typing import Any

UNSUPPORTED_NODE_BODY = "admission:unsupported_node_body"
UNSUPPORTED_BRANCH = "admission:unsupported_branch"
DESCRIPTOR_CHANGED = "admission:descriptor_changed"
UNSUPPORTED_ASYNC = "admission:unsupported_async"
CLOSED_ADMISSION_REQUIRED = "admission:closed_admission_required"

_SHA256_LENGTH = 64
_HEX = frozenset("0123456789abcdef")
_FRAMEWORK_BRANCHES: tuple[tuple[str, str], ...] = (
    ("langgraph.prebuilt.tool_node", "tools_condition"),
)
_pinned_branches: dict[str, tuple[FunctionType, tuple]] = {}
# Chat-model classes a closed graph may call as a `MODEL_CALL` node, matched by
# exact type identity. Optional provider packages are imported lazily; an
# absent package only means its class is not allowlisted.
_MODEL_CLASSES: tuple[tuple[str, str], ...] = (
    ("langchain_core.language_models.fake_chat_models", "FakeListChatModel"),
    ("langchain_core.language_models.fake_chat_models", "GenericFakeChatModel"),
    ("langchain_openai", "ChatOpenAI"),
    ("langchain_ollama", "ChatOllama"),
)
# Declared endpoint fields projected into a model descriptor when they are
# exact `str` (or `None`); any other value refuses.
_MODEL_ENDPOINT_FIELDS: tuple[str, ...] = (
    "model",
    "model_name",
    "base_url",
    "openai_api_base",
    "openai_organization",
    "openai_proxy",
)
# Model fields the chat-model runtime would call back into; each must be unset.
_MODEL_CALLBACK_FIELDS: tuple[str, ...] = (
    "callbacks",
    "callback_manager",
    "custom_get_token_ids",
    "rate_limiter",
)
_pinned_models: dict[str, Any] = {}


class AdmittedKind(str, Enum):
    """Closed set of execution descriptor kinds a secured graph may reference."""

    LANGUAGE_PROGRAM = "language_program"
    TOOL_NODE = "tool_node"
    NATIVE_DEPLOYMENT = "native_deployment"
    FRAMEWORK_BRANCH = "framework_branch"
    MODEL_CALL = "model_call"
    TRUSTED_APPLICATION = "trusted_application"
    TRUSTED_APPLICATION_BRANCH = "trusted_application_branch"


@dataclass(frozen=True, slots=True)
class AdmittedDescriptor:
    """One admitted graph entry bound to its exact captured implementation.

    `identity` is a SHA-256 hex digest over the captured implementation's exact
    program, loaded-code or deployment data; `source_sha256` digests the
    underlying source/artifact digests. `implementation` is the exact captured
    object graph and takes no part in equality.
    """

    kind: AdmittedKind
    name: str
    identity: str
    implementation: Any = field(compare=False, repr=False)
    source_sha256: str = ""


@dataclass(frozen=True, slots=True)
class _CapturedToolNode:
    """Exact `ToolNode`, its dispatch path and its registered tools."""

    node: Any
    executor: Any
    dispatcher: Any
    admission: Any
    tools: tuple[tuple[str, Any], ...]


@dataclass(frozen=True, slots=True)
class _CapturedModel:
    """Exact allowlisted chat model and its class-level `invoke`/`ainvoke`.

    `node` is the model object itself; `call`/`acall` are the class functions
    resolved through the exact class at admission, never instance attributes.
    """

    node: Any
    registry_id: str
    model_class: Any
    call: FunctionType
    acall: FunctionType


@dataclass(frozen=True, slots=True)
class _CapturedApplication:
    """Declared trusted application node and its function pinned at admission.

    `node` is the exact `RunnableCallable` `StateGraph.add_node` built around
    the developer's function; `function` is that function object, captured so
    dispatch never reads the mutable `func`/`afunc` attributes. `accepts` is the
    framework's keyword-injection plan (`func_accepts`) as of admission and
    `code` the native identity of the loaded code. This binds the inventory;
    the code is trusted per D11, not contained.
    """

    name: str
    node: Any
    function: FunctionType
    is_async: bool
    accepts: tuple[tuple[str, str, Any], ...]
    code: tuple


@dataclass(frozen=True, slots=True)
class _CapturedTrustedBranch:
    """Declared trusted conditional edge and its function pinned at admission.

    `branch` is the exact `BranchSpec`, `path` its exact `RunnableCallable`
    and `function` the developer's plain synchronous function (a closure or a
    lambda), captured so dispatch never reads `path.func`. `code` is the native
    identity of its loaded code. Trusted per D11; identity is bound, behavior
    is not.
    """

    name: str
    branch: Any
    path: Any
    function: FunctionType
    code: tuple


@dataclass(frozen=True, slots=True)
class _CapturedBranch:
    """Exact `BranchSpec`, its `RunnableCallable` and pinned framework function."""

    branch: Any
    path: Any
    function: FunctionType
    registry_id: str


def admit_node(name: str, runnable: Any, *, config: Any) -> AdmittedDescriptor:
    """Admit one graph node body or refuse it before any candidate protocol runs.

    An instance of an allowlisted chat-model class (exact type identity, see
    `_MODEL_CLASSES`) is admitted as `MODEL_CALL`. Otherwise only an exact
    `ToolNode` whose dispatch path is `config.host_executor` with a concrete
    confined route is admitted. The node must have no pre/post tool call
    wrappers, no injected arguments and exact `StructuredTool` schemas. A plain
    function that calls a model internally is an ordinary callable and refuses
    unless the deployer declared its node name trusted.

    A node whose exact `str` name is a member of the exact frozenset
    `config.trusted_application_nodes` is admitted as `TRUSTED_APPLICATION`
    (see `_capture_application`). The model allowlist is consulted first, so a
    declared model is never downgraded from `MODEL_CALL`. A declared `ToolNode`
    is refused with `admission:unsupported_node_body`: its exact type is not
    `RunnableCallable`, and refusing (rather than silently keeping the tool
    kind) surfaces a declaration that contradicts D11, under which tool
    implementations are never trusted application code.
    """
    _require_name(name, UNSUPPORTED_NODE_BODY)
    from langgraph.prebuilt.tool_node import ToolNode

    registry_id = _allowlisted_model(type(runnable))
    if registry_id is not None:
        return _admit_model_call(name, runnable, registry_id)
    if _declared_trusted(name, config):
        return _admit_trusted_application(name, runnable)
    if type(runnable) is not ToolNode:
        raise PermissionError(UNSUPPORTED_NODE_BODY)
    captured = _capture_tool_node(runnable, config)
    kind, identity, source, _ = _tool_node_state(captured, installed=False)
    return AdmittedDescriptor(kind, name, identity, captured, source)


def admit_branch(name: str, branch: Any, *, config: Any) -> AdmittedDescriptor:
    """Admit one conditional-edge `BranchSpec` or refuse it.

    The path must be an exact `RunnableCallable` whose `func` is a pinned
    framework branch function and whose `afunc` is the framework's own executor
    shim for that function. An asynchronous branch body is refused with
    `admission:unsupported_async`; everything else outside the registry with
    `admission:unsupported_branch`.

    A branch whose exact `name` (`<source>:branch:<branch_name>`) is a member
    of the exact frozenset `config.trusted_application_branches` is admitted
    as `TRUSTED_APPLICATION_BRANCH` instead (see `_capture_trusted_branch`).
    """
    _require_name(name, UNSUPPORTED_BRANCH)
    _require_config(config, UNSUPPORTED_BRANCH)
    from langgraph.graph._branch import BranchSpec

    if _declared_trusted_branch(name, config):
        return _admit_trusted_branch(name, branch)
    if type(branch) is not BranchSpec:
        raise PermissionError(UNSUPPORTED_BRANCH)
    captured = _capture_branch(branch)
    identity, source, _ = _branch_state(captured)
    return AdmittedDescriptor(
        AdmittedKind.FRAMEWORK_BRANCH, name, identity, captured, source
    )


def recheck(descriptor: AdmittedDescriptor) -> None:
    """Recompute the identity from the captured implementation; refuse drift.

    The captured links (node, executor, dispatcher, admitted programs, pinned
    branch function and routing map) are re-read through exact-type checks.
    Any replaced link, program, artifact digest or loaded code raises
    `admission:descriptor_changed`.
    """
    kind, identity, source = _current_state(descriptor)
    if (
        kind is not descriptor.kind
        or identity != descriptor.identity
        or source != descriptor.source_sha256
    ):
        raise PermissionError(DESCRIPTOR_CHANGED)


def describe(descriptor: AdmittedDescriptor) -> dict[str, Any]:
    """Return an inert data projection of one admitted descriptor for evidence."""
    if type(descriptor) is not AdmittedDescriptor:
        raise PermissionError(DESCRIPTOR_CHANGED)
    recheck(descriptor)
    implementation = descriptor.implementation
    if type(implementation) is _CapturedToolNode:
        _, _, _, details = _tool_node_state(implementation, installed=True)
    elif type(implementation) is _CapturedModel:
        _, _, details = _model_state(implementation)
    elif type(implementation) is _CapturedApplication:
        _, _, details = _application_state(implementation)
    elif type(implementation) is _CapturedTrustedBranch:
        _, _, details = _trusted_branch_state(implementation)
    else:
        _, _, details = _branch_state(implementation)
    return {
        "kind": descriptor.kind.value,
        "name": descriptor.name,
        "identity": descriptor.identity,
        "source_sha256": descriptor.source_sha256,
        "details": details,
    }


def _current_state(descriptor: Any) -> tuple[AdmittedKind, str, str]:
    if type(descriptor) is not AdmittedDescriptor:
        raise PermissionError(DESCRIPTOR_CHANGED)
    implementation = descriptor.implementation
    try:
        if type(implementation) is _CapturedToolNode:
            kind, identity, source, _ = _tool_node_state(implementation, installed=True)
            return kind, identity, source
        if type(implementation) is _CapturedBranch:
            identity, source, _ = _branch_state(implementation)
            return AdmittedKind.FRAMEWORK_BRANCH, identity, source
        if type(implementation) is _CapturedModel:
            identity, source, _ = _model_state(implementation)
            return AdmittedKind.MODEL_CALL, identity, source
        if type(implementation) is _CapturedApplication:
            if implementation.name != descriptor.name:
                raise PermissionError(DESCRIPTOR_CHANGED)
            identity, source, _ = _application_state(implementation)
            return AdmittedKind.TRUSTED_APPLICATION, identity, source
        if type(implementation) is _CapturedTrustedBranch:
            if implementation.name != descriptor.name:
                raise PermissionError(DESCRIPTOR_CHANGED)
            identity, source, _ = _trusted_branch_state(implementation)
            return AdmittedKind.TRUSTED_APPLICATION_BRANCH, identity, source
    except PermissionError:
        pass
    raise PermissionError(DESCRIPTOR_CHANGED)


def _require_name(name: Any, code: str) -> None:
    if type(name) is not str or not name:
        raise PermissionError(code)


def _require_config(config: Any, code: str) -> Any:
    from langgraph.prebuilt.security.config import SecurityConfig

    if type(config) is not SecurityConfig:
        raise PermissionError(code)
    return config


def _declared_application_nodes(config: Any) -> frozenset[str]:
    """Return the deployer's exact frozenset of trusted application node names."""
    config = _require_config(config, UNSUPPORTED_NODE_BODY)
    declared = config.trusted_application_nodes
    if type(declared) is not frozenset:
        raise PermissionError(UNSUPPORTED_NODE_BODY)
    for item in declared:
        if type(item) is not str:
            raise PermissionError(UNSUPPORTED_NODE_BODY)
    return declared


def _declared_trusted(name: str, config: Any) -> bool:
    """Whether `name` is declared trusted: exact frozenset membership only."""
    declared = _declared_application_nodes(config)
    return name in declared


def _declared_application_branches(config: Any) -> frozenset[str]:
    """Return the deployer's exact frozenset of trusted branch names."""
    config = _require_config(config, UNSUPPORTED_BRANCH)
    declared = config.trusted_application_branches
    if type(declared) is not frozenset:
        raise PermissionError(UNSUPPORTED_BRANCH)
    for item in declared:
        if type(item) is not str:
            raise PermissionError(UNSUPPORTED_BRANCH)
    return declared


def _declared_trusted_branch(name: str, config: Any) -> bool:
    """Whether branch `name` is declared trusted: exact frozenset membership."""
    declared = _declared_application_branches(config)
    return name in declared


def _bind_declared_branches(config: Any, inventory: Any) -> None:
    """Require every declared branch name to be an admitted trusted branch."""
    declared = _declared_application_branches(config)
    for name in declared:
        descriptor = inventory.get(name)
        if type(descriptor) is not AdmittedDescriptor:
            raise PermissionError(UNSUPPORTED_BRANCH)
        if descriptor.kind is not AdmittedKind.TRUSTED_APPLICATION_BRANCH:
            raise PermissionError(UNSUPPORTED_BRANCH)


def _admit_trusted_branch(name: str, branch: Any) -> AdmittedDescriptor:
    captured = _capture_trusted_branch(name, branch)
    identity, source, _ = _trusted_branch_state(captured)
    return AdmittedDescriptor(
        AdmittedKind.TRUSTED_APPLICATION_BRANCH, name, identity, captured, source
    )


def _capture_trusted_branch(name: str, branch: Any) -> _CapturedTrustedBranch:
    """Capture a declared branch's exact path and its plain synchronous function.

    The branch must be an exact `BranchSpec` whose `path` is the exact
    `RunnableCallable` that `add_conditional_edges` builds for a plain function
    or lambda: `func` a plain non-coroutine function, `afunc` the framework's
    `run_in_executor` shim for it, no bound kwargs, no argument explosion and
    no injected framework keywords. A pinned framework branch keeps its
    stronger `FRAMEWORK_BRANCH` kind, so declaring it refuses. Everything
    else refuses with `admission:unsupported_branch`.
    """
    from langgraph._internal._runnable import RunnableCallable
    from langgraph.graph._branch import BranchSpec

    if type(branch) is not BranchSpec:
        raise PermissionError(UNSUPPORTED_BRANCH)
    path = branch.path
    if type(path) is not RunnableCallable:
        raise PermissionError(UNSUPPORTED_BRANCH)
    missing = False
    try:
        func = path.func
        afunc = path.afunc
        bound = path.kwargs
        explode = path.explode_args
        accepts = path.func_accepts
    except AttributeError:
        missing = True
    if missing:
        raise PermissionError(UNSUPPORTED_BRANCH)
    if type(func) is not FunctionType or _is_coroutine(func):
        raise PermissionError(UNSUPPORTED_BRANCH)
    if not _is_executor_shim(afunc, func):
        raise PermissionError(UNSUPPORTED_BRANCH)
    if type(bound) is not dict or bound or explode is not False:
        raise PermissionError(UNSUPPORTED_BRANCH)
    if type(accepts) is not dict or accepts:
        raise PermissionError(UNSUPPORTED_BRANCH)
    if _pinned_branch_id(func) is not None:
        raise PermissionError(UNSUPPORTED_BRANCH)
    code = _application_code(func, UNSUPPORTED_BRANCH)
    return _CapturedTrustedBranch(name, branch, path, func, code)


def _trusted_branch_state(
    captured: _CapturedTrustedBranch,
) -> tuple[str, str, dict[str, Any]]:
    """Re-read a trusted branch and return identity, source digest and details.

    The identity is a SHA-256 digest over the branch name, the function's
    module and qualname, its loaded-code identity and the exact routing map
    (`ends`). A replaced `path`, `func` or `afunc`, a reassigned `__code__`,
    bound kwargs, injected keywords or a changed routing map raise
    `admission:descriptor_changed`.
    """
    from langgraph._internal._runnable import RunnableCallable
    from langgraph.graph._branch import BranchSpec

    branch = captured.branch
    path = captured.path
    function = captured.function
    if (
        type(branch) is not BranchSpec
        or type(path) is not RunnableCallable
        or type(function) is not FunctionType
    ):
        raise PermissionError(DESCRIPTOR_CHANGED)
    if branch.path is not path:
        raise PermissionError(DESCRIPTOR_CHANGED)
    missing = False
    try:
        func = path.func
        afunc = path.afunc
        bound = path.kwargs
        explode = path.explode_args
        accepts = path.func_accepts
    except AttributeError:
        missing = True
    if missing:
        raise PermissionError(DESCRIPTOR_CHANGED)
    if func is not function or not _is_executor_shim(afunc, function):
        raise PermissionError(DESCRIPTOR_CHANGED)
    if type(bound) is not dict or bound or explode is not False:
        raise PermissionError(DESCRIPTOR_CHANGED)
    if type(accepts) is not dict or accepts:
        raise PermissionError(DESCRIPTOR_CHANGED)
    code = _application_code(function, DESCRIPTOR_CHANGED)
    if code != captured.code:
        raise PermissionError(DESCRIPTOR_CHANGED)
    module = function.__module__
    qualname = function.__qualname__
    if type(module) is not str or type(qualname) is not str:
        raise PermissionError(DESCRIPTOR_CHANGED)
    ends = branch.ends
    if ends is not None:
        if type(ends) is not dict or any(
            type(key) is not str or type(value) is not str
            for key, value in ends.items()
        ):
            raise PermissionError(DESCRIPTOR_CHANGED)
        ends = sorted(ends.items())
    code_sha256 = hashlib.sha256(_encode(code).encode()).hexdigest()
    details = {
        "kind": AdmittedKind.TRUSTED_APPLICATION_BRANCH.value,
        "name": captured.name,
        "module": module,
        "qualname": qualname,
        "code_sha256": code_sha256,
        "ends": [list(item) for item in ends] if ends is not None else None,
    }
    return _digest(details), code_sha256, details


def _admit_trusted_application(name: str, runnable: Any) -> AdmittedDescriptor:
    captured = _capture_application(name, runnable)
    identity, source, _ = _application_state(captured)
    return AdmittedDescriptor(
        AdmittedKind.TRUSTED_APPLICATION, name, identity, captured, source
    )


def _capture_application(name: str, node: Any) -> _CapturedApplication:
    """Capture a declared node's exact `RunnableCallable` and its plain function.

    Only the shape `StateGraph.add_node` builds for a plain function is
    accepted: an exact `RunnableCallable` with no bound kwargs and no argument
    explosion whose `func` is a plain function and `afunc` the framework's
    `run_in_executor` shim for it, or whose `func` is `None` and `afunc` a
    plain coroutine function. Anything else (a `ToolNode`, another `Runnable`,
    a bound method, a partial, a generator) refuses with
    `admission:unsupported_node_body`.
    """
    from langgraph._internal._runnable import RunnableCallable

    if type(node) is not RunnableCallable:
        raise PermissionError(UNSUPPORTED_NODE_BODY)
    missing = False
    try:
        func = node.func
        afunc = node.afunc
        bound = node.kwargs
        explode = node.explode_args
        accepts = node.func_accepts
    except AttributeError:
        missing = True
    if missing:
        raise PermissionError(UNSUPPORTED_NODE_BODY)
    if type(bound) is not dict or bound or explode is not False:
        raise PermissionError(UNSUPPORTED_NODE_BODY)
    if type(accepts) is not dict:
        raise PermissionError(UNSUPPORTED_NODE_BODY)
    if func is None:
        if type(afunc) is not FunctionType or not _is_coroutine(afunc):
            raise PermissionError(UNSUPPORTED_NODE_BODY)
        function = afunc
        is_async = True
    else:
        if type(func) is not FunctionType or _is_coroutine(func):
            raise PermissionError(UNSUPPORTED_NODE_BODY)
        if not _is_executor_shim(afunc, func):
            raise PermissionError(UNSUPPORTED_NODE_BODY)
        function = func
        is_async = False
    plan = []
    for keyword, entry in accepts.items():
        if type(keyword) is not str or type(entry) is not tuple or len(entry) != 2:
            raise PermissionError(UNSUPPORTED_NODE_BODY)
        if type(entry[0]) is not str:
            raise PermissionError(UNSUPPORTED_NODE_BODY)
        plan.append((keyword, entry[0], entry[1]))
    code = _application_code(function, UNSUPPORTED_NODE_BODY)
    return _CapturedApplication(name, node, function, is_async, tuple(plan), code)


def _is_coroutine(function: FunctionType) -> bool:
    return bool(function.__code__.co_flags & CO_COROUTINE)


def _is_executor_shim(afunc: Any, function: Any) -> bool:
    """Whether `afunc` is the framework's `run_in_executor` shim for `function`."""
    from langgraph._internal._runnable import run_in_executor

    return (
        type(afunc) is partial
        and afunc.func is run_in_executor
        and type(afunc.args) is tuple
        and len(afunc.args) == 2
        and afunc.args[0] is None
        and afunc.args[1] is function
        and type(afunc.keywords) is dict
        and not afunc.keywords
    )


def _application_code(function: Any, code: str) -> tuple:
    """Return the native identity of `function`'s loaded code or refuse."""
    from langgraph.prebuilt.security.inprocess import _code_identity as identity

    if type(function) is not FunctionType:
        raise PermissionError(code)
    loaded = function.__code__
    if type(loaded) is not CodeType:
        raise PermissionError(code)
    try:
        return identity(loaded)
    except Exception:
        raise PermissionError(code) from None


def _application_state(
    captured: _CapturedApplication,
) -> tuple[str, str, dict[str, Any]]:
    """Re-read a trusted application node and return identity, source, details.

    The identity is a SHA-256 digest over the node name, the function's module
    and qualname, its loaded-code identity (bytecode, constants, names, flags)
    and the keyword-injection plan. A replaced `func`/`afunc`, a reassigned
    `__code__`, bound kwargs or argument explosion raise
    `admission:descriptor_changed`. Globals, closures and defaults are not
    bound: the body is trusted per D11 and this binds identity only.
    """
    from langgraph._internal._runnable import RunnableCallable

    node = captured.node
    function = captured.function
    if type(node) is not RunnableCallable or type(function) is not FunctionType:
        raise PermissionError(DESCRIPTOR_CHANGED)
    missing = False
    try:
        func = node.func
        afunc = node.afunc
        bound = node.kwargs
        explode = node.explode_args
    except AttributeError:
        missing = True
    if missing:
        raise PermissionError(DESCRIPTOR_CHANGED)
    if captured.is_async:
        if func is not None or afunc is not function:
            raise PermissionError(DESCRIPTOR_CHANGED)
    elif func is not function or not _is_executor_shim(afunc, function):
        raise PermissionError(DESCRIPTOR_CHANGED)
    if type(bound) is not dict or bound or explode is not False:
        raise PermissionError(DESCRIPTOR_CHANGED)
    code = _application_code(function, DESCRIPTOR_CHANGED)
    if code != captured.code:
        raise PermissionError(DESCRIPTOR_CHANGED)
    module = function.__module__
    qualname = function.__qualname__
    if type(module) is not str or type(qualname) is not str:
        raise PermissionError(DESCRIPTOR_CHANGED)
    code_sha256 = hashlib.sha256(_encode(code).encode()).hexdigest()
    details = {
        "kind": AdmittedKind.TRUSTED_APPLICATION.value,
        "name": captured.name,
        "module": module,
        "qualname": qualname,
        "code_sha256": code_sha256,
        "async": captured.is_async,
        "injected": sorted(keyword for keyword, _, _ in captured.accepts),
    }
    return _digest(details), code_sha256, details


def _capture_tool_node(node: Any, config: Any) -> _CapturedToolNode:
    """Capture the exact dispatch path of one `ToolNode` from native storage."""
    from langchain_core.tools import StructuredTool

    from langgraph.prebuilt.security.linux import LinuxSandboxExecutor
    from langgraph.prebuilt.security.object_policy import ObjectPolicyHostExecutor
    from langgraph.prebuilt.tool_node import ToolNode, _InjectedArgs

    config = _require_config(config, UNSUPPORTED_NODE_BODY)
    executor = config.host_executor
    if executor is None:
        # Without a host executor the tool bodies would run in the coordinator.
        raise PermissionError(UNSUPPORTED_NODE_BODY)
    missing = False
    try:
        func = node.func
        afunc = node.afunc
        wrap = node._wrap_tool_call
        awrap = node._awrap_tool_call
        tools = node._tools_by_name
        injected = node._injected_args
        existing_executor = node._security_host_executor
        existing_config = node._security_config
    except AttributeError:
        missing = True
    if missing:
        raise PermissionError(UNSUPPORTED_NODE_BODY)
    if not _is_bound_method(func, node, ToolNode.__dict__.get("_func")):
        raise PermissionError(UNSUPPORTED_NODE_BODY)
    if not _is_bound_method(afunc, node, ToolNode.__dict__.get("_afunc")):
        raise PermissionError(UNSUPPORTED_ASYNC)
    if wrap is not None or awrap is not None:
        raise PermissionError(UNSUPPORTED_NODE_BODY)
    if existing_executor is not None and existing_executor is not executor:
        raise PermissionError(UNSUPPORTED_NODE_BODY)
    if existing_config is not None and existing_config is not config:
        raise PermissionError(UNSUPPORTED_NODE_BODY)
    if type(tools) is not dict or type(injected) is not dict:
        raise PermissionError(UNSUPPORTED_NODE_BODY)
    captured_tools = []
    for tool_name, tool in tools.items():
        if type(tool_name) is not str or type(tool) is not StructuredTool:
            raise PermissionError(UNSUPPORTED_NODE_BODY)
        args = injected.get(tool_name)
        if type(args) is not _InjectedArgs or (
            args.state
            or args.store is not None
            or args.runtime is not None
            or args.all_injected_keys
        ):
            raise PermissionError(UNSUPPORTED_NODE_BODY)
        captured_tools.append((tool_name, tool))
    dispatcher = None
    admission = None
    if type(executor) is ObjectPolicyHostExecutor:
        dispatcher = executor.dispatcher
        admission = _language_admission(dispatcher)
    elif type(executor) is not LinuxSandboxExecutor:
        raise PermissionError(UNSUPPORTED_NODE_BODY)
    return _CapturedToolNode(
        node, executor, dispatcher, admission, tuple(captured_tools)
    )


def _admit_model_call(name: str, model: Any, registry_id: str) -> AdmittedDescriptor:
    captured = _capture_model(model, registry_id)
    identity, source, _ = _model_state(captured)
    return AdmittedDescriptor(AdmittedKind.MODEL_CALL, name, identity, captured, source)


def _model_allowlist() -> tuple[tuple[str, Any], ...]:
    """Resolve `_MODEL_CLASSES` once; an unimportable package pins `None`."""
    import importlib

    for module_name, attribute in _MODEL_CLASSES:
        registry_id = f"{module_name}:{attribute}"
        if registry_id in _pinned_models:
            continue
        resolved = None
        try:
            module = importlib.import_module(module_name)
            resolved = module.__dict__.get(attribute)
        except ImportError:
            resolved = None
        _pinned_models.setdefault(registry_id, resolved)
    return tuple(_pinned_models.items())


def _allowlisted_model(kind: Any) -> str | None:
    """Return the registry id when `kind` is an allowlisted class by identity."""
    for registry_id, allowed in _model_allowlist():
        if allowed is not None and kind is allowed:
            return registry_id
    return None


def _capture_model(model: Any, registry_id: str) -> _CapturedModel:
    """Capture an exact allowlisted model and its class-level call functions."""
    model_class = _pinned_models.get(registry_id)
    if model_class is None:
        raise PermissionError(UNSUPPORTED_NODE_BODY)
    if type(model) is not model_class:
        raise PermissionError(UNSUPPORTED_NODE_BODY)
    missing = False
    try:
        fields = model.__dict__
    except AttributeError:
        missing = True
    if missing:
        raise PermissionError(UNSUPPORTED_NODE_BODY)
    _model_endpoint(fields, UNSUPPORTED_NODE_BODY)
    call = _class_function(model_class, "invoke")
    acall = _class_function(model_class, "ainvoke")
    return _CapturedModel(model, registry_id, model_class, call, acall)


def _model_endpoint(fields: Any, code: str) -> dict[str, str | None]:
    """Project exact-`str` endpoint fields; refuse callback fields or other values."""
    if type(fields) is not dict:
        raise PermissionError(code)
    for name in _MODEL_CALLBACK_FIELDS:
        if fields.get(name) is not None:
            raise PermissionError(code)
    endpoint: dict[str, str | None] = {}
    for name in _MODEL_ENDPOINT_FIELDS:
        if name not in fields:
            continue
        value = fields[name]
        if value is not None and type(value) is not str:
            raise PermissionError(code)
        endpoint[name] = value
    return endpoint


def _class_function(model_class: Any, name: str) -> FunctionType:
    """Resolve `name` through the exact class MRO; it must be a plain function."""
    for klass in model_class.__mro__:
        value = klass.__dict__.get(name)
        if value is not None:
            if type(value) is not FunctionType:
                raise PermissionError(UNSUPPORTED_NODE_BODY)
            return value
    raise PermissionError(UNSUPPORTED_NODE_BODY)


def _model_state(captured: _CapturedModel) -> tuple[str, str, dict[str, Any]]:
    """Re-read the live model and return identity, source digest and details.

    The identity covers the registry id (exact module and qualname of the
    class) and every declared endpoint field that is an exact `str`. A class
    swap, a re-resolved class-level `invoke`/`ainvoke`, an endpoint change or
    a callback field set after admission raises `admission:descriptor_changed`.
    """
    model = captured.node
    model_class = captured.model_class
    if (
        type(model) is not model_class
        or _pinned_models.get(captured.registry_id) is not model_class
        or _class_function(model_class, "invoke") is not captured.call
        or _class_function(model_class, "ainvoke") is not captured.acall
    ):
        raise PermissionError(DESCRIPTOR_CHANGED)
    try:
        fields = model.__dict__
    except AttributeError:
        raise PermissionError(DESCRIPTOR_CHANGED) from None
    endpoint = _model_endpoint(fields, DESCRIPTOR_CHANGED)
    details = {
        "kind": AdmittedKind.MODEL_CALL.value,
        "class": captured.registry_id,
        "endpoint": endpoint,
    }
    source = hashlib.sha256(captured.registry_id.encode()).hexdigest()
    return _digest(details), source, details


def _language_admission(dispatcher: Any) -> Any:
    from langgraph.prebuilt.security.inprocess import ManifestAdmission
    from langgraph.prebuilt.security.object_policy import _LanguageSandboxDispatcher

    if type(dispatcher) is not _LanguageSandboxDispatcher:
        return None
    admission = dispatcher.admission
    if type(admission) is not ManifestAdmission:
        raise PermissionError(UNSUPPORTED_NODE_BODY)
    return admission


def _is_bound_method(value: Any, instance: Any, function: Any) -> bool:
    return (
        type(value) is MethodType
        and type(function) is FunctionType
        and value.__func__ is function
        and value.__self__ is instance
    )


def _tool_node_state(
    captured: _CapturedToolNode, *, installed: bool
) -> tuple[AdmittedKind, str, str, dict[str, Any]]:
    """Re-read the live dispatch path and return kind, identity, source, details."""
    from langgraph.prebuilt.security.container import DockerObjectDispatcher
    from langgraph.prebuilt.security.linux import LinuxSandboxExecutor
    from langgraph.prebuilt.security.linux_object import LinuxObjectDispatcher
    from langgraph.prebuilt.security.macos_object import MacOSObjectDispatcher
    from langgraph.prebuilt.security.object_broker import ObjectBrokerDispatcher
    from langgraph.prebuilt.security.object_policy import (
        CedarObjectAuthorizer,
        ObjectPolicyHostExecutor,
        _LanguageSandboxDispatcher,
    )
    from langgraph.prebuilt.tool_node import ToolNode

    node = captured.node
    executor = captured.executor
    if type(node) is not ToolNode:
        raise PermissionError(UNSUPPORTED_NODE_BODY)
    missing = False
    try:
        func = node.func
        afunc = node.afunc
        wrap = node._wrap_tool_call
        awrap = node._awrap_tool_call
        tools = node._tools_by_name
        live_executor = node._security_host_executor
    except AttributeError:
        missing = True
    if missing:
        raise PermissionError(UNSUPPORTED_NODE_BODY)
    if not _is_bound_method(func, node, ToolNode.__dict__.get("_func")):
        raise PermissionError(UNSUPPORTED_NODE_BODY)
    if not _is_bound_method(afunc, node, ToolNode.__dict__.get("_afunc")):
        raise PermissionError(UNSUPPORTED_ASYNC)
    if wrap is not None or awrap is not None:
        raise PermissionError(UNSUPPORTED_NODE_BODY)
    if installed:
        if live_executor is not executor:
            raise PermissionError(DESCRIPTOR_CHANGED)
    elif live_executor is not None and live_executor is not executor:
        raise PermissionError(UNSUPPORTED_NODE_BODY)
    if type(tools) is not dict or len(tools) != len(captured.tools):
        raise PermissionError(DESCRIPTOR_CHANGED)
    for tool_name, tool in captured.tools:
        if tools.get(tool_name) is not tool:
            raise PermissionError(DESCRIPTOR_CHANGED)
    tool_names = tuple(name for name, _ in captured.tools)
    if type(executor) is ObjectPolicyHostExecutor:
        authorizer = executor.authorizer
        dispatcher = executor.dispatcher
        if (
            type(authorizer) is not CedarObjectAuthorizer
            or dispatcher is not captured.dispatcher
        ):
            raise PermissionError(DESCRIPTOR_CHANGED)
        waivers = authorizer.enforcement_waivers
        if type(waivers) is not MappingProxyType or len(waivers):
            raise PermissionError(UNSUPPORTED_NODE_BODY)
        dispatcher_type = type(dispatcher)
        if dispatcher_type is _LanguageSandboxDispatcher:
            kind = AdmittedKind.LANGUAGE_PROGRAM
            details = _language_details(captured, dispatcher)
        elif dispatcher_type is DockerObjectDispatcher:
            kind = AdmittedKind.NATIVE_DEPLOYMENT
            details = _docker_details(dispatcher, tool_names)
        elif dispatcher_type is LinuxObjectDispatcher:
            kind = AdmittedKind.NATIVE_DEPLOYMENT
            details = _linux_object_details(dispatcher, tool_names)
        elif dispatcher_type is MacOSObjectDispatcher:
            kind = AdmittedKind.NATIVE_DEPLOYMENT
            details = _macos_object_details(dispatcher, tool_names)
        elif dispatcher_type is ObjectBrokerDispatcher:
            kind = AdmittedKind.TOOL_NODE
            details = _broker_details(dispatcher, tool_names)
        else:
            raise PermissionError(UNSUPPORTED_NODE_BODY)
    elif type(executor) is LinuxSandboxExecutor:
        if captured.dispatcher is not None:
            raise PermissionError(DESCRIPTOR_CHANGED)
        kind = AdmittedKind.NATIVE_DEPLOYMENT
        details = _linux_details(executor, tool_names)
    else:
        raise PermissionError(UNSUPPORTED_NODE_BODY)
    details = {"kind": kind.value, "tools": list(tool_names), **details}
    return kind, _digest(details), _digest(sorted(set(details["sources"]))), details


def _language_details(captured: _CapturedToolNode, dispatcher: Any) -> dict[str, Any]:
    """Project the admitted language programs with closed terminal IDs."""
    from langgraph.prebuilt.security._language_sandbox import LanguageProgram
    from langgraph.prebuilt.security.errors import SecurityConfigurationError
    from langgraph.prebuilt.security.execution import HostExecutionDenied
    from langgraph.prebuilt.security.inprocess import ManifestAdmission

    admission = dispatcher.admission
    if admission is not captured.admission or type(admission) is not ManifestAdmission:
        raise PermissionError(DESCRIPTOR_CHANGED)
    tool = admission.tool
    if (
        dispatcher.tool is not tool
        or len(captured.tools) != 1
        or captured.tools[0][1] is not tool
    ):
        raise PermissionError(DESCRIPTOR_CHANGED)
    try:
        admission.validate()
    except (HostExecutionDenied, SecurityConfigurationError, PermissionError):
        raise PermissionError(DESCRIPTOR_CHANGED) from None
    programs = admission.programs
    sources = admission.program_sources
    if type(programs) is not dict or type(sources) is not dict or not programs:
        raise PermissionError(DESCRIPTOR_CHANGED)
    projected: dict[str, Any] = {}
    source_digests: list[str] = []
    for attribute in sorted(programs):
        program = programs[attribute]
        source = sources.get(attribute)
        if (
            type(attribute) is not str
            or type(program) is not LanguageProgram
            or not _is_sha256(source)
        ):
            raise PermissionError(DESCRIPTOR_CHANGED)
        try:
            body, signature, terminals, contracts = program._snapshot()
        except SecurityConfigurationError:
            raise PermissionError(DESCRIPTOR_CHANGED) from None
        terminal_ids = sorted(terminals)
        if any(type(item) is not str for item in terminal_ids) or set(
            terminal_ids
        ) != set(contracts):
            raise PermissionError(DESCRIPTOR_CHANGED)
        projected[attribute] = {
            "body": _native(body),
            "signature": [
                [
                    parameter.name,
                    parameter.kind.name,
                    None
                    if parameter.default is Parameter.empty
                    else _native(parameter.default),
                ]
                for parameter in signature.parameters.values()
            ],
            "terminals": terminal_ids,
            "contracts": {
                name: {
                    "parameters": [list(item) for item in contracts[name].parameters],
                    "result": sorted(contracts[name].result),
                }
                for name in terminal_ids
            },
            "source_sha256": source,
        }
        source_digests.append(source)
    return {
        "tool": captured.tools[0][0],
        "programs": projected,
        "sources": source_digests,
    }


def _docker_details(dispatcher: Any, tool_names: tuple[str, ...]) -> dict[str, Any]:
    specs = _tool_specs(dispatcher.tools, tool_names)
    image = dispatcher.image
    worker = dispatcher._worker_digest
    if type(image) is not str or not _is_sha256(worker):
        raise PermissionError(DESCRIPTOR_CHANGED)
    return {
        "host": "docker",
        "image": image,
        "worker_sha256": worker,
        "specs": specs,
        "sources": [spec["artifact_sha256"] for spec in specs],
    }


def _broker_details(dispatcher: Any, tool_names: tuple[str, ...]) -> dict[str, Any]:
    specs = _tool_specs(dispatcher.tools, tool_names)
    roots = dispatcher.runtime_roots
    if type(roots) is not tuple:
        raise PermissionError(DESCRIPTOR_CHANGED)
    return {
        "host": "broker",
        "runtime_roots": [_path_text(root) for root in roots],
        "specs": specs,
        "sources": [spec["artifact_sha256"] for spec in specs],
    }


def _linux_object_details(
    dispatcher: Any, tool_names: tuple[str, ...]
) -> dict[str, Any]:
    specs = _tool_specs(dispatcher.tools, tool_names)
    roots = dispatcher.runtime_roots
    checker = dispatcher.lifecycle_checker
    if type(roots) is not tuple:
        raise PermissionError(DESCRIPTOR_CHANGED)
    checker_digest = None if checker is None else checker.binary_sha256
    if checker_digest is not None and not _is_sha256(checker_digest):
        raise PermissionError(DESCRIPTOR_CHANGED)
    return {
        "host": "linux_object",
        "runtime_roots": [_path_text(root) for root in roots],
        "lean_worker_sha256": checker_digest,
        "specs": specs,
        "sources": [spec["artifact_sha256"] for spec in specs],
    }


def _linux_details(executor: Any, tool_names: tuple[str, ...]) -> dict[str, Any]:
    specs = _tool_specs(executor.tools, tool_names)
    roots = executor.runtime_roots
    if type(roots) is not tuple:
        raise PermissionError(DESCRIPTOR_CHANGED)
    return {
        "host": "linux",
        "runtime_roots": [_path_text(root) for root in roots],
        "specs": specs,
        "sources": [spec["artifact_sha256"] for spec in specs],
    }


def _macos_object_details(
    dispatcher: Any, tool_names: tuple[str, ...]
) -> dict[str, Any]:
    from langgraph.prebuilt.security.lean_lifecycle import LeanLifecycleChecker
    from langgraph.prebuilt.security.macos import MacOSToolSpec
    from langgraph.prebuilt.security.macos_native import MacOSNativeLauncher
    from langgraph.prebuilt.security.resource_mediator import ResourceMediatorAdapter

    specs = _tool_specs(dispatcher.tools, tool_names, spec_type=MacOSToolSpec)
    launcher, checker = dispatcher.launcher, dispatcher.lifecycle_checker
    if (
        type(launcher) is not MacOSNativeLauncher
        or type(checker) is not LeanLifecycleChecker
    ):
        raise PermissionError(UNSUPPORTED_NODE_BODY)
    if (
        type(dispatcher.runtime_roots) is not tuple
        or type(dispatcher.executable_roots) is not tuple
    ):
        raise PermissionError(DESCRIPTOR_CHANGED)
    mediators, callback_sources = [], []
    if type(dispatcher.mediators) is not tuple:
        raise PermissionError(DESCRIPTOR_CHANGED)
    for mediator in dispatcher.mediators:
        if type(mediator) is not ResourceMediatorAdapter:
            raise PermissionError(UNSUPPORTED_NODE_BODY)
        callbacks = {}
        for name in ("assess", "invoke", "preflight", "activate", "release"):
            callback = getattr(mediator, name)
            if callback is None:
                callbacks[name] = None
                continue
            function = callback.__func__ if type(callback) is MethodType else callback
            if type(function) is not FunctionType:
                raise PermissionError(UNSUPPORTED_NODE_BODY)
            source = hashlib.sha256(
                _encode(_code_identity(function.__code__)).encode()
            ).hexdigest()
            callbacks[name] = {"identity": id(callback), "code": source}
            callback_sources.append(source)
        mediators.append({"adapter": mediator.adapter_id, "callbacks": callbacks})
    return {
        "host": "macos_object",
        "specs": specs,
        "runtime_roots": [_path_text(root) for root in dispatcher.runtime_roots],
        "executable_roots": [_path_text(root) for root in dispatcher.executable_roots],
        "launcher": _path_text(launcher.path),
        "launcher_sha256": launcher.digest,
        "libpython": _path_text(launcher.library),
        "libpython_sha256": launcher.library_digest,
        "stdlib": _path_text(launcher.stdlib),
        "dynload": _path_text(launcher.dynload),
        "lean_worker_sha256": checker.binary_sha256,
        "lean_runtime_sha256": checker.runtime_sha256,
        "wall_timeout_s": dispatcher.wall_timeout_s,
        "bindings": sorted(dispatcher.bindings.items()),
        "mediators": mediators,
        "runtime_aliases": sorted(dispatcher.runtime_aliases.items()),
        "runtime_libraries": [dict(item) for item in dispatcher.runtime_libraries],
        "sources": [spec["artifact_sha256"] for spec in specs] + callback_sources,
    }


def _tool_specs(
    registry: Any, tool_names: tuple[str, ...], *, spec_type: Any = None
) -> list[dict[str, Any]]:
    """Project exact `LinuxToolSpec` records for the node's registered tools."""
    from langgraph.prebuilt.security.linux import LinuxToolSpec

    if spec_type is None:
        spec_type = LinuxToolSpec

    if type(registry) is not MappingProxyType:
        raise PermissionError(DESCRIPTOR_CHANGED)
    specs = []
    for name in tool_names:
        spec = registry.get(name)
        if type(spec) is not spec_type:
            raise PermissionError(UNSUPPORTED_NODE_BODY)
        entrypoint = spec.entrypoint
        digest = spec.artifact_digest
        if type(entrypoint) is not str or not _is_sha256(digest):
            raise PermissionError(DESCRIPTOR_CHANGED)
        specs.append(
            {
                "tool": name,
                "entrypoint": entrypoint,
                "artifact_path": _path_text(spec.artifact_path),
                "artifact_sha256": digest,
                "deployment": getattr(spec, "deployment", None) is not None,
            }
        )
    return specs


def _capture_branch(branch: Any) -> _CapturedBranch:
    from langgraph._internal._runnable import RunnableCallable

    path = branch.path
    if type(path) is not RunnableCallable:
        raise PermissionError(UNSUPPORTED_BRANCH)
    missing = False
    try:
        func = path.func
    except AttributeError:
        missing = True
    if missing:
        raise PermissionError(UNSUPPORTED_BRANCH)
    if func is None:
        raise PermissionError(UNSUPPORTED_ASYNC)
    registry_id = _pinned_branch_id(func)
    if registry_id is None:
        raise PermissionError(UNSUPPORTED_BRANCH)
    return _CapturedBranch(branch, path, func, registry_id)


def _pinned_branch_id(function: Any) -> str | None:
    """Return the registry id when `function` is a pinned framework branch."""
    import importlib

    if type(function) is not FunctionType:
        return None
    for module_name, attribute in _FRAMEWORK_BRANCHES:
        registry_id = f"{module_name}:{attribute}"
        pinned = _pinned_branches.get(registry_id)
        if pinned is None:
            module = importlib.import_module(module_name)
            candidate = module.__dict__.get(attribute)
            if type(candidate) is not FunctionType:
                continue
            pinned = (candidate, _code_identity(candidate.__code__))
            _pinned_branches.setdefault(registry_id, pinned)
            pinned = _pinned_branches[registry_id]
        if function is pinned[0]:
            return registry_id
    return None


def _branch_state(captured: _CapturedBranch) -> tuple[str, str, dict[str, Any]]:
    from langgraph._internal._runnable import RunnableCallable, run_in_executor
    from langgraph.graph._branch import BranchSpec

    branch = captured.branch
    path = captured.path
    function = captured.function
    if type(branch) is not BranchSpec or type(path) is not RunnableCallable:
        raise PermissionError(UNSUPPORTED_BRANCH)
    if branch.path is not path:
        raise PermissionError(DESCRIPTOR_CHANGED)
    pinned = _pinned_branches.get(captured.registry_id)
    if (
        pinned is None
        or function is not pinned[0]
        or type(function) is not FunctionType
    ):
        raise PermissionError(DESCRIPTOR_CHANGED)
    missing = False
    try:
        func = path.func
        afunc = path.afunc
        kwargs = path.kwargs
        explode = path.explode_args
    except AttributeError:
        missing = True
    if missing:
        raise PermissionError(UNSUPPORTED_BRANCH)
    if func is not function:
        raise PermissionError(DESCRIPTOR_CHANGED)
    if (
        type(afunc) is not partial
        or afunc.func is not run_in_executor
        or type(afunc.args) is not tuple
        or len(afunc.args) != 2
        or afunc.args[0] is not None
        or afunc.args[1] is not function
        or type(afunc.keywords) is not dict
        or afunc.keywords
    ):
        raise PermissionError(UNSUPPORTED_ASYNC)
    if type(kwargs) is not dict or kwargs or explode is not False:
        raise PermissionError(UNSUPPORTED_BRANCH)
    code = function.__code__
    if type(code) is not CodeType:
        raise PermissionError(DESCRIPTOR_CHANGED)
    code_identity = _code_identity(code)
    if code_identity != pinned[1]:
        raise PermissionError(DESCRIPTOR_CHANGED)
    ends = branch.ends
    if ends is not None:
        if type(ends) is not dict or any(
            type(key) is not str or type(value) is not str
            for key, value in ends.items()
        ):
            raise PermissionError(UNSUPPORTED_BRANCH)
        ends = sorted(ends.items())
    code_text = _encode(code_identity)
    details = {
        "kind": AdmittedKind.FRAMEWORK_BRANCH.value,
        "function": captured.registry_id,
        "code_sha256": hashlib.sha256(code_text.encode()).hexdigest(),
        "ends": [list(item) for item in ends] if ends is not None else None,
    }
    return _digest(details), details["code_sha256"], details


def _code_identity(code: CodeType) -> tuple:
    from langgraph.prebuilt.security.inprocess import _code_identity as identity

    try:
        return identity(code)
    except Exception:
        raise PermissionError(UNSUPPORTED_BRANCH) from None


def _native(value: Any, depth: int = 0) -> Any:
    """Project immutable program data; any other type refuses."""
    if depth > 64:
        raise PermissionError(DESCRIPTOR_CHANGED)
    kind = type(value)
    if value is None or kind is str or kind is bool or kind is int:
        return value
    if kind is float:
        return ["float", struct.pack("!d", value).hex()]
    if kind is tuple:
        return [_native(item, depth + 1) for item in value]
    raise PermissionError(DESCRIPTOR_CHANGED)


def _encode(value: Any, depth: int = 0) -> str:
    """Deterministically encode a native tagged code identity."""
    if depth > 80:
        raise PermissionError(DESCRIPTOR_CHANGED)
    kind = type(value)
    if kind is str:
        return "s" + value.encode().hex()
    if kind is bytes:
        return "b" + value.hex()
    if kind is bool:
        return "t" if value else "f"
    if kind is int:
        return f"i{value}"
    if kind is float:
        return "d" + struct.pack("!d", value).hex()
    if value is None:
        return "n"
    if kind is tuple:
        return "(" + ",".join(_encode(item, depth + 1) for item in value) + ")"
    if kind is frozenset:
        return "{" + ",".join(sorted(_encode(item, depth + 1) for item in value)) + "}"
    raise PermissionError(DESCRIPTOR_CHANGED)


def _path_text(value: Any) -> str:
    kind = type(value)
    if kind is str:
        return value
    if kind is PosixPath or kind is WindowsPath:
        return str(value)
    raise PermissionError(DESCRIPTOR_CHANGED)


def _is_sha256(value: Any) -> bool:
    return (
        type(value) is str
        and len(value) == _SHA256_LENGTH
        and all(character in _HEX for character in value)
    )


def _digest(payload: Any) -> str:
    encoded = json.dumps(
        payload, sort_keys=True, separators=(",", ":"), allow_nan=False
    ).encode()
    return hashlib.sha256(encoded).hexdigest()
