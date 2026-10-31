"""Operator-owned mandatory policy for the entire Python runtime.

The controller, its configuration, callbacks, and installed Python code are
trusted. This is not a kernel LSM: arbitrary hostile code in that controller
requires OS isolation. Unsupported graph bodies fail closed under runtime MAC.

The registry records one entry per secured graph at compilation. A graph
compiled with `closed_admission=True` contributes a `_MacBoundary`: the
inventory captured before any compile-time candidate protocol (see
`admission`), bound to its mediated wrappers and, on every check, re-bound to
the compiled Pregel nodes the scheduler executes (`graph.nodes[name].bound`
and the branch writers). Admitted `MODEL_CALL` nodes are bound and rechecked
like tool nodes; their confinement is the model-invocation hook. Declared
`TRUSTED_APPLICATION` nodes are bound and rechecked the same way; they are
trusted application code (D11), so the binding covers their identity, not
their behavior. Declared `TRUSTED_APPLICATION_BRANCH` edges are bound through
the compiled branch writers and rechecked like framework branches. Without
closed admission only the legacy shape (exact
`MediatedNode` wrapping an exact `ToolNode`, no branches) is recorded, as the
tuple of wrapped `ToolNode` objects; every other shape is recorded as `None`
and refused with `mac:unconfined_graph_body`.
"""

from __future__ import annotations

from dataclasses import dataclass
from threading import RLock
from types import MethodType
from typing import Any
from weakref import WeakKeyDictionary

from langgraph._internal._runtime_policy import (
    install_runtime_policy,
    runtime_policy,
)

from langgraph.prebuilt.security.admission import (
    DESCRIPTOR_CHANGED,
    AdmittedDescriptor,
    _CapturedApplication,
    _CapturedBranch,
    _CapturedModel,
    _CapturedToolNode,
    _CapturedTrustedBranch,
    _is_bound_method,
    recheck,
)
from langgraph.prebuilt.security.errors import SecurityConfigurationError


@dataclass(frozen=True, slots=True)
class _MacBoundary:
    """Admitted inventory of one closed graph with its mediated wrappers.

    `nodes` holds `(name, MediatedNode, descriptor)`; `branches` holds
    `(name, source, MediatedBranch, descriptor)` where `source` names the
    compiled node whose writers carry the branch.
    """

    nodes: tuple[tuple[str, Any, AdmittedDescriptor], ...]
    branches: tuple[tuple[str, str, Any, AdmittedDescriptor], ...]


_graph_lock = RLock()
_graph_boundaries: WeakKeyDictionary[Any, Any] = WeakKeyDictionary()


def register_mac_boundary(graph: Any) -> None:
    """Record the admitted descriptor inventory at SecurityConfig compilation."""
    from langgraph.prebuilt.security.config import SecurityConfig

    builder = graph.builder
    config = getattr(builder, "_security_config", None)
    boundary: Any = None
    if type(config) is SecurityConfig:
        if config.closed_admission:
            boundary = _closed_boundary(builder, graph)
        else:
            boundary = _legacy_boundary(builder)
    with _graph_lock:
        _graph_boundaries[graph] = boundary


def _closed_boundary(builder: Any, graph: Any) -> _MacBoundary:
    """Bind the pre-protocol inventory to the wrappers and the compiled nodes."""
    from langgraph.prebuilt.security.placement import MediatedBranch, MediatedNode

    inventory = getattr(builder, "_security_admission", None)
    if type(inventory) is not tuple:
        raise PermissionError(DESCRIPTOR_CHANGED)
    nodes = []
    branches = []
    wrappers: dict[str, Any] = {}
    sources: dict[str, str] = {}
    for name, spec in builder.nodes.items():
        wrappers[name] = spec.runnable
    for source, named in builder.branches.items():
        for branch_name, branch in named.items():
            placement_name = f"{source}:branch:{branch_name}"
            wrappers[placement_name] = branch.path
            sources[placement_name] = source
    for descriptor in inventory:
        if type(descriptor) is not AdmittedDescriptor:
            raise PermissionError(DESCRIPTOR_CHANGED)
        wrapper = wrappers.pop(descriptor.name, None)
        implementation = descriptor.implementation
        if (
            type(implementation) is _CapturedToolNode
            or type(implementation) is _CapturedModel
            or type(implementation) is _CapturedApplication
        ):
            if (
                type(wrapper) is not MediatedNode
                or wrapper.runnable is not implementation.node
            ):
                raise PermissionError(DESCRIPTOR_CHANGED)
            nodes.append((descriptor.name, wrapper, descriptor))
        elif (
            type(implementation) is _CapturedBranch
            or type(implementation) is _CapturedTrustedBranch
        ):
            if (
                type(wrapper) is not MediatedBranch
                or wrapper.runnable is not implementation.path
            ):
                raise PermissionError(DESCRIPTOR_CHANGED)
            branches.append(
                (descriptor.name, sources[descriptor.name], wrapper, descriptor)
            )
        else:
            raise PermissionError(DESCRIPTOR_CHANGED)
        recheck(descriptor)
    if wrappers:
        raise PermissionError(DESCRIPTOR_CHANGED)
    boundary = _MacBoundary(tuple(nodes), tuple(branches))
    _bind_compiled_graph(boundary, graph)
    return boundary


def _legacy_boundary(builder: Any) -> tuple[Any, ...] | None:
    """Record the legacy ToolNode-only shape; any other shape is unconfined.

    This is the pre-admission behavior: an exact `MediatedNode` wrapping an
    exact `ToolNode` for every node and no branches yields the wrapped
    `ToolNode` objects, which `RuntimeMAC.check` re-examines through
    `_check_tool_node`; anything else yields `None`. Nothing is admitted here,
    and this path cannot show that no compile-time protocol ran earlier; that
    proof requires `closed_admission=True`.
    """
    from langgraph.prebuilt.security.placement import MediatedNode
    from langgraph.prebuilt.tool_node import ToolNode

    if any(builder.branches.values()):
        return None
    nodes = []
    for spec in builder.nodes.values():
        mediated = spec.runnable
        if (
            type(mediated) is not MediatedNode
            or type(mediated.runnable) is not ToolNode
        ):
            return None
        nodes.append(mediated.runnable)
    return tuple(nodes)


def _bind_compiled_graph(boundary: _MacBoundary, graph: Any) -> None:
    """Require the compiled Pregel nodes to execute exactly the admitted wrappers.

    The scheduler invokes `graph.nodes[name].bound` followed by that node's
    `writers`; a conditional branch is a writer whose `func`/`afunc` are the
    `BranchSpec._route`/`_aroute` methods of the spec carrying the mediated
    path. The compiled node names must equal the admitted inventory plus the
    framework `START` node with the default bound; every `bound` must be the
    captured `MediatedNode` by identity; every writer must be an exact
    `ChannelWrite` dispatching its own methods or a branch writer bound to a
    captured `MediatedBranch` of that node; and every captured branch must
    appear exactly once. Any mismatch raises `admission:descriptor_changed`
    before any other work. Cached execution plans are dropped afterwards so the
    scheduler rebuilds them from the verified parts.
    """
    from langgraph.constants import START
    from langgraph.pregel._read import DEFAULT_BOUND, PregelNode
    from langgraph.pregel._write import ChannelWrite

    compiled = graph.nodes
    if type(compiled) is not dict:
        raise PermissionError(DESCRIPTOR_CHANGED)
    expected: dict[str, Any] = {START: DEFAULT_BOUND}
    for name, mediated, _ in boundary.nodes:
        expected[name] = mediated
    if set(compiled) != set(expected):
        raise PermissionError(DESCRIPTOR_CHANGED)
    routes: dict[str, list[Any]] = {}
    for name in compiled:
        routes[name] = []
    for _, source, mediated, _ in boundary.branches:
        if source not in routes:
            raise PermissionError(DESCRIPTOR_CHANGED)
        admitted = routes[source]
        admitted.append(mediated)
    for name, proc in compiled.items():
        if type(proc) is not PregelNode or proc.bound is not expected[name]:
            raise PermissionError(DESCRIPTOR_CHANGED)
        writers = proc.writers
        if type(writers) is not list:
            raise PermissionError(DESCRIPTOR_CHANGED)
        admitted = routes[name]
        found = []
        for writer in writers:
            if type(writer) is ChannelWrite:
                _channel_write_route(writer)
                continue
            path = _branch_writer_path(writer)
            if _count(admitted, path) == 0:
                raise PermissionError(DESCRIPTOR_CHANGED)
            found.append(path)
        if len(found) != len(admitted):
            raise PermissionError(DESCRIPTOR_CHANGED)
        for mediated in admitted:
            if _count(found, mediated) != 1:
                raise PermissionError(DESCRIPTOR_CHANGED)
    for proc in compiled.values():
        cache = proc.__dict__
        cache.pop("node", None)
        cache.pop("flat_writers", None)


def _channel_write_route(writer: Any) -> None:
    """Require an exact `ChannelWrite` to dispatch its own `_write`/`_awrite`."""
    from langgraph.pregel._write import ChannelWrite

    if type(writer) is not ChannelWrite:
        raise PermissionError(DESCRIPTOR_CHANGED)
    missing = False
    try:
        func = writer.func
        afunc = writer.afunc
    except AttributeError:
        missing = True
    if missing:
        raise PermissionError(DESCRIPTOR_CHANGED)
    if not _is_bound_method(func, writer, ChannelWrite.__dict__.get("_write")):
        raise PermissionError(DESCRIPTOR_CHANGED)
    if not _is_bound_method(afunc, writer, ChannelWrite.__dict__.get("_awrite")):
        raise PermissionError(DESCRIPTOR_CHANGED)


def _branch_writer_path(writer: Any) -> Any:
    """Return the mediated path of a compiled branch writer; refuse any other."""
    from langgraph._internal._runnable import RunnableCallable
    from langgraph.graph._branch import BranchSpec

    from langgraph.prebuilt.security.placement import MediatedBranch

    if type(writer) is not RunnableCallable:
        raise PermissionError(DESCRIPTOR_CHANGED)
    missing = False
    try:
        func = writer.func
        afunc = writer.afunc
    except AttributeError:
        missing = True
    if missing:
        raise PermissionError(DESCRIPTOR_CHANGED)
    if type(func) is not MethodType:
        raise PermissionError(DESCRIPTOR_CHANGED)
    spec = func.__self__
    if type(spec) is not BranchSpec:
        raise PermissionError(DESCRIPTOR_CHANGED)
    if not _is_bound_method(func, spec, BranchSpec.__dict__.get("_route")):
        raise PermissionError(DESCRIPTOR_CHANGED)
    if not _is_bound_method(afunc, spec, BranchSpec.__dict__.get("_aroute")):
        raise PermissionError(DESCRIPTOR_CHANGED)
    path = spec.path
    if type(path) is not MediatedBranch:
        raise PermissionError(DESCRIPTOR_CHANGED)
    return path


def _count(items: list[Any], value: Any) -> int:
    """Count list members that are `value` by identity."""
    total = 0
    for item in items:
        if item is value:
            total = total + 1
    return total


@dataclass(frozen=True, slots=True)
class RuntimeMAC:
    """Immutable operator forbids shared by every graph, session, and tool."""

    forbids: str

    def __post_init__(self) -> None:
        from langgraph.prebuilt.security.object_policy import _require_policy_effect

        if not self.forbids.strip():
            raise ValueError("runtime MAC policy must not be empty")
        _require_policy_effect(self.forbids, "forbid")

    def check(self, target: Any) -> None:
        from langgraph.graph.state import CompiledStateGraph

        from langgraph.prebuilt.tool_node import ToolNode

        if type(target) is ToolNode:
            self._check_tool_node(target)
            return
        if type(target) is not CompiledStateGraph:
            raise SecurityConfigurationError("mac:unsupported_execution_boundary")
        with _graph_lock:
            if target not in _graph_boundaries:
                raise SecurityConfigurationError("mac:graph_requires_security")
            boundary = _graph_boundaries[target]
        if boundary is None:
            raise SecurityConfigurationError("mac:unconfined_graph_body")
        if type(boundary) is tuple:
            for node in boundary:
                self._check_tool_node(node)
            return
        if type(boundary) is not _MacBoundary:
            raise SecurityConfigurationError("mac:unconfined_graph_body")
        self._check_boundary(boundary, target)

    def _check_boundary(self, boundary: _MacBoundary, graph: Any) -> None:
        from langgraph.prebuilt.security.placement import MediatedBranch, MediatedNode
        from langgraph.prebuilt.tool_node import ToolNode

        _bind_compiled_graph(boundary, graph)
        for _, mediated, descriptor in boundary.nodes:
            if type(mediated) is not MediatedNode:
                raise SecurityConfigurationError("mac:unconfined_graph_body")
            implementation = descriptor.implementation
            node = mediated.runnable
            if (
                type(implementation) is _CapturedModel
                or type(implementation) is _CapturedApplication
            ):
                # A model call is confined by its hook and a trusted
                # application node is trusted code (D11), not a host executor;
                # the wrapper must still hold exactly the captured body.
                if node is not implementation.node:
                    raise PermissionError(DESCRIPTOR_CHANGED)
                recheck(descriptor)
                continue
            if (
                type(implementation) is not _CapturedToolNode
                or node is not implementation.node
                or type(node) is not ToolNode
            ):
                raise PermissionError(DESCRIPTOR_CHANGED)
            recheck(descriptor)
            self._check_tool_node(node)
        for _, _, mediated, descriptor in boundary.branches:
            if type(mediated) is not MediatedBranch:
                raise SecurityConfigurationError("mac:unconfined_graph_body")
            implementation = descriptor.implementation
            if (
                type(implementation) is not _CapturedBranch
                and type(implementation) is not _CapturedTrustedBranch
            ):
                raise PermissionError(DESCRIPTOR_CHANGED)
            if mediated.runnable is not implementation.path:
                raise PermissionError(DESCRIPTOR_CHANGED)
            recheck(descriptor)

    def _check_tool_node(self, node: Any) -> None:
        from langgraph.prebuilt.security.container import DockerObjectDispatcher
        from langgraph.prebuilt.security.linux_object import LinuxObjectDispatcher
        from langgraph.prebuilt.security.macos_object import MacOSObjectDispatcher
        from langgraph.prebuilt.security.object_broker import ObjectBrokerDispatcher
        from langgraph.prebuilt.security.object_policy import (
            CedarObjectAuthorizer,
            ObjectPolicyHostExecutor,
            _LanguageSandboxDispatcher,
        )

        executor = node._security_host_executor
        if type(executor) is not ObjectPolicyHostExecutor:
            raise SecurityConfigurationError("mac:tool_requires_object_authorization")
        if type(executor.authorizer) is not CedarObjectAuthorizer:
            raise SecurityConfigurationError("mac:unsupported_authorizer")
        if executor.authorizer.enforcement_waivers:
            raise SecurityConfigurationError("mac:enforcement_waivers_forbidden")
        if type(executor.dispatcher) not in (
            DockerObjectDispatcher,
            LinuxObjectDispatcher,
            MacOSObjectDispatcher,
            ObjectBrokerDispatcher,
            _LanguageSandboxDispatcher,
        ):
            raise SecurityConfigurationError("mac:unsupported_dispatcher")
        if node._wrap_tool_call is not None or node._awrap_tool_call is not None:
            raise SecurityConfigurationError("mac:unconfined_tool_wrapper")


def install_mac_policy(forbids: str) -> None:
    """Install operator MAC once, before any graph or ToolNode executes.

    Used by standalone trusted bootstrap. Deployments can instead provision
    `mac.cedar` in `LANGGRAPH_MAC_DIR` (default `/etc/langgraph`), which is
    loaded automatically and takes precedence.
    Graph-local policies can add restrictions but cannot replace these forbids.
    Graphs without supported mediation are refused, including precompiled graphs,
    raw Pregel programs, arbitrary Python nodes, and direct unsecured ToolNodes.
    Secured graphs outside the legacy ToolNode-only shape must be compiled with
    `SecurityConfig(closed_admission=True)`.
    """
    install_runtime_policy(RuntimeMAC(forbids))


def runtime_mac_forbids() -> str:
    """Read the sealed operator policy at authorization time."""
    policy = runtime_policy()
    return policy.forbids if isinstance(policy, RuntimeMAC) else ""
