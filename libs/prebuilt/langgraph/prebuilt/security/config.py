"""Public configuration and compile-time setup for security mediation."""

from __future__ import annotations

import hashlib
import json
import secrets
from collections.abc import Iterable, Mapping, Sequence
from dataclasses import dataclass, field, replace
from operator import add
from types import MappingProxyType
from typing import Any

from langgraph._internal._cache import default_cache_key
from langgraph._internal._retry import default_retry_on
from langgraph.channels import (
    AnyValue,
    BinaryOperatorAggregate,
    EphemeralValue,
    LastValue,
    LastValueAfterFinish,
    Topic,
    UntrackedValue,
)
from langgraph.checkpoint.base import BaseCheckpointSaver
from langgraph.graph.message import add_messages
from langgraph.types import CachePolicy, RetryPolicy

from langgraph.prebuilt.security.admission import (
    DESCRIPTOR_CHANGED,
    UNSUPPORTED_BRANCH,
    UNSUPPORTED_NODE_BODY,
    AdmittedDescriptor,
    AdmittedKind,
    _bind_declared_branches,
    _CapturedApplication,
    _CapturedBranch,
    _CapturedModel,
    _CapturedToolNode,
    _CapturedTrustedBranch,
    _declared_application_nodes,
    admit_branch,
    admit_node,
    recheck,
)
from langgraph.prebuilt.security.checkpoint_security import MediatedCheckpointer
from langgraph.prebuilt.security.descriptor import DacOverrides, _has_declared_dac
from langgraph.prebuilt.security.errors import SecurityConfigurationError
from langgraph.prebuilt.security.execution import HostToolExecutor
from langgraph.prebuilt.security.flow import SessionFlowPolicy
from langgraph.prebuilt.security.hooks import SecurityModule
from langgraph.prebuilt.security.host_boundary import (
    make_authorized_host_router,
    make_host_router,
)
from langgraph.prebuilt.security.object_manager import (
    ObjectManagerHost,
    ObjectManagerPolicy,
    ToolObjectDac,
)
from langgraph.prebuilt.security.observability import SecurityObserver
from langgraph.prebuilt.security.placement import (
    MediatedBranch,
    MediatedNode,
    NodeKind,
    NodeTrust,
    OutputMediator,
    PlacementSpec,
    UntrustedNodeHost,
    resolve_placement,
)
from langgraph.prebuilt.security.profile import ToolProfile
from langgraph.prebuilt.security.stack import SecurityStack
from langgraph.prebuilt.security.types import AuditRecord, AuditSink, Tool, Verdict

UNSUPPORTED_CALLBACK = "admission:unsupported_callback"
# Graph-author callbacks the framework runs outside any node body. Under closed
# admission a channel reducer must be one of these objects by identity, every
# channel must be one of these exact framework classes, and node cache/retry
# policies must carry the framework defaults; anything else refuses with
# `admission:unsupported_callback` before any candidate protocol runs.
_FRAMEWORK_REDUCERS = (add, add_messages)
_FRAMEWORK_CHANNELS = (
    AnyValue,
    BinaryOperatorAggregate,
    EphemeralValue,
    LastValue,
    LastValueAfterFinish,
    Topic,
    UntrackedValue,
)


@dataclass(frozen=True, slots=True)
class SecurityConfig:
    """Configure restrictive modules, operator DACs, auditing, and identity rules."""

    modules: Sequence[SecurityModule] = ()
    dac_overrides: DacOverrides | None = None
    audit_sink: AuditSink | None = None
    observer: SecurityObserver | None = None
    policy_timeout_s: float = 2.0
    approval_ttl_s: float = 300.0
    require_principal: bool = True
    flow_policy: SessionFlowPolicy | None = None
    host_executor: HostToolExecutor | None = None
    object_dacs: Mapping[str, ToolObjectDac] = field(default_factory=dict)
    untrusted_node_host: UntrustedNodeHost | None = None
    output_destination: str = "caller"
    output_clearance: frozenset[str] = frozenset()
    checkpoint_key: bytes | None = field(default=None, repr=False)
    analysis: Any = field(default=None, repr=False, compare=False)
    closed_admission: bool = False
    """Admit every node and branch by exact descriptor before any candidate call.

    When true, `configure_graph` builds the whole node/branch inventory through
    `admission.admit_node` and `admission.admit_branch` before any other
    compile-time protocol runs on candidate objects, refuses the first
    unsupported body, and attaches the immutable inventory as
    `_security_admission` on the builder. Effects incurred by graph
    construction before `compile(security=...)` are outside this control.
    When false (the default), behavior is unchanged.
    """
    trusted_application_nodes: frozenset[str] = frozenset()
    """Exact names of graph nodes whose bodies are trusted application code (D11).

    Requires `closed_admission=True`. Each named node must be a plain function
    added with `StateGraph.add_node`; it is admitted as `TRUSTED_APPLICATION`,
    placed `TRUSTED`/`STANDARD` and dispatched as the function captured at
    compile with the normal config. Admission binds the function's identity so
    a swapped body is refused; it does not contain or vet that code. A named
    `ToolNode` is refused (tools stay contained), a named allowlisted model
    keeps its model hook, and a name that is not a graph node is refused.
    Nothing is inferred: an undeclared plain function still refuses with
    `admission:unsupported_node_body`.
    """
    trusted_application_branches: frozenset[str] = frozenset()
    """Exact inventory names of conditional edges that are trusted application code.

    Each name has the form `<source>:branch:<branch_name>`, exactly the name
    closed admission records for the branch (for a lambda path the framework
    names the branch `condition`). Requires `closed_admission=True`. A named
    branch must be a plain synchronous function or lambda passed to
    `add_conditional_edges`; it is admitted as `TRUSTED_APPLICATION_BRANCH` and
    dispatched as the function captured at compile. Admission binds its
    identity and routing map; it does not contain or vet that code. A name
    that is not a branch of the graph, or names a pinned framework branch, is
    refused with `admission:unsupported_branch`; an undeclared custom branch
    still refuses.
    """

    def __post_init__(self) -> None:
        if type(self.closed_admission) is not bool:
            raise TypeError("closed_admission must be a bool")
        declared = self.trusted_application_nodes
        if type(declared) is not frozenset or any(
            type(item) is not str or not item for item in declared
        ):
            raise TypeError(
                "trusted_application_nodes must be a frozenset of non-empty str"
            )
        if declared and not self.closed_admission:
            raise ValueError("trusted_application_nodes requires closed_admission")
        branches = self.trusted_application_branches
        if type(branches) is not frozenset or any(
            type(item) is not str or not item for item in branches
        ):
            raise TypeError(
                "trusted_application_branches must be a frozenset of non-empty str"
            )
        if branches and not self.closed_admission:
            raise ValueError("trusted_application_branches requires closed_admission")
        if self.analysis is not None:
            from langgraph.prebuilt.security.modules.analysis_gate import AnalysisGate

            if not any(
                isinstance(module, AnalysisGate)
                and module.policy_version == self.analysis.config.policy_version
                for module in self.modules
            ):
                raise SecurityConfigurationError("analysis:missing_policy_bridge")
            for module in self.modules:
                validator = getattr(module, "validate_analysis", None)
                if validator is not None:
                    validator(self.analysis)
        object.__setattr__(self, "modules", tuple(self.modules))
        object.__setattr__(
            self, "object_dacs", MappingProxyType(dict(self.object_dacs))
        )
        object.__setattr__(self, "output_clearance", frozenset(self.output_clearance))
        if not self.output_destination:
            raise ValueError("output_destination must be non-empty")
        if any(not item for item in self.output_clearance):
            raise ValueError("output_clearance labels must be non-empty")
        if self.untrusted_node_host is not None and not isinstance(
            self.untrusted_node_host, UntrustedNodeHost
        ):
            raise TypeError("untrusted_node_host must implement UntrustedNodeHost")
        if self.checkpoint_key is None:
            object.__setattr__(self, "checkpoint_key", secrets.token_bytes(32))
        elif not self.checkpoint_key:
            raise ValueError("checkpoint_key must be non-empty")
        if self.policy_timeout_s <= 0:
            raise ValueError("policy_timeout_s must be positive")
        if self.approval_ttl_s <= 0:
            raise ValueError("approval_ttl_s must be positive")
        if self.dac_overrides is not None and not isinstance(
            self.dac_overrides, DacOverrides
        ):
            raise TypeError("dac_overrides must be DacOverrides or None")
        if (
            self.host_executor is not None
            and self.flow_policy is not None
            and not self.flow_policy.store.persistent
        ):
            raise SecurityConfigurationError(
                "host execution with session flow requires a persistent flow store"
            )

    @property
    def can_escalate(self) -> bool:
        """Whether any configured module can request durable human approval."""
        return any(module.can_escalate for module in self.modules)

    def configure_graph(self, graph: Any, *, checkpointer: Any) -> Any:
        """Place every graph operation on the shared refusing router path."""
        if self.can_escalate and checkpointer in (None, False):
            raise ValueError(
                "security modules that can escalate require a checkpointer"
            )
        admitted: dict[str, AdmittedDescriptor] = {}
        if self.closed_admission:
            # Closed admission runs before `_find_tool_nodes`, `resolve_placement`
            # and every other compile-time read of candidate objects.
            admitted = _closed_admission_inventory(self, graph)
        nodes = tuple(_find_tool_nodes(graph))
        known_tools = {name for node in nodes for name in node._security_tools_by_name}
        overrides = self.dac_overrides or DacOverrides()
        unknown = set(overrides).difference(known_tools)
        if unknown:
            names = ", ".join(sorted(unknown))
            raise ValueError(f"DAC overrides reference unknown tools: {names}")
        unknown_object_dacs = set(self.object_dacs).difference(known_tools)
        if unknown_object_dacs:
            names = ", ".join(sorted(unknown_object_dacs))
            raise ValueError(f"object DACs reference unknown tools: {names}")
        if self.flow_policy is not None:
            self.flow_policy.validate_tools(tuple(known_tools))
        if self.host_executor is not None:
            self.host_executor.validate_tools(tuple(known_tools))
        graph_tools = {
            name: tool
            for node in nodes
            for name, tool in node._security_tools_by_name.items()
        }
        object_host = ObjectManagerHost(
            checkpoint_key=self.checkpoint_key or b"",
            tools=graph_tools,
        )
        for node in nodes:
            self.configure_tool_node(
                node,
                validate_overrides=False,
                _object_host=object_host,
            )
        placement_stack = SecurityStack(
            self.modules,
            policy_timeout_s=self.policy_timeout_s,
            observer=self.observer,
            audit_sink=self.audit_sink,
            approval_ttl_s=self.approval_ttl_s,
            analysis=self.analysis,
        )
        placement_router = make_host_router(
            ObjectManagerPolicy(placement_stack, self.object_dacs), object_host
        )
        inprocess_tool_policy = any(
            getattr(module, "authorizes_inprocess_tools", False)
            for module in self.modules
        )
        for name, node_spec in graph.nodes.items():
            if self.closed_admission:
                # Admitted bodies are exact framework primitives; placement
                # comes from the descriptor, not from module-name heuristics
                # or metadata promotion.
                if name not in admitted:
                    placement_stack.close()
                    raise PermissionError(DESCRIPTOR_CHANGED)
                node_spec.runnable = MediatedNode(
                    node_spec.runnable,
                    PlacementSpec(
                        name, NodeTrust.TRUSTED, _admitted_node_kind(admitted[name])
                    ),
                    placement_router,
                    untrusted_host=self.untrusted_node_host,
                    descriptor=admitted[name],
                )
                continue
            contains_tool_node = any(_find_tool_nodes(node_spec.runnable))
            try:
                placement = resolve_placement(
                    name, node_spec.runnable, node_spec.metadata
                )
            except ValueError as exc:
                placement_stack.close()
                raise SecurityConfigurationError(str(exc)) from exc
            if contains_tool_node and (
                self.host_executor is not None or inprocess_tool_policy
            ):
                placement = PlacementSpec(
                    name,
                    NodeTrust.TRUSTED,
                    NodeKind.STANDARD,
                    promoted=True,
                    promotion_reason=(
                        (
                            "reviewed ToolNode coordinator; tool bodies use host "
                            "execution"
                        )
                        if self.host_executor is not None
                        else "Cedar-authorized operator tool runs in process"
                    ),
                )
            if (
                placement.trust is NodeTrust.UNTRUSTED
                and self.untrusted_node_host is None
            ):
                placement_stack.close()
                raise SecurityConfigurationError(
                    f"untrusted node requires a separate-process host:{name}"
                )
            if placement.promoted:
                self._audit_node_promotion(placement)
            node_spec.runnable = MediatedNode(
                node_spec.runnable,
                placement,
                placement_router,
                untrusted_host=self.untrusted_node_host,
            )
        for source, branches in graph.branches.items():
            for branch_name, branch in tuple(branches.items()):
                placement_name = f"{source}:branch:{branch_name}"
                if self.closed_admission:
                    if placement_name not in admitted:
                        placement_stack.close()
                        raise PermissionError(DESCRIPTOR_CHANGED)
                    branches[branch_name] = branch._replace(
                        path=MediatedBranch(
                            branch.path,
                            placement_name,
                            placement_router,
                            trust=NodeTrust.TRUSTED,
                            untrusted_host=self.untrusted_node_host,
                            descriptor=admitted[placement_name],
                        )
                    )
                    continue
                try:
                    placement = resolve_placement(placement_name, branch.path, None)
                except ValueError as exc:
                    placement_stack.close()
                    raise SecurityConfigurationError(str(exc)) from exc
                if (
                    placement.trust is NodeTrust.UNTRUSTED
                    and self.untrusted_node_host is None
                ):
                    placement_stack.close()
                    raise SecurityConfigurationError(
                        "untrusted branch requires a separate-process host:"
                        + placement_name
                    )
                branches[branch_name] = branch._replace(
                    path=MediatedBranch(
                        branch.path,
                        placement_name,
                        placement_router,
                        trust=placement.trust,
                        untrusted_host=self.untrusted_node_host,
                    )
                )
        if not all(
            isinstance(node_spec.runnable, MediatedNode)
            for node_spec in graph.nodes.values()
        ):
            placement_stack.close()
            raise SecurityConfigurationError("unplaceable graph node")
        if not all(
            isinstance(branch.path, MediatedBranch)
            for branches in graph.branches.values()
            for branch in branches.values()
        ):
            placement_stack.close()
            raise SecurityConfigurationError("unplaceable graph branch")
        if self.closed_admission:
            try:
                _verify_admitted_graph(admitted, graph)
            except PermissionError:
                placement_stack.close()
                raise
            graph._security_admission = tuple(admitted.values())
        graph._security_placement_stack = placement_stack
        graph._security_output_mediator = OutputMediator(
            placement_router,
            object_host,
            destination=self.output_destination,
            clearance=self.output_clearance,
        )
        graph._security_config = self
        if isinstance(checkpointer, MediatedCheckpointer):
            return checkpointer
        if isinstance(checkpointer, BaseCheckpointSaver):
            return MediatedCheckpointer(
                checkpointer,
                placement_router,
                self.checkpoint_key or b"",
                analysis=self.analysis,
            )
        return checkpointer

    def configure_compiled_graph(self, graph: Any) -> None:
        """Install the graph's refusing output route on every stream emission."""
        builder = getattr(graph, "builder", None)
        mediator = getattr(builder, "_security_output_mediator", None)
        install = getattr(graph, "_set_output_filter", None)
        if mediator is None or not callable(install):
            raise SecurityConfigurationError("compiled graph lacks output placement")
        install(
            mediator,
            mediator.acall,
            stream_output_filter=mediator.stream,
            astream_output_filter=mediator.astream,
            callback_filter=mediator.callback,
            acallback_filter=mediator.acallback,
            invoke_final_output_only=(
                self.audit_sink is None
                and self.observer is None
                and all(
                    type(module).output_emit is SecurityModule.output_emit
                    for module in self.modules
                )
            ),
        )
        if self.analysis is not None:
            from langgraph.prebuilt.analysis.adapters.agent import AgentAdapter

            input_install = getattr(graph, "_set_input_guard", None)
            if not callable(input_install):
                raise SecurityConfigurationError("analysis:missing_input_boundary")
            input_adapter = AgentAdapter(self.analysis)
            input_install(input_adapter.input_guard, input_adapter.ainput_guard)
        from langgraph.prebuilt.security.mac import register_mac_boundary

        register_mac_boundary(graph)

    def configure_tool_node(
        self,
        node: Any,
        *,
        validate_overrides: bool = True,
        _object_host: ObjectManagerHost | None = None,
    ) -> None:
        """Apply this configuration to one ToolNode."""
        existing = getattr(node, "_security_config", None)
        if existing is self:
            return
        if existing is not None:
            raise SecurityConfigurationError(
                "a secured ToolNode cannot be reconfigured or downgraded"
            )
        overrides = self.dac_overrides or DacOverrides()
        unknown = set(overrides).difference(node._security_tools_by_name)
        if validate_overrides and unknown:
            names = ", ".join(sorted(unknown))
            raise ValueError(f"DAC overrides reference unknown tools: {names}")
        unknown_object_dacs = set(self.object_dacs).difference(
            node._security_tools_by_name
        )
        if validate_overrides and unknown_object_dacs:
            names = ", ".join(sorted(unknown_object_dacs))
            raise ValueError(f"object DACs reference unknown tools: {names}")
        if self.flow_policy is not None:
            self.flow_policy.validate_tools(tuple(node._security_tools_by_name))
        if self.host_executor is not None:
            self.host_executor.validate_tools(tuple(node._security_tools_by_name))
            injected = [
                name
                for name, args in node._injected_args.items()
                if args.state
                or args.store is not None
                or args.runtime is not None
                or args.all_injected_keys
            ]
            if injected:
                raise SecurityConfigurationError(
                    "host execution does not support injected tool arguments: "
                    + ", ".join(sorted(injected))
                )
        external_dac = bool(
            self.host_executor is not None
            and getattr(self.host_executor, "authorizes_dac", False)
        )
        stack = SecurityStack(
            self.modules,
            policy_timeout_s=self.policy_timeout_s,
            observer=self.observer,
            audit_sink=self.audit_sink,
            approval_ttl_s=self.approval_ttl_s,
            analysis=self.analysis,
        )
        try:
            object_dacs = dict(self.object_dacs)
            for name, security_tool in tuple(node._security_tools_by_name.items()):
                policy = overrides.get(name, security_tool.dac)
                if (
                    external_dac
                    and name not in overrides
                    and not _has_declared_dac(node.tools_by_name[name])
                ):
                    policy = replace(
                        policy,
                        grants={"*": "x"},
                        required_scopes=frozenset(),
                        arg_grants={},
                    )
                configured_tool = Tool(
                    name=security_tool.name,
                    dac=policy,
                    effects=security_tool.effects,
                    resources=security_tool.resources,
                    security=security_tool.security,
                )
                for module in stack.modules:
                    slot = configured_tool.security.allocate(module.name)
                    module.tool_alloc_security(configured_tool, slot)
                node._security_tools_by_name[name] = configured_tool
                node._dacs_by_name[name] = policy
                profile = overrides.profiles.get(name)
                if profile is not None and name not in object_dacs:
                    object_dacs[name] = ToolObjectDac(
                        profile.readable_channels,
                        profile.readable_store_keys,
                        profile.writable_store_keys,
                    )
                if name in overrides:
                    self._audit_override(
                        name,
                        overrides.profiles.get(name, policy),
                    )
            node._configure_security(
                stack,
                audit_sink=self.audit_sink,
                require_principal=self.require_principal,
                flow_policy=self.flow_policy,
                host_executor=self.host_executor,
                host_router=(
                    make_authorized_host_router(self.host_executor)
                    if self.host_executor is not None
                    else None
                ),
                object_router=make_host_router(
                    ObjectManagerPolicy(stack, object_dacs),
                    _object_host
                    or ObjectManagerHost(
                        checkpoint_key=self.checkpoint_key or b"",
                        tools=node._security_tools_by_name,
                    ),
                ),
                object_dacs=object_dacs,
            )
            node._security_config = self
        except BaseException:
            stack.close()
            raise

    def _audit_override(self, tool_name: str, policy: Any) -> None:
        if self.audit_sink is None:
            return
        payload = (
            policy.audit_payload()
            if isinstance(policy, ToolProfile)
            else {
                "arg_grants": {
                    key: dict(value) for key, value in policy.arg_grants.items()
                },
                "grants": dict(policy.grants),
                "owner": policy.owner,
                "required_scopes": sorted(policy.required_scopes),
            }
        )
        encoded = json.dumps(
            payload,
            sort_keys=True,
            separators=(",", ":"),
        ).encode()
        self.audit_sink.write(
            AuditRecord(
                call_index=0,
                tool_name=tool_name,
                user_id="__operator__",
                args_hash=hashlib.sha256(encoded).hexdigest(),
                stage="compile",
                module="dac_override",
                verdict=Verdict.ALLOW,
                reason="operator_override",
            )
        )

    def _audit_node_promotion(self, placement: PlacementSpec) -> None:
        if self.audit_sink is None:
            return
        encoded = json.dumps(
            {
                "kind": placement.kind.value,
                "node": placement.name,
                "reason": placement.promotion_reason,
            },
            sort_keys=True,
            separators=(",", ":"),
        ).encode()
        self.audit_sink.write(
            AuditRecord(
                call_index=0,
                tool_name=placement.name,
                user_id="__operator__",
                args_hash=hashlib.sha256(encoded).hexdigest(),
                stage="compile",
                module="node_trust_override",
                verdict=Verdict.ALLOW,
                reason="operator_promotion",
            )
        )


def _closed_admission_inventory(
    config: SecurityConfig, graph: Any
) -> dict[str, AdmittedDescriptor]:
    """Admit every node and branch of an exact `StateGraph` before any protocol.

    The builder, its node specs and branch specs must be exact framework
    containers; each body is handed to `admit_node`/`admit_branch`, which refuse
    the first unsupported body with a registered `admission:` code. Node
    metadata is never consulted for admission; a promoted or foreign node is
    refused on its body alone. Every name in `trusted_application_nodes` must
    be a node of this builder, or `admission:unsupported_node_body` is raised
    before any body is admitted, and every name in
    `trusted_application_branches` must have been admitted as a trusted branch,
    or `admission:unsupported_branch` is raised.
    """
    from collections import defaultdict

    from langgraph.graph._branch import BranchSpec
    from langgraph.graph._node import StateNodeSpec
    from langgraph.graph.state import StateGraph

    if type(graph) is not StateGraph:
        raise PermissionError(UNSUPPORTED_NODE_BODY)
    nodes = graph.nodes
    branches = graph.branches
    if type(nodes) is not dict or (
        type(branches) is not dict and type(branches) is not defaultdict
    ):
        raise PermissionError(UNSUPPORTED_NODE_BODY)
    _admit_channels(graph.channels)
    declared = _declared_application_nodes(config)
    if not declared <= frozenset(nodes):
        raise PermissionError(UNSUPPORTED_NODE_BODY)
    inventory: dict[str, AdmittedDescriptor] = {}
    for name, spec in nodes.items():
        if type(name) is not str or type(spec) is not StateNodeSpec:
            raise PermissionError(UNSUPPORTED_NODE_BODY)
        metadata = spec.metadata
        if metadata is not None and type(metadata) is not dict:
            raise PermissionError(UNSUPPORTED_NODE_BODY)
        _admit_node_policies(spec)
        inventory[name] = admit_node(name, spec.runnable, config=config)
    for source, named in branches.items():
        if type(source) is not str or type(named) is not dict:
            raise PermissionError(UNSUPPORTED_BRANCH)
        for branch_name, branch in named.items():
            if type(branch_name) is not str or type(branch) is not BranchSpec:
                raise PermissionError(UNSUPPORTED_BRANCH)
            placement_name = f"{source}:branch:{branch_name}"
            inventory[placement_name] = admit_branch(
                placement_name, branch, config=config
            )
    _bind_declared_branches(config, inventory)
    return inventory


def _pinned(value: Any, pins: tuple[Any, ...]) -> bool:
    """Whether `value` is one of the pinned framework objects by identity."""
    for pin in pins:
        if value is pin:
            return True
    return False


def _admit_channels(channels: Any) -> None:
    """Refuse state channels whose update would run graph-author code.

    Every channel must be an exact framework channel class, and a
    `BinaryOperatorAggregate` may carry only a pinned reducer (`operator.add`
    or `langgraph.graph.message.add_messages`), compared by identity. Custom
    reducers and channel classes refuse with `admission:unsupported_callback`
    before any node body is read.
    """
    if type(channels) is not dict:
        raise PermissionError(UNSUPPORTED_NODE_BODY)
    for name, channel in channels.items():
        if type(name) is not str:
            raise PermissionError(UNSUPPORTED_NODE_BODY)
        kind = type(channel)
        if kind is BinaryOperatorAggregate:
            reducer = channel.operator
            if not _pinned(reducer, _FRAMEWORK_REDUCERS):
                raise PermissionError(UNSUPPORTED_CALLBACK)
        elif not _pinned(kind, _FRAMEWORK_CHANNELS):
            raise PermissionError(UNSUPPORTED_CALLBACK)


def _admit_node_policies(spec: Any) -> None:
    """Refuse node cache, retry and trace policies that carry author callbacks.

    `cache_policy.key_func` must be the framework `default_cache_key`, every
    `retry_policy.retry_on` must be the framework `default_retry_on` (an
    exception class or sequence is refused too) and `trace_policy` must be
    `None`; the framework invokes these callables outside any admitted body.
    """
    retry = spec.retry_policy
    cache = spec.cache_policy
    trace = spec.trace_policy
    if trace is not None:
        raise PermissionError(UNSUPPORTED_CALLBACK)
    if cache is not None:
        if type(cache) is not CachePolicy or cache.key_func is not default_cache_key:
            raise PermissionError(UNSUPPORTED_CALLBACK)
    if retry is None:
        return
    if type(retry) is RetryPolicy:
        policies = (retry,)
    elif type(retry) is tuple or type(retry) is list:
        policies = tuple(retry)
    else:
        raise PermissionError(UNSUPPORTED_CALLBACK)
    for policy in policies:
        if type(policy) is not RetryPolicy or policy.retry_on is not default_retry_on:
            raise PermissionError(UNSUPPORTED_CALLBACK)


def _admitted_node_kind(descriptor: AdmittedDescriptor) -> NodeKind:
    """Place a `MODEL_CALL` descriptor as a model node so its hook always runs.

    Every other kind, including `TRUSTED_APPLICATION`, is `STANDARD`: a trusted
    application node has no tool mediation of its own, but its wrapper still
    carries the descriptor, so the inventory and the RuntimeMAC binding cover it.
    """
    if descriptor.kind is AdmittedKind.MODEL_CALL:
        return NodeKind.MODEL
    return NodeKind.STANDARD


def _verify_admitted_graph(
    admitted: Mapping[str, AdmittedDescriptor], graph: Any
) -> None:
    """Require every mediated entry to wrap exactly its admitted implementation."""
    mediated: dict[str, Any] = {}
    for name, spec in graph.nodes.items():
        mediated[name] = spec.runnable
    for source, named in graph.branches.items():
        for branch_name, branch in named.items():
            mediated[f"{source}:branch:{branch_name}"] = branch.path
    if set(mediated) != set(admitted):
        raise PermissionError(DESCRIPTOR_CHANGED)
    for name, descriptor in admitted.items():
        wrapper = mediated[name]
        implementation = descriptor.implementation
        if type(implementation) is _CapturedToolNode:
            if (
                type(wrapper) is not MediatedNode
                or wrapper.runnable is not implementation.node
            ):
                raise PermissionError(DESCRIPTOR_CHANGED)
        elif type(implementation) is _CapturedModel:
            if (
                type(wrapper) is not MediatedNode
                or wrapper.runnable is not implementation.node
                or wrapper.spec.kind is not NodeKind.MODEL
            ):
                raise PermissionError(DESCRIPTOR_CHANGED)
        elif type(implementation) is _CapturedApplication:
            if (
                type(wrapper) is not MediatedNode
                or wrapper.runnable is not implementation.node
                or wrapper.spec.kind is not NodeKind.STANDARD
            ):
                raise PermissionError(DESCRIPTOR_CHANGED)
        elif (
            type(implementation) is _CapturedBranch
            or type(implementation) is _CapturedTrustedBranch
        ):
            if (
                type(wrapper) is not MediatedBranch
                or wrapper.runnable is not implementation.path
            ):
                raise PermissionError(DESCRIPTOR_CHANGED)
        else:
            raise PermissionError(DESCRIPTOR_CHANGED)
        recheck(descriptor)


def _find_tool_nodes(root: Any) -> Iterable[Any]:
    """Yield ToolNodes through builders, compiled graphs, and runnable wrappers."""
    from langgraph.prebuilt.tool_node import ToolNode

    stack: list[tuple[Any, int]] = [(root, 0)]
    visited: set[int] = set()
    while stack:
        current, depth = stack.pop()
        if current is None or depth > 12 or id(current) in visited:
            continue
        visited.add(id(current))
        if isinstance(current, ToolNode):
            yield current
            continue
        if isinstance(current, Mapping):
            stack.extend((child, depth + 1) for child in current.values())
            continue
        if isinstance(current, Sequence) and not isinstance(
            current, (str, bytes, bytearray)
        ):
            stack.extend((child, depth + 1) for child in current)
            continue
        for attribute in (
            "nodes",
            "bound",
            "func",
            "afunc",
            "runnable",
            "steps",
            "first",
            "middle",
            "last",
        ):
            child = getattr(current, attribute, None)
            if child is not None and child is not current:
                stack.append((child, depth + 1))
        closure = getattr(current, "__closure__", None)
        if closure:
            for cell in closure:
                try:
                    stack.append((cell.cell_contents, depth + 1))
                except ValueError:
                    continue
