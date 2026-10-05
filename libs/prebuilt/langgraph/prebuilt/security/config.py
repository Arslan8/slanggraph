"""Public configuration and compile-time setup for security mediation."""

from __future__ import annotations

import hashlib
import json
from collections.abc import Iterable, Mapping, Sequence
from dataclasses import dataclass
from typing import Any

from langgraph.prebuilt.security.descriptor import DacOverrides
from langgraph.prebuilt.security.hooks import SecurityModule
from langgraph.prebuilt.security.stack import SecurityStack
from langgraph.prebuilt.security.types import AuditRecord, AuditSink, Tool, Verdict


@dataclass(frozen=True, slots=True)
class SecurityConfig:
    """Configure restrictive modules, operator DACs, auditing, and identity rules."""

    modules: Sequence[SecurityModule] = ()
    dac_overrides: DacOverrides | None = None
    audit_sink: AuditSink | None = None
    policy_timeout_s: float = 2.0
    require_principal: bool = True

    def __post_init__(self) -> None:
        object.__setattr__(self, "modules", tuple(self.modules))
        if self.policy_timeout_s <= 0:
            raise ValueError("policy_timeout_s must be positive")
        if self.dac_overrides is not None and not isinstance(
            self.dac_overrides, DacOverrides
        ):
            raise TypeError("dac_overrides must be DacOverrides or None")

    @property
    def can_escalate(self) -> bool:
        """Whether any configured module can request durable human approval."""
        return any(module.can_escalate for module in self.modules)

    def configure_graph(self, graph: Any, *, checkpointer: Any) -> None:
        """Apply this configuration to every statically reachable ToolNode."""
        if self.can_escalate and checkpointer in (None, False):
            raise ValueError(
                "security modules that can escalate require a checkpointer"
            )
        nodes = tuple(_find_tool_nodes(graph))
        known_tools = {name for node in nodes for name in node._security_tools_by_name}
        overrides = self.dac_overrides or DacOverrides()
        unknown = set(overrides).difference(known_tools)
        if unknown:
            names = ", ".join(sorted(unknown))
            raise ValueError(f"DAC overrides reference unknown tools: {names}")
        for node in nodes:
            self.configure_tool_node(node, validate_overrides=False)
        graph._security_config = self

    def configure_tool_node(
        self, node: Any, *, validate_overrides: bool = True
    ) -> None:
        """Apply this configuration to one ToolNode."""
        if getattr(node, "_security_config", None) is self:
            return
        overrides = self.dac_overrides or DacOverrides()
        unknown = set(overrides).difference(node._security_tools_by_name)
        if validate_overrides and unknown:
            names = ", ".join(sorted(unknown))
            raise ValueError(f"DAC overrides reference unknown tools: {names}")
        stack = SecurityStack(self.modules, policy_timeout_s=self.policy_timeout_s)
        try:
            for name, security_tool in tuple(node._security_tools_by_name.items()):
                policy = overrides.get(name, security_tool.dac)
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
                if name in overrides:
                    self._audit_override(name, policy)
            node._configure_security(
                stack,
                audit_sink=self.audit_sink,
                require_principal=self.require_principal,
            )
            node._security_config = self
        except BaseException:
            stack.close()
            raise

    def _audit_override(self, tool_name: str, policy: Any) -> None:
        if self.audit_sink is None:
            return
        encoded = json.dumps(
            {
                "arg_grants": {
                    key: dict(value) for key, value in policy.arg_grants.items()
                },
                "grants": dict(policy.grants),
                "owner": policy.owner,
                "required_scopes": sorted(policy.required_scopes),
            },
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
