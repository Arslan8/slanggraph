"""Shared full-Argus configuration for application resource monitors."""

from __future__ import annotations

from collections.abc import Mapping, Sequence

from langchain_core.tools import BaseTool
from langgraph.prebuilt.security import (
    CedarObjectAuthorizer,
    CedarPolicySet,
    DacOverrides,
    EnforcementKind,
    MemoryAuditSink,
    ObjectPolicyHostExecutor,
    SecurityConfig,
    ToolDac,
    parse_security_manifest,
)
from langgraph.prebuilt.security.object_policy import _language_sandbox_owner_policy
from native_host import NATIVE_HOST

FS_CLASS = """class fs {
 operations read write truncate
 object path
 normalizer fs.realpath
 attrs
 enforced_by kernel
}"""


def monitored_security(
    tools: Sequence[BaseTool],
    *,
    dispatcher,
    resources: Sequence,
    permissions: Mapping[str, Sequence[str]],
    trusted_nodes: Sequence[str] = (),
    trusted_branches: Sequence[str] = (),
):
    """Build one closed-admission policy over several typed resource tools."""
    declarations = [FS_CLASS]
    by_class = {}
    for resource in resources:
        declaration = resource.class_declaration(enforced_by="broker")
        previous = by_class.setdefault(resource.class_name, declaration)
        if previous != declaration:
            raise ValueError("conflicting resource class declarations")
    declarations.extend(by_class.values())
    blocks = []
    for item in tools:
        lines = [f"runs {NATIVE_HOST}", *(permissions[item.name]), "returns normal"]
        blocks.append(f"tool {item.name} {{\n" + "\n".join(lines) + "\n}")
    parsed = parse_security_manifest(
        "\n".join((*declarations, *blocks)),
        enforcers={
            EnforcementKind.KERNEL: dispatcher,
            EnforcementKind.BROKER: dispatcher,
        },
    )
    policies = CedarPolicySet(
        {item.name: _language_sandbox_owner_policy(parsed.tools[item.name]) for item in tools},
        'permit(principal == slangGraph::User::"alice", action, resource);',
    )
    executor = ObjectPolicyHostExecutor(
        CedarObjectAuthorizer(parsed, policies),
        dispatcher,
        tool_owners={item.name: "application" for item in tools},
    )
    executor.validate_tools(tuple(item.name for item in tools))
    audit = MemoryAuditSink()
    config = SecurityConfig(
        host_executor=executor,
        dac_overrides=DacOverrides({item.name: ToolDac("__cedar__", {"*": "x"}) for item in tools}),
        audit_sink=audit,
        closed_admission=True,
        trusted_application_nodes=frozenset(trusted_nodes),
        trusted_application_branches=frozenset(trusted_branches),
    )
    return config, audit
