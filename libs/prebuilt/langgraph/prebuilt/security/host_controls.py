"""Translate shared policy vocabulary into obligations, without asserting support."""

from langgraph.prebuilt.security.enforcement import AuthorityDomain, GrantRule
from langgraph.prebuilt.security.execution import HostExecutionDenied
from langgraph.prebuilt.security.object_policy import EnforcementKind, ObjectGrantLine


def host_control_rule(line: ObjectGrantLine) -> GrantRule | None:
    """Preserve a host requirement for concrete capability negotiation."""
    if line.class_name not in {"cpu", "syscalls"}:
        return None
    if line.enforcer is not EnforcementKind.KERNEL or line.attributes or line.lowering:
        raise HostExecutionDenied(f"host_control:invalid_contract:{line.line_id}")
    if line.class_name == "cpu":
        if line.operation not in {"per_process", "aggregate"}:
            raise HostExecutionDenied(f"host_control:invalid_cpu_scope:{line.line_id}")
        try:
            maximum = int(line.selector)
        except ValueError:
            raise HostExecutionDenied(
                f"host_control:invalid_cpu_budget:{line.line_id}"
            ) from None
        domain = AuthorityDomain.RESOURCE_LIMIT
        operation = "limit"
        selector = "cpu_ms" if line.operation == "per_process" else "aggregate_cpu_ms"
        conditions = {"maximum": maximum}
    else:
        if line.operation != "filter":
            raise HostExecutionDenied(
                f"host_control:invalid_syscall_operation:{line.line_id}"
            )
        domain, operation = AuthorityDomain.PROCESS, "syscall_set"
        selector, conditions = line.selector.removeprefix("@"), {}
    return GrantRule(
        line.line_id,
        domain,
        operation,
        selector,
        conditions,
        line.requirement,
        line.provenance,
    )
