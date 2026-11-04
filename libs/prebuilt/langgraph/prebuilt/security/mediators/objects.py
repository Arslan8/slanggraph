"""Grant-scoped transport for object-bound typed clients.

Worker aliases only locate objects. They confer no authority: the broker checks
its authenticated invocation's effective grant after resolving an alias.
"""

from __future__ import annotations

import os
import secrets
import time
from contextlib import contextmanager
from contextvars import ContextVar
from dataclasses import dataclass
from typing import Any

from langgraph.prebuilt.security.broker import broker_request
from langgraph.prebuilt.security.enforcement import (
    ExecutionContext,
    HostAttestation,
    SupportLevel,
)
from langgraph.prebuilt.security.execution import HostExecutionDenied
from langgraph.prebuilt.security.resource_mediator import ResourceInvocation

_local: ContextVar[Any] = ContextVar("object_resource_transport", default=None)


class ResourceReleaseError(RuntimeError):
    """Cleanup failed after activation; completed effects cannot be ruled out."""


@dataclass(frozen=True)
class ResourceReference:
    """Opaque broker address for OS-sandboxed code, including non-Python clients.

    Send `service`, operation and payload over the inherited broker channel.
    Possession of this address never substitutes for an authorized grant.
    """

    service: str

    def request(self, operation: str, payload: dict[str, Any] | None = None) -> Any:
        return broker_request(self.service, operation, payload or {})


def request_object(identity, export, operation, payload):
    local = _local.get()
    if local is not None:
        return local(identity, operation, payload)
    return broker_request("resource:" + export, operation, payload)


def request_resource(class_name, selector, operation, payload):
    """Dispatch a selector-bound request locally or over the object broker."""
    local = _local.get()
    if local is not None:
        return local((class_name, selector), operation, payload)
    from langgraph.prebuilt.security.object_broker import object_request

    return object_request(class_name, operation, selector, payload)


@contextmanager
def local_resources(resources, principal, call, grant):
    """Install exact-object dispatch for an admitted in-process invocation.

    This is explicit trusted-runtime evidence, not an OS isolation attestation.
    OS capabilities and protected-file custody are deliberately unavailable.
    """
    if (grant.principal_id, grant.tool_name, grant.call_id) != (
        principal.user_id,
        call.tool.name,
        call.call_id,
    ) or grant.enforcement_waivers:
        raise HostExecutionDenied("resource:grant_binding")
    nonce = secrets.token_hex(24)
    now = time.time()
    host = HostAttestation(
        "trusted-inprocess",
        nonce,
        "process:" + str(os.getpid()),
        "verified-python",
        now,
        now + 60,
        frozenset(),
        {},
        {"mechanism": "manifest-admission", "os_isolation": False},
        "explicit-tcb",
    )
    worker = ExecutionContext(
        call.call_id,
        str(os.getpid()),
        host.boot_id,
        {},
        grant.digest,
        "inprocess",
        nonce,
    )
    context = ResourceInvocation(
        principal.user_id,
        principal.session_id,
        call.tool.name,
        call.call_id,
        grant.digest,
        worker,
    )
    routes = {}
    bound_lines = set()
    activated = []
    pending = []
    active = True

    def check(adapter, line):
        support = adapter.assess(line, host)
        if (
            support.support is not SupportLevel.EXACT
            or support.required_capabilities
            or support.protected_paths
        ):
            raise HostExecutionDenied("resource:unsupported_inprocess_binding")

    def dispatch(identity, operation, payload):
        if not active:
            raise HostExecutionDenied("resource:invocation_closed")
        entry = routes.get((identity, operation))
        if entry is None:
            raise HostExecutionDenied("resource:not_granted")
        adapter, line = entry
        check(adapter, line)
        return adapter.invoke(line, payload, context)

    token = None
    try:
        for resource in resources:
            adapter = resource.adapter
            lines = tuple(line for line in grant.lines if resource._matches(line))
            for line in lines:
                check(adapter, line)
                identity = (
                    resource._object_id
                    if resource._object_id is not None
                    else (resource.class_name, line.selector)
                )
                key = (identity, line.operation)
                if key in routes:
                    raise HostExecutionDenied("resource:ambiguous_grant")
                routes[key] = (adapter, line)
                bound_lines.add(line.line_id)
            if lines:
                pending.append((adapter, lines))
        # Reject declared custom authority that has no registered implementation.
        if any(
            line.class_name != "fs" and line.line_id not in bound_lines
            for line in grant.lines
        ):
            raise HostExecutionDenied("resource:unbound_grant")
        for adapter, lines in pending:
            activated.append(adapter)
            if adapter.activate is not None:
                adapter.activate(lines, context)
        token = _local.set(dispatch)
        yield
    finally:
        active = False
        if token is not None:
            _local.reset(token)
        failures = []
        for adapter in reversed(activated):
            try:
                if adapter.release is not None:
                    adapter.release(context)
            except Exception as exc:
                failures.append(exc)
        if failures:
            raise ResourceReleaseError("resource:release_failed") from failures[0]
