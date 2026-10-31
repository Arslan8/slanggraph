"""Credential-custody broker over a spawn-bound Unix socketpair."""

from __future__ import annotations

import json
import os
import socket
from collections import deque
from collections.abc import Callable, Mapping
from dataclasses import dataclass, field
from threading import Event, RLock, Thread
from types import MappingProxyType
from typing import Any, Protocol, runtime_checkable

from langgraph.prebuilt.security.enforcement import AuthorityDomain, Grant, GrantRule

_MAX_FRAME = 1_048_576
_BROKER_FD_ENV = "SLANGGRAPH_BROKER_FD"
_pipe_transport: Callable[[Mapping[str, Any]], Any] | None = None
_IDENTITY_FIELDS = frozenset(
    {"principal", "principal_id", "tool", "tool_name", "grant", "grant_hash", "nonce"}
)


@dataclass(frozen=True, slots=True)
class SpawnRecord:
    """Parent-authenticated identity bound to one worker channel."""

    principal_id: str
    tool_name: str
    grant_hash: str
    nonce: str

    def __post_init__(self) -> None:
        if not all((self.principal_id, self.tool_name, self.grant_hash, self.nonce)):
            raise ValueError("spawn record fields must be non-empty")


@dataclass(frozen=True, slots=True)
class IssuedCredential:
    """A broker-owned credential and its issuer-attested exact scope."""

    token: str = field(repr=False)
    scope: Mapping[str, str]

    def __post_init__(self) -> None:
        if not self.token:
            raise ValueError("issued credential token must be non-empty")
        object.__setattr__(self, "scope", MappingProxyType(dict(self.scope)))


@runtime_checkable
class CredentialIssuer(Protocol):
    """Mint one short-lived credential for one exact service rule."""

    def issue(
        self, spawn: SpawnRecord, rule: GrantRule, scope: Mapping[str, str]
    ) -> IssuedCredential: ...


class GitHubAppIssuer:
    """Mint GitHub App installation tokens through an injected trusted client."""

    def __init__(
        self,
        mint: Callable[[SpawnRecord, Mapping[str, str]], str],
    ) -> None:
        self._mint = mint

    def issue(
        self, spawn: SpawnRecord, rule: GrantRule, scope: Mapping[str, str]
    ) -> IssuedCredential:
        return IssuedCredential(self._mint(spawn, scope), scope)


class StsSessionIssuer:
    """Mint an STS session credential with the rule as its session policy."""

    def __init__(
        self,
        mint: Callable[[SpawnRecord, Mapping[str, str]], str],
    ) -> None:
        self._mint = mint

    def issue(
        self, spawn: SpawnRecord, rule: GrantRule, scope: Mapping[str, str]
    ) -> IssuedCredential:
        return IssuedCredential(self._mint(spawn, scope), scope)


@dataclass(frozen=True, slots=True)
class BrokerAuditRecord:
    """Token-free evidence for one broker decision."""

    principal_id: str
    tool_name: str
    grant_hash: str
    spawn_nonce: str
    service: str
    operation: str
    rule_id: str
    allowed: bool
    reason: str


class BrokerSession:
    """One parent endpoint and one worker descriptor bound to a spawn record."""

    def __init__(
        self,
        parent: socket.socket,
        worker: socket.socket,
        thread: Thread,
        stopped: Event | None = None,
    ) -> None:
        self._parent = parent
        self._worker = worker
        self._thread = thread
        self._stopped = stopped if stopped is not None else Event()

    @property
    def terminated(self) -> bool:
        """Whether the channel's active handler has finished executing."""
        return not self._thread.is_alive()

    @property
    def worker_fd(self) -> int:
        """Return the non-inheritable worker endpoint for explicit `pass_fds`."""
        return self._worker.fileno()

    def detach_worker(self) -> int:
        """Transfer ownership of the worker endpoint to the process launcher."""
        descriptor = self._worker.detach()
        os.set_inheritable(descriptor, False)
        return descriptor

    def close_parent(self) -> None:
        """Close the parent endpoint and wait briefly for its broker thread."""
        self._stopped.set()
        try:
            self._parent.shutdown(socket.SHUT_RDWR)
        except OSError:
            pass
        self._parent.close()
        self._thread.join(timeout=1)

    def close(self) -> None:
        """Close both endpoints owned by this session."""
        try:
            self._worker.close()
        finally:
            self.close_parent()


class CredentialBroker:
    """Perform service operations while retaining all credentials in the parent."""

    def __init__(
        self,
        issuers: Mapping[str, CredentialIssuer],
        services: Mapping[
            str,
            Callable[[str, str, Mapping[str, Any], SpawnRecord], Any],
        ],
    ) -> None:
        if not issuers or not services:
            raise ValueError("broker requires issuers and service handlers")
        self.issuers = MappingProxyType(dict(issuers))
        self.services = MappingProxyType(dict(services))
        self._audit: deque[BrokerAuditRecord] = deque(maxlen=4096)
        self._lock = RLock()

    def open_session(self, spawn: SpawnRecord, grant: Grant) -> BrokerSession:
        """Create the channel before confinement and bind it to trusted state."""
        if grant.digest != spawn.grant_hash:
            raise ValueError("spawn record does not match grant")
        if (
            grant.principal_id != spawn.principal_id
            or grant.tool_name != spawn.tool_name
        ):
            raise ValueError("spawn identity does not match grant")
        parent, worker = socket.socketpair(socket.AF_UNIX, socket.SOCK_STREAM)
        parent.set_inheritable(False)
        worker.set_inheritable(False)
        stopped = Event()
        thread = Thread(
            target=self._serve,
            args=(parent, spawn, grant, stopped),
            name=f"slanggraph-broker-{spawn.nonce[:8]}",
            daemon=True,
        )
        thread.start()
        return BrokerSession(parent, worker, thread, stopped)

    def audit_records(self) -> tuple[BrokerAuditRecord, ...]:
        """Return bounded token-free broker evidence."""
        with self._lock:
            return tuple(self._audit)

    def _serve(
        self, channel: socket.socket, spawn: SpawnRecord, grant: Grant, stopped: Event
    ) -> None:
        stream = channel.makefile("rwb", buffering=0)
        try:
            while not stopped.is_set():
                frame = stream.readline(_MAX_FRAME + 1)
                if not frame or stopped.is_set():
                    return
                if len(frame) > _MAX_FRAME or not frame.endswith(b"\n"):
                    # Do not interpret a suffix of an oversized frame as a new
                    # authorized request.
                    return
                response = self._handle_frame(frame, spawn, grant)
                try:
                    encoded = json.dumps(
                        response,
                        sort_keys=True,
                        separators=(",", ":"),
                        allow_nan=False,
                    ).encode()
                    if len(encoded) + 1 > _MAX_FRAME:
                        raise ValueError("response too large")
                except (TypeError, ValueError, RecursionError):
                    # Never expose arbitrary object reprs or exception text.
                    encoded = b'{"status":"denied","error":"broker:invalid_response"}'
                channel.sendall(encoded + b"\n")
        except (OSError, ValueError, RecursionError):
            return
        finally:
            try:
                channel.shutdown(socket.SHUT_RDWR)
            except OSError:
                pass
            try:
                stream.close()
            except OSError:
                pass

    def _handle_frame(
        self, frame: bytes, spawn: SpawnRecord, grant: Grant
    ) -> Mapping[str, Any]:
        if len(frame) > _MAX_FRAME or not frame.endswith(b"\n"):
            return {"error": "broker:invalid_frame", "status": "denied"}
        try:
            request = json.loads(frame)
        except (json.JSONDecodeError, UnicodeDecodeError):
            return {"error": "broker:invalid_json", "status": "denied"}
        if not isinstance(request, dict) or _IDENTITY_FIELDS.intersection(request):
            return {"error": "broker:worker_identity_rejected", "status": "denied"}
        service = request.get("service")
        operation = request.get("operation")
        payload = request.get("payload", {})
        if (
            not isinstance(service, str)
            or not service
            or not isinstance(operation, str)
            or not operation
            or not isinstance(payload, dict)
        ):
            return {"error": "broker:invalid_request", "status": "denied"}
        candidates = [
            rule
            for rule in grant.rules
            if rule.domain is AuthorityDomain.SERVICE
            and rule.selector == service
            and rule.operation == operation
        ]
        if len(candidates) != 1:
            self._record(spawn, service, operation, "", False, "rule_not_unique")
            return {"error": "broker:not_granted", "status": "denied"}
        rule = candidates[0]
        issuer_name = rule.conditions.get("issuer")
        if not isinstance(issuer_name, str) or issuer_name not in self.issuers:
            self._record(
                spawn, service, operation, rule.rule_id, False, "issuer_unavailable"
            )
            return {"error": "broker:issuer_unavailable", "status": "denied"}
        handler = self.services.get(service)
        if handler is None:
            self._record(
                spawn, service, operation, rule.rule_id, False, "service_unavailable"
            )
            return {"error": "broker:service_unavailable", "status": "denied"}
        scope = {
            key: str(value) for key, value in rule.conditions.items() if key != "issuer"
        }
        try:
            credential = self.issuers[issuer_name].issue(spawn, rule, scope)
            if dict(credential.scope) != scope:
                raise PermissionError("credential_scope_mismatch")
            result = handler(
                credential.token,
                operation,
                MappingProxyType(dict(payload)),
                spawn,
            )
        except BaseException:
            self._record(
                spawn, service, operation, rule.rule_id, False, "service_failure"
            )
            return {"error": "broker:service_failure", "status": "denied"}
        self._record(spawn, service, operation, rule.rule_id, True, "exact_scope")
        return {"result": result, "status": "ok"}

    def _record(
        self,
        spawn: SpawnRecord,
        service: str,
        operation: str,
        rule_id: str,
        allowed: bool,
        reason: str,
    ) -> None:
        with self._lock:
            self._audit.append(
                BrokerAuditRecord(
                    spawn.principal_id,
                    spawn.tool_name,
                    spawn.grant_hash,
                    spawn.nonce,
                    service,
                    operation,
                    rule_id,
                    allowed,
                    reason,
                )
            )


def broker_request(
    service: str, operation: str, payload: Mapping[str, Any] | None = None
) -> Any:
    """Request a brokered service operation from a confined worker.

    Identity is deliberately absent from this protocol. The parent associates
    the inherited socket endpoint with its authenticated spawn record.
    """
    if _pipe_transport is not None:
        return _pipe_transport(
            {"service": service, "operation": operation, "payload": dict(payload or {})}
        )
    raw_fd = os.environ.get(_BROKER_FD_ENV)
    if raw_fd is None:
        raise PermissionError("broker:channel_unavailable")
    try:
        descriptor = int(raw_fd)
    except ValueError as exc:
        raise PermissionError("broker:invalid_channel") from exc
    request = json.dumps(
        {"operation": operation, "payload": dict(payload or {}), "service": service},
        sort_keys=True,
        separators=(",", ":"),
    ).encode()
    if len(request) + 1 > _MAX_FRAME:
        raise ValueError("broker request exceeds frame limit")
    duplicate = os.dup(descriptor)
    try:
        pending = memoryview(request + b"\n")
        while pending:
            written = os.write(duplicate, pending)
            if written <= 0:
                raise PermissionError("broker:channel_closed")
            pending = pending[written:]
        response = bytearray()
        while len(response) <= _MAX_FRAME:
            chunk = os.read(duplicate, min(65_536, _MAX_FRAME + 1 - len(response)))
            if not chunk:
                break
            response.extend(chunk)
            if response.endswith(b"\n"):
                break
        response_frame = bytes(response)
        if (
            not response_frame
            or len(response_frame) > _MAX_FRAME
            or not response_frame.endswith(b"\n")
        ):
            raise PermissionError("broker:invalid_response")
        response = json.loads(response_frame)
        if not isinstance(response, dict) or response.get("status") != "ok":
            reason = (
                response.get("error", "broker:denied")
                if isinstance(response, dict)
                else "broker:invalid_response"
            )
            raise PermissionError(str(reason))
        return response.get("result")
    finally:
        os.close(duplicate)
