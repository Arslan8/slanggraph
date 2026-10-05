"""Graph-independent public types used by security modules."""

from __future__ import annotations

from collections.abc import Iterator, Mapping, MutableMapping, Sequence
from dataclasses import dataclass, field
from enum import Enum
from threading import RLock
from types import MappingProxyType
from typing import Any, Protocol, runtime_checkable

from langgraph.prebuilt.security.descriptor import Effect, ResourceArg, ToolDac


class Slot(MutableMapping[str, Any]):
    """Small thread-safe mutable mapping owned by one security module."""

    __slots__ = ("_lock", "_values")

    def __init__(self, values: Mapping[str, Any] | None = None) -> None:
        self._values = dict(values or {})
        self._lock = RLock()

    def __getitem__(self, key: str) -> Any:
        with self._lock:
            return self._values[key]

    def __setitem__(self, key: str, value: Any) -> None:
        with self._lock:
            self._values[key] = value

    def __delitem__(self, key: str) -> None:
        with self._lock:
            del self._values[key]

    def __iter__(self) -> Iterator[str]:
        with self._lock:
            return iter(tuple(self._values))

    def __len__(self) -> int:
        with self._lock:
            return len(self._values)

    def snapshot(self) -> Mapping[str, Any]:
        """Return an immutable shallow snapshot of the slot."""
        with self._lock:
            return MappingProxyType(dict(self._values))

    def clone(self) -> Slot:
        """Return an independent slot initialized from this slot."""
        return Slot(self.snapshot())


class Blobs(Mapping[str, Slot]):
    """Map security-module names to their private mutable slots."""

    __slots__ = ("_lock", "_slots")

    def __init__(self, values: Mapping[str, Slot | Mapping[str, Any]] | None = None):
        self._slots: dict[str, Slot] = {}
        self._lock = RLock()
        for name, value in (values or {}).items():
            self._slots[name] = value if isinstance(value, Slot) else Slot(value)

    def __getitem__(self, key: str) -> Slot:
        with self._lock:
            return self._slots[key]

    def __iter__(self) -> Iterator[str]:
        with self._lock:
            return iter(tuple(self._slots))

    def __len__(self) -> int:
        with self._lock:
            return len(self._slots)

    def allocate(self, module_name: str) -> Slot:
        """Return the named slot, allocating it exactly once if absent."""
        if not module_name:
            raise ValueError("module name must be non-empty")
        with self._lock:
            return self._slots.setdefault(module_name, Slot())

    def clone(self) -> Blobs:
        """Copy every module slot for an independent principal or tool."""
        with self._lock:
            return Blobs({name: slot.clone() for name, slot in self._slots.items()})


@dataclass(frozen=True, slots=True)
class Principal:
    """Authenticated identity and authority bound outside graph state."""

    user_id: str
    roles: frozenset[str]
    scopes: frozenset[str]
    session_id: str
    delegated_by: str | None = None
    security: Blobs = field(default_factory=Blobs, compare=False)

    def __post_init__(self) -> None:
        if not self.user_id or not self.session_id:
            raise ValueError("principal user_id and session_id must be non-empty")
        object.__setattr__(self, "roles", frozenset(self.roles))
        object.__setattr__(self, "scopes", frozenset(self.scopes))


@dataclass(frozen=True, slots=True)
class Tool:
    """Security representation of an executable tool."""

    name: str
    dac: ToolDac
    effects: frozenset[Effect]
    resources: tuple[ResourceArg, ...]
    security: Blobs = field(default_factory=Blobs, compare=False)

    def __post_init__(self) -> None:
        if not self.name:
            raise ValueError("tool name must be non-empty")
        object.__setattr__(self, "effects", frozenset(self.effects))
        object.__setattr__(self, "resources", tuple(self.resources))


class Verdict(str, Enum):
    """Possible outcomes of a security-policy hook."""

    ALLOW = "allow"
    DENY = "deny"
    TRANSFORM = "transform"
    ESCALATE = "escalate"


@dataclass(frozen=True, slots=True)
class EscalationRequest:
    """Redacted human-approval request emitted by a policy module."""

    request_id: str
    reason: str
    tool_name: str
    call_id: str
    metadata: Mapping[str, Any] = field(default_factory=dict)

    def __post_init__(self) -> None:
        if not all((self.request_id, self.reason, self.tool_name, self.call_id)):
            raise ValueError("escalation identifiers and reason must be non-empty")
        object.__setattr__(self, "metadata", MappingProxyType(dict(self.metadata)))

    def to_payload(self) -> Mapping[str, Any]:
        """Return the argument-free payload passed to LangGraph `interrupt()`."""
        return MappingProxyType(
            {
                "type": "security_approval",
                "request_id": self.request_id,
                "reason": self.reason,
                "tool_name": self.tool_name,
                "call_id": self.call_id,
                "metadata": dict(self.metadata),
            }
        )


@dataclass(frozen=True, slots=True)
class Approval:
    """Human response to an `EscalationRequest`."""

    request_id: str
    approved: bool
    approver: str
    reason: str = ""

    def __post_init__(self) -> None:
        if not self.request_id or not self.approver:
            raise ValueError("approval request_id and approver must be non-empty")


@dataclass(frozen=True, slots=True)
class Decision:
    """One policy hook's verdict and optional transform or escalation."""

    verdict: Verdict
    reason: str
    new_args: Mapping[str, Any] | None = None
    escalation: EscalationRequest | None = None

    def __post_init__(self) -> None:
        if not self.reason:
            raise ValueError("decision reason must be non-empty")
        if self.verdict is Verdict.TRANSFORM:
            if self.new_args is None or self.escalation is not None:
                raise ValueError("TRANSFORM requires new_args and forbids escalation")
            object.__setattr__(self, "new_args", MappingProxyType(dict(self.new_args)))
        elif self.verdict is Verdict.ESCALATE:
            if self.escalation is None or self.new_args is not None:
                raise ValueError("ESCALATE requires escalation and forbids new_args")
        elif self.new_args is not None or self.escalation is not None:
            raise ValueError("ALLOW and DENY cannot carry transform or escalation data")


@dataclass(frozen=True, slots=True)
class AuditRecord:
    """Hash-chainable record of one security enforcement stage."""

    call_index: int
    tool_name: str
    user_id: str
    args_hash: str
    stage: str
    module: str
    verdict: Verdict
    reason: str
    prev_hash: str = ""
    hash: str = ""

    def __post_init__(self) -> None:
        if self.call_index < 0:
            raise ValueError("audit call_index must be non-negative")
        if not self.tool_name or not self.user_id or not self.stage:
            raise ValueError("audit tool, user, and stage must be non-empty")


@runtime_checkable
class AuditSink(Protocol):
    """Storage protocol implemented by security audit sinks."""

    def write(self, record: AuditRecord) -> AuditRecord:
        """Persist a record and return its finalized hash-chain form."""
        ...

    def records(self) -> Sequence[AuditRecord]:
        """Return records in append order."""
        ...

    def verify(self) -> tuple[bool, int | None]:
        """Return integrity status and the first invalid record index."""
        ...


@dataclass(frozen=True, slots=True)
class ToolCall:
    """Normalized security request for one physical tool execution."""

    tool: Tool
    args: Mapping[str, Any]
    normalized: Mapping[str, Any]
    call_id: str
    call_index: int
    history: Sequence[AuditRecord] = ()

    def __post_init__(self) -> None:
        if not self.call_id or self.call_index < 0:
            raise ValueError("tool call id must be non-empty and index non-negative")
        object.__setattr__(self, "args", MappingProxyType(dict(self.args)))
        object.__setattr__(self, "normalized", MappingProxyType(dict(self.normalized)))
        object.__setattr__(self, "history", tuple(self.history))
