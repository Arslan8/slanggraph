"""Redacted structured observability for security policy decisions."""

from __future__ import annotations

import hashlib
import json
import logging
from collections import Counter
from collections.abc import Mapping, Sequence
from dataclasses import asdict, dataclass
from threading import RLock
from typing import Any, Protocol, runtime_checkable

from langgraph.prebuilt.security.types import AuditRecord, AuditSink, Verdict


@dataclass(frozen=True, slots=True)
class SecurityEvent:
    """One redacted policy-hook observation."""

    stage: str
    module: str
    verdict: Verdict
    reason: str
    latency_ms: float
    user_id: str
    tool_name: str | None = None
    call_index: int | None = None
    args_hash: str = ""

    def attributes(self) -> Mapping[str, str | int | float]:
        """Return low-cardinality attributes suitable for traces and logs."""
        values: dict[str, str | int | float] = {
            "security.stage": self.stage,
            "security.module": self.module,
            "security.verdict": self.verdict.value,
            "security.reason": self.reason,
            "security.latency_ms": self.latency_ms,
            "security.user_id": self.user_id,
        }
        if self.tool_name is not None:
            values["security.tool_name"] = self.tool_name
        if self.call_index is not None:
            values["security.call_index"] = self.call_index
        return values


@runtime_checkable
class SecurityObserver(Protocol):
    """Consumer of redacted security events."""

    def record(self, event: SecurityEvent) -> None:
        """Record one event without receiving raw tool arguments."""
        ...


class MemorySecurityObserver:
    """Thread-safe event collector with verdict counters."""

    def __init__(self) -> None:
        self._events: list[SecurityEvent] = []
        self._counts: Counter[tuple[str, str, Verdict]] = Counter()
        self._lock = RLock()

    def record(self, event: SecurityEvent) -> None:
        with self._lock:
            self._events.append(event)
            self._counts[(event.stage, event.module, event.verdict)] += 1

    def events(self) -> tuple[SecurityEvent, ...]:
        """Return an immutable event snapshot."""
        with self._lock:
            return tuple(self._events)

    def counters(self) -> Mapping[tuple[str, str, Verdict], int]:
        """Return a snapshot of stage/module/verdict counters."""
        with self._lock:
            return dict(self._counts)


class LoggingSecurityObserver:
    """Emit structured, argument-free policy events through standard logging."""

    def __init__(self, logger: logging.Logger | None = None) -> None:
        self.logger = logger or logging.getLogger("langgraph.security")

    def record(self, event: SecurityEvent) -> None:
        self.logger.info("security_policy", extra={"security": asdict(event)})


class OpenTelemetrySecurityObserver:
    """Adapt OpenTelemetry-compatible tracer and counter objects without a hard dependency."""

    def __init__(self, tracer: Any, counter: Any | None = None) -> None:
        self.tracer = tracer
        self.counter = counter

    def record(self, event: SecurityEvent) -> None:
        span = self.tracer.start_span("langgraph.security.policy")
        try:
            for key, value in event.attributes().items():
                span.set_attribute(key, value)
        finally:
            span.end()
        if self.counter is not None:
            self.counter.add(
                1,
                {
                    "stage": event.stage,
                    "module": event.module,
                    "verdict": event.verdict.value,
                },
            )


class _CompositeSecurityObserver:
    def __init__(self, observers: Sequence[SecurityObserver]) -> None:
        self.observers = tuple(observers)

    def record(self, event: SecurityEvent) -> None:
        for observer in self.observers:
            try:
                observer.record(event)
            except Exception:
                logging.getLogger("langgraph.security").exception(
                    "security observer failed"
                )


class _AuditSecurityObserver:
    def __init__(self, sink: AuditSink) -> None:
        self.sink = sink

    def record(self, event: SecurityEvent) -> None:
        if event.tool_name is None or event.call_index is None:
            return
        self.sink.write(
            AuditRecord(
                call_index=event.call_index,
                tool_name=event.tool_name,
                user_id=event.user_id,
                args_hash=event.args_hash,
                stage=event.stage,
                module=event.module,
                verdict=event.verdict,
                reason=event.reason,
            )
        )


def compose_observer(
    observer: SecurityObserver | None, audit_sink: AuditSink | None
) -> SecurityObserver | None:
    """Combine optional telemetry and audit consumers."""
    observers: list[SecurityObserver] = []
    if observer is not None:
        observers.append(observer)
    if audit_sink is not None:
        observers.append(_AuditSecurityObserver(audit_sink))
    if not observers:
        return None
    return _CompositeSecurityObserver(observers)


def hash_args(args: Mapping[str, Any]) -> str:
    """Hash arguments for correlation without exposing their values."""
    encoded = json.dumps(
        dict(args), sort_keys=True, default=repr, separators=(",", ":")
    ).encode()
    return hashlib.sha256(encoded).hexdigest()


def langsmith_metadata(event: SecurityEvent) -> dict[str, Any]:
    """Return redacted metadata suitable for a LangSmith run."""
    return {
        "security": {
            "stage": event.stage,
            "module": event.module,
            "verdict": event.verdict.value,
            "reason": event.reason,
            "tool_name": event.tool_name,
            "call_index": event.call_index,
            "latency_ms": event.latency_ms,
        }
    }
