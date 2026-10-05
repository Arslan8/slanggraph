"""Tests for redacted security telemetry and per-hook auditing."""

from __future__ import annotations

import logging
from unittest.mock import Mock

from langchain_core.messages import AIMessage
from langchain_core.runnables import RunnableConfig
from langchain_core.tools import tool

from langgraph.prebuilt import ToolNode
from langgraph.prebuilt.security import (
    Effect,
    LoggingSecurityObserver,
    MemoryAuditSink,
    MemorySecurityObserver,
    OpenTelemetrySecurityObserver,
    Principal,
    SecurityConfig,
    SecurityEvent,
    Verdict,
    dac,
    effects,
    langsmith_metadata,
    with_principal,
)

_CAPTURED_METADATA = {}


@tool
@dac(owner="observer", grants={"observer": "x"})
@effects(Effect.READ)
def observed_tool(secret: str, config: RunnableConfig) -> str:
    """Return a value while ensuring telemetry stays redacted."""
    _CAPTURED_METADATA.update(config.get("metadata") or {})
    return secret


def _invoke(observer, audit=None):
    runtime = Mock(store=None, context=None, stream_writer=lambda _: None)
    principal = Principal("alice", frozenset({"observer"}), frozenset(), "session")
    config = with_principal({"configurable": {"__pregel_runtime": runtime}}, principal)
    node = ToolNode(
        [observed_tool],
        security=SecurityConfig(observer=observer, audit_sink=audit),
    )
    try:
        return node.invoke(
            {
                "messages": [
                    AIMessage(
                        content="",
                        tool_calls=[
                            {
                                "name": "observed_tool",
                                "args": {"secret": "do-not-log"},
                                "id": "call-1",
                            }
                        ],
                    )
                ]
            },
            config=config,
        )
    finally:
        assert node._security_stack is not None
        node._security_stack.close()


def test_memory_observer_records_each_invoked_policy_hook() -> None:
    """Events identify stage, module, verdict, latency, and call without raw args."""
    observer = MemorySecurityObserver()
    audit = MemoryAuditSink()
    _CAPTURED_METADATA.clear()

    result = _invoke(observer, audit)

    assert result["messages"][0].content == "do-not-log"
    events = observer.events()
    assert [(event.stage, event.module) for event in events] == [
        ("prepare", "dac_initial"),
        ("prepare", "dac_final"),
        ("permission", "dac"),
        ("permission", "cap"),
    ]
    assert all(event.verdict is Verdict.ALLOW for event in events)
    assert all(event.latency_ms >= 0 for event in events)
    assert all("do-not-log" not in repr(event) for event in events)
    assert sum(observer.counters().values()) == 4
    assert [(record.stage, record.module) for record in audit.records()] == [
        ("prepare", "dac_initial"),
        ("prepare", "dac_final"),
        ("permission", "dac"),
        ("permission", "cap"),
    ]
    assert audit.verify() == (True, None)
    assert _CAPTURED_METADATA["security"] == {
        "tool_name": "observed_tool",
        "call_index": 0,
        "verdict": "allow",
        "reason": "stack:allow",
    }


def test_logging_observer_emits_structured_redacted_record(caplog) -> None:
    """Standard logging receives structured fields rather than arguments."""
    observer = LoggingSecurityObserver()
    with caplog.at_level(logging.INFO, logger="langgraph.security"):
        _invoke(observer)
    assert caplog.records
    assert caplog.records[0].security["module"] == "dac_initial"
    assert "do-not-log" not in caplog.text


def test_opentelemetry_adapter_and_langsmith_metadata() -> None:
    """Generic adapters work without hard OpenTelemetry or LangSmith dependencies."""

    class Span:
        def __init__(self) -> None:
            self.attributes = {}
            self.ended = False

        def set_attribute(self, key, value) -> None:
            self.attributes[key] = value

        def end(self) -> None:
            self.ended = True

    class Tracer:
        def __init__(self) -> None:
            self.spans = []

        def start_span(self, name):
            span = Span()
            self.spans.append((name, span))
            return span

    class Counter:
        def __init__(self) -> None:
            self.values = []

        def add(self, value, attributes) -> None:
            self.values.append((value, attributes))

    tracer = Tracer()
    counter = Counter()
    event = SecurityEvent(
        "permission", "dac", Verdict.DENY, "dac:grant", 0.25, "alice", "tool", 1
    )
    OpenTelemetrySecurityObserver(tracer, counter).record(event)

    assert tracer.spans[0][0] == "langgraph.security.policy"
    assert tracer.spans[0][1].attributes["security.verdict"] == "deny"
    assert tracer.spans[0][1].ended
    assert counter.values[0][1]["module"] == "dac"
    metadata = langsmith_metadata(event)
    assert metadata["security"]["call_index"] == 1
    assert "args" not in repr(metadata)
