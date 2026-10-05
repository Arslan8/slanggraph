"""High-contention security mediation tests."""

from __future__ import annotations

import asyncio
from collections import Counter
from concurrent.futures import ThreadPoolExecutor
from unittest.mock import Mock

import pytest
from langchain_core.messages import AIMessage
from langchain_core.tools import tool

from langgraph.prebuilt import ToolNode
from langgraph.prebuilt.security import (
    Effect,
    MemoryAuditSink,
    Principal,
    SecurityConfig,
    dac,
    effects,
    with_principal,
)


@tool
@dac(owner="worker", grants={"worker": "x"}, required_scopes={"work"})
@effects(Effect.READ)
def concurrent_noop(value: int) -> int:
    """Return a value under concurrent mediation."""
    return value


def _config() -> dict:
    runtime = Mock(store=None, context=None, stream_writer=lambda _: None)
    principal = Principal(
        "worker", frozenset({"worker"}), frozenset({"work"}), "session"
    )
    return with_principal({"configurable": {"__pregel_runtime": runtime}}, principal)


def _request(index: int) -> dict:
    return {
        "messages": [
            AIMessage(
                content="",
                tool_calls=[
                    {
                        "name": "concurrent_noop",
                        "args": {"value": index},
                        "id": f"call-{index}",
                    }
                ],
            )
        ]
    }


def _assert_complete_audit(audit: MemoryAuditSink, count: int) -> None:
    records = audit.records()
    occurrences = Counter(record.call_index for record in records)
    assert occurrences == Counter({index: 4 for index in range(count)})
    assert audit.verify() == (True, None)


def test_thousand_parallel_sync_calls_have_unique_indices() -> None:
    """Eight threads cannot duplicate indices or corrupt the audit chain."""
    count = 1000
    audit = MemoryAuditSink()
    node = ToolNode([concurrent_noop], security=SecurityConfig(audit_sink=audit))
    config = _config()
    try:
        with ThreadPoolExecutor(max_workers=8) as executor:
            results = list(
                executor.map(
                    lambda index: node.invoke(_request(index), config=config),
                    range(count),
                )
            )
        assert {result["messages"][0].content for result in results} == {
            str(index) for index in range(count)
        }
        _assert_complete_audit(audit, count)
    finally:
        assert node._security_stack is not None
        node._security_stack.close()


@pytest.mark.asyncio
async def test_thousand_parallel_async_calls_have_unique_indices() -> None:
    """Concurrent coroutines preserve stable unique indices and audit integrity."""
    count = 1000
    audit = MemoryAuditSink()
    node = ToolNode([concurrent_noop], security=SecurityConfig(audit_sink=audit))
    config = _config()
    try:
        results = await asyncio.gather(
            *(node.ainvoke(_request(index), config=config) for index in range(count))
        )
        assert len(results) == count
        _assert_complete_audit(audit, count)
    finally:
        assert node._security_stack is not None
        node._security_stack.close()
