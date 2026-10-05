"""Tests for tamper-evident audit sinks."""

from __future__ import annotations

import sqlite3
from concurrent.futures import ThreadPoolExecutor
from pathlib import Path

import pytest

from langgraph.prebuilt.security import (
    AuditRecord,
    AuditSink,
    MemoryAuditSink,
    SqliteAuditSink,
    Verdict,
)


def _record(index: int) -> AuditRecord:
    return AuditRecord(
        call_index=index,
        tool_name="read_file",
        user_id="alice",
        args_hash=f"args-{index}",
        stage="permission",
        module="paths",
        verdict=Verdict.ALLOW,
        reason="policy:allow",
    )


@pytest.mark.parametrize("kind", ["memory", "sqlite"])
def test_sinks_hash_chain_and_verify(kind: str, tmp_path: Path) -> None:
    """Both implementations finalize the same valid chain contract."""
    sink: AuditSink
    if kind == "memory":
        sink = MemoryAuditSink()
    else:
        sink = SqliteAuditSink(tmp_path / "audit.db")
    try:
        first = sink.write(_record(0))
        second = sink.write(_record(1))

        assert first.hash
        assert second.prev_hash == first.hash
        assert sink.verify() == (True, None)
    finally:
        if isinstance(sink, SqliteAuditSink):
            sink.close()


def test_memory_sink_returns_immutable_snapshot() -> None:
    """Callers cannot mutate the sink's append-order record list."""
    sink = MemoryAuditSink()
    sink.write(_record(0))
    snapshot = sink.records()
    assert isinstance(snapshot, tuple)


def test_sqlite_uses_wal_mode(tmp_path: Path) -> None:
    """The durable sink enables the required concurrent journal mode."""
    sink = SqliteAuditSink(tmp_path / "audit.db")
    try:
        connection = sqlite3.connect(sink.path)
        try:
            assert connection.execute("PRAGMA journal_mode").fetchone()[0] == "wal"
        finally:
            connection.close()
    finally:
        sink.close()


def test_sqlite_tamper_names_first_bad_record(tmp_path: Path) -> None:
    """Changing any persisted field breaks that record and the chain."""
    sink = SqliteAuditSink(tmp_path / "audit.db")
    try:
        sink.write(_record(0))
        sink.write(_record(1))
        connection = sqlite3.connect(sink.path)
        try:
            connection.execute(
                "UPDATE audit_records SET reason = ? WHERE sequence = 1",
                ("tampered",),
            )
            connection.commit()
        finally:
            connection.close()

        assert sink.verify() == (False, 0)
    finally:
        sink.close()


def test_memory_sink_serializes_parallel_appends() -> None:
    """Concurrent calls produce one valid chain without lost records."""
    sink = MemoryAuditSink()
    with ThreadPoolExecutor(max_workers=8) as executor:
        list(executor.map(lambda index: sink.write(_record(index)), range(100)))

    assert len(sink.records()) == 100
    assert sink.verify() == (True, None)
