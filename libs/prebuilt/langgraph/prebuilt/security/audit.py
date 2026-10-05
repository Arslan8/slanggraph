"""Tamper-evident in-memory and SQLite security audit sinks."""

from __future__ import annotations

import hashlib
import json
import sqlite3
from dataclasses import replace
from pathlib import Path
from threading import RLock

from langgraph.prebuilt.security.types import AuditRecord, Verdict


class MemoryAuditSink:
    """Thread-safe in-memory hash-chained audit sink."""

    def __init__(self) -> None:
        self._records: list[AuditRecord] = []
        self._lock = RLock()

    def write(self, record: AuditRecord) -> AuditRecord:
        """Append and finalize one record under the current chain head."""
        with self._lock:
            previous = self._records[-1].hash if self._records else ""
            finalized = _finalize(record, previous)
            self._records.append(finalized)
            return finalized

    def records(self) -> tuple[AuditRecord, ...]:
        """Return an immutable append-order snapshot."""
        with self._lock:
            return tuple(self._records)

    def verify(self) -> tuple[bool, int | None]:
        """Verify the chain and return the first invalid record index."""
        with self._lock:
            return _verify(self._records)


class SqliteAuditSink:
    """Thread-safe SQLite audit sink using WAL and a SHA-256 hash chain."""

    def __init__(self, path: str | Path) -> None:
        self.path = Path(path)
        self._lock = RLock()
        self._connection = sqlite3.connect(self.path, check_same_thread=False)
        self._connection.execute("PRAGMA journal_mode=WAL")
        self._connection.execute("PRAGMA synchronous=FULL")
        self._connection.execute(
            """
            CREATE TABLE IF NOT EXISTS audit_records (
                sequence INTEGER PRIMARY KEY AUTOINCREMENT,
                call_index INTEGER NOT NULL,
                tool_name TEXT NOT NULL,
                user_id TEXT NOT NULL,
                args_hash TEXT NOT NULL,
                stage TEXT NOT NULL,
                module TEXT NOT NULL,
                verdict TEXT NOT NULL,
                reason TEXT NOT NULL,
                prev_hash TEXT NOT NULL,
                hash TEXT NOT NULL
            )
            """
        )
        self._connection.commit()

    def write(self, record: AuditRecord) -> AuditRecord:
        """Atomically append and finalize one record."""
        with self._lock, self._connection:
            row = self._connection.execute(
                "SELECT hash FROM audit_records ORDER BY sequence DESC LIMIT 1"
            ).fetchone()
            previous = str(row[0]) if row else ""
            finalized = _finalize(record, previous)
            self._connection.execute(
                """
                INSERT INTO audit_records (
                    call_index, tool_name, user_id, args_hash, stage, module,
                    verdict, reason, prev_hash, hash
                ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
                """,
                (
                    finalized.call_index,
                    finalized.tool_name,
                    finalized.user_id,
                    finalized.args_hash,
                    finalized.stage,
                    finalized.module,
                    finalized.verdict.value,
                    finalized.reason,
                    finalized.prev_hash,
                    finalized.hash,
                ),
            )
            return finalized

    def records(self) -> tuple[AuditRecord, ...]:
        """Return all records in append order."""
        with self._lock:
            rows = self._connection.execute(
                """
                SELECT call_index, tool_name, user_id, args_hash, stage, module,
                       verdict, reason, prev_hash, hash
                FROM audit_records ORDER BY sequence
                """
            ).fetchall()
        return tuple(
            AuditRecord(
                call_index=row[0],
                tool_name=row[1],
                user_id=row[2],
                args_hash=row[3],
                stage=row[4],
                module=row[5],
                verdict=Verdict(row[6]),
                reason=row[7],
                prev_hash=row[8],
                hash=row[9],
            )
            for row in rows
        )

    def verify(self) -> tuple[bool, int | None]:
        """Verify the persisted chain and name the first invalid index."""
        return _verify(self.records())

    def close(self) -> None:
        """Flush and close the SQLite connection."""
        with self._lock:
            self._connection.close()


def _finalize(record: AuditRecord, previous: str) -> AuditRecord:
    unhashed = replace(record, prev_hash=previous, hash="")
    return replace(unhashed, hash=_record_hash(unhashed))


def _record_hash(record: AuditRecord) -> str:
    payload = {
        "args_hash": record.args_hash,
        "call_index": record.call_index,
        "module": record.module,
        "prev_hash": record.prev_hash,
        "reason": record.reason,
        "stage": record.stage,
        "tool_name": record.tool_name,
        "user_id": record.user_id,
        "verdict": record.verdict.value,
    }
    encoded = json.dumps(
        payload, sort_keys=True, separators=(",", ":"), ensure_ascii=False
    ).encode()
    return hashlib.sha256(encoded).hexdigest()


def _verify(
    records: list[AuditRecord] | tuple[AuditRecord, ...],
) -> tuple[bool, int | None]:
    previous = ""
    for index, record in enumerate(records):
        if record.prev_hash != previous or record.hash != _record_hash(record):
            return False, index
        previous = record.hash
    return True, None
