"""Tamper-evident in-memory and SQLite security audit sinks."""

from __future__ import annotations

import hashlib
import hmac
import json
import queue
import sqlite3
import time
import uuid
from atexit import register as register_atexit
from dataclasses import replace
from pathlib import Path
from threading import RLock, Thread
from typing import Literal

from langgraph.prebuilt.security.types import (
    AuditRecord,
    AuditSeal,
    AuditWitness,
    ExecutionOutcome,
    Verdict,
)


class HmacAuditWitness:
    """HMAC trust anchor suitable for a separately held audit witness key."""

    def __init__(self, key: bytes) -> None:
        if len(key) < 32:
            raise ValueError("audit witness keys must contain at least 32 bytes")
        self._key = bytes(key)

    def sign(self, payload: bytes) -> str:
        """Return a SHA-256 HMAC over a canonical seal payload."""
        return hmac.new(self._key, payload, hashlib.sha256).hexdigest()

    def verify(self, payload: bytes, signature: str) -> bool:
        """Verify a seal signature without timing-dependent comparison."""
        return hmac.compare_digest(self.sign(payload), signature)


class MemoryAuditSink:
    """Thread-safe in-memory hash-chained audit sink."""

    def __init__(self) -> None:
        self._records: list[AuditRecord] = []
        self._lock = RLock()
        self._stream_id = str(uuid.uuid4())

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

    def seal(self, witness: AuditWitness) -> AuditSeal:
        """Commit the current chain head for retention outside this sink."""
        with self._lock:
            return _seal(self._stream_id, self._records, witness)

    def verify_seal(self, seal: AuditSeal, witness: AuditWitness) -> bool:
        """Detect modification and valid-prefix or suffix truncation."""
        with self._lock:
            return _verify_seal(self._stream_id, self._records, seal, witness)


class SqliteAuditSink:
    """Thread-safe SQLite audit sink using WAL and a SHA-256 hash chain."""

    def __init__(
        self,
        path: str | Path,
        *,
        durability: Literal["synchronous", "trusted-async"] = "synchronous",
        batch_size: int = 256,
        max_pending: int = 8192,
    ) -> None:
        if durability not in {"synchronous", "trusted-async"}:
            raise ValueError("unknown audit durability mode")
        if type(batch_size) is not int or batch_size <= 0:
            raise ValueError("audit batch_size must be a positive integer")
        if type(max_pending) is not int or max_pending <= 0:
            raise ValueError("audit max_pending must be a positive integer")
        self.path = Path(path)
        self._lock = RLock()
        self.durability = durability
        self.batch_size = batch_size
        self._closed = False
        self._failure: BaseException | None = None
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
                session_id TEXT NOT NULL DEFAULT '',
                args_hash TEXT NOT NULL,
                stage TEXT NOT NULL,
                module TEXT NOT NULL,
                verdict TEXT NOT NULL,
                reason TEXT NOT NULL,
                prev_hash TEXT NOT NULL,
                hash TEXT NOT NULL,
                outcome TEXT
            )
            """
        )
        self._connection.execute(
            """
            CREATE TABLE IF NOT EXISTS audit_metadata (
                key TEXT PRIMARY KEY,
                value TEXT NOT NULL
            )
            """
        )
        row = self._connection.execute(
            "SELECT value FROM audit_metadata WHERE key = 'stream_id'"
        ).fetchone()
        if row is None:
            self._stream_id = str(uuid.uuid4())
            self._connection.execute(
                "INSERT INTO audit_metadata (key, value) VALUES ('stream_id', ?)",
                (self._stream_id,),
            )
        else:
            self._stream_id = str(row[0])
        columns = {
            str(row[1])
            for row in self._connection.execute("PRAGMA table_info(audit_records)")
        }
        if "session_id" not in columns:
            self._connection.execute(
                "ALTER TABLE audit_records "
                "ADD COLUMN session_id TEXT NOT NULL DEFAULT ''"
            )
        if "outcome" not in columns:
            self._connection.execute(
                "ALTER TABLE audit_records ADD COLUMN outcome TEXT"
            )
        self._connection.commit()
        row = self._connection.execute(
            "SELECT hash FROM audit_records ORDER BY sequence DESC LIMIT 1"
        ).fetchone()
        self._head = str(row[0]) if row else ""
        self._pending: queue.Queue[AuditRecord | object] | None = None
        self._stop = object()
        self._writer: Thread | None = None
        if durability == "trusted-async":
            self._pending = queue.Queue(maxsize=max_pending)
            self._writer = Thread(
                target=self._write_batches,
                name="argus-audit-writer",
                daemon=True,
            )
            self._writer.start()
            register_atexit(self.close)

    def write(self, record: AuditRecord) -> AuditRecord:
        """Finalize and hand one record to the configured durability boundary."""
        with self._lock:
            self._require_available()
            previous = self._head
            finalized = _finalize(record, previous)
            if self._pending is None:
                with self._connection:
                    self._insert(finalized)
            else:
                try:
                    self._pending.put_nowait(finalized)
                except queue.Full as exc:
                    raise RuntimeError("trusted audit writer queue is full") from exc
            self._head = finalized.hash
            return finalized

    def _insert(self, record: AuditRecord) -> None:
        self._connection.execute(
            """
            INSERT INTO audit_records (
                call_index, tool_name, user_id, session_id, args_hash, stage,
                module, verdict, reason, prev_hash, hash, outcome
            ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
            """,
            (
                record.call_index,
                record.tool_name,
                record.user_id,
                record.session_id,
                record.args_hash,
                record.stage,
                record.module,
                record.verdict.value,
                record.reason,
                record.prev_hash,
                record.hash,
                record.outcome.value if record.outcome is not None else None,
            ),
        )

    def _write_batches(self) -> None:
        assert self._pending is not None
        while True:
            first = self._pending.get()
            if first is self._stop:
                self._pending.task_done()
                return
            batch = [first]
            stop_after_batch = False
            while len(batch) < self.batch_size:
                try:
                    item = self._pending.get_nowait()
                except queue.Empty:
                    break
                if item is self._stop:
                    self._pending.task_done()
                    stop_after_batch = True
                    break
                batch.append(item)
            try:
                with self._connection:
                    for item in batch:
                        assert isinstance(item, AuditRecord)
                        self._insert(item)
            except BaseException as exc:
                self._failure = exc
            finally:
                for _ in batch:
                    self._pending.task_done()
            if stop_after_batch:
                return

    def _require_available(self) -> None:
        if self._closed:
            raise RuntimeError("audit sink is closed")
        if self._failure is not None:
            raise RuntimeError("trusted audit writer failed") from self._failure

    def flush(self) -> None:
        """Wait until every accepted record has reached SQLite."""
        pending = self._pending
        if pending is None:
            return
        pending.join()
        with self._lock:
            self._require_available()

    def records(self) -> tuple[AuditRecord, ...]:
        """Return all records in append order."""
        with self._lock:
            self.flush()
            rows = self._connection.execute(
                """
                SELECT call_index, tool_name, user_id, args_hash, stage, module,
                       verdict, reason, prev_hash, hash, session_id, outcome
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
                session_id=row[10],
                outcome=ExecutionOutcome(row[11]) if row[11] is not None else None,
            )
            for row in rows
        )

    def verify(self) -> tuple[bool, int | None]:
        """Verify the persisted chain and name the first invalid index."""
        return _verify(self.records())

    def seal(self, witness: AuditWitness) -> AuditSeal:
        """Commit the current persisted chain for an external witness."""
        with self._lock:
            return _seal(self._stream_id, self.records(), witness)

    def verify_seal(self, seal: AuditSeal, witness: AuditWitness) -> bool:
        """Verify the external commitment against the current database."""
        with self._lock:
            return _verify_seal(self._stream_id, self.records(), seal, witness)

    def close(self) -> None:
        """Flush and close the SQLite connection."""
        with self._lock:
            if self._closed:
                return
            self.flush()
            if self._pending is not None:
                self._pending.put(self._stop)
                self._pending.join()
                assert self._writer is not None
                self._writer.join(timeout=5.0)
                if self._writer.is_alive():
                    raise RuntimeError("trusted audit writer did not stop")
            self._connection.close()
            self._closed = True


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
    if record.outcome is not None:
        payload["outcome"] = record.outcome.value
    if record.session_id:
        payload["session_id"] = record.session_id
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


def _seal(
    stream_id: str,
    records: list[AuditRecord] | tuple[AuditRecord, ...],
    witness: AuditWitness,
) -> AuditSeal:
    issued_at = time.time()
    head = records[-1].hash if records else ""
    payload = _seal_payload(stream_id, len(records), head, issued_at)
    return AuditSeal(
        stream_id,
        len(records),
        head,
        issued_at,
        witness.sign(payload),
    )


def _verify_seal(
    stream_id: str,
    records: list[AuditRecord] | tuple[AuditRecord, ...],
    seal: AuditSeal,
    witness: AuditWitness,
) -> bool:
    valid, _ = _verify(records)
    head = records[-1].hash if records else ""
    if (
        not valid
        or seal.stream_id != stream_id
        or seal.record_count != len(records)
        or seal.chain_head != head
    ):
        return False
    payload = _seal_payload(
        seal.stream_id, seal.record_count, seal.chain_head, seal.issued_at
    )
    return witness.verify(payload, seal.signature)


def _seal_payload(
    stream_id: str, record_count: int, chain_head: str, issued_at: float
) -> bytes:
    return json.dumps(
        {
            "chain_head": chain_head,
            "issued_at": issued_at,
            "record_count": record_count,
            "stream_id": stream_id,
        },
        sort_keys=True,
        separators=(",", ":"),
    ).encode()
