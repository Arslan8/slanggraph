"""Record-scoped SQLite mediation with a parent-only database connection."""

from __future__ import annotations

import math
import re
import sqlite3
import time
from collections.abc import Mapping
from pathlib import Path
from typing import Any, cast

from langgraph.prebuilt.security.enforcement import HostAttestation, SupportLevel
from langgraph.prebuilt.security.mediators.contracts import ResourceContract
from langgraph.prebuilt.security.mediators.records import (
    RECORDS,
    RecordMutation,
    RecordRead,
    RecordsAPI,
)
from langgraph.prebuilt.security.object_policy import EnforcementKind, ObjectGrantLine
from langgraph.prebuilt.security.resource_mediator import (
    ResourceInvocation,
    ResourceMediatorAdapter,
    ResourceSupport,
)

SQLITE_RECORD_SCHEMA = (
    "CREATE TABLE records (key TEXT PRIMARY KEY, value TEXT NOT NULL)"
)
"""Required operator-created schema for the SQLite record mediator."""

_NAME = re.compile(r"[A-Za-z0-9_-]{1,128}\Z")
_CAPABILITIES = frozenset({"broker:spawn-bound", "seccomp:minimal"})
_MAX_VALUE_BYTES = 8192


def sqlite_records_resource(
    path: str | Path,
    *,
    database_id: str,
    timeout_s: float = 1.0,
) -> ResourceContract[RecordsAPI]:
    """Mediate db_record read/write/delete on database_id/key selectors.

    Requires Python 3.11+, lowering sqlite.record.v1, empty attributes, and the exact
    SQLITE_RECORD_SCHEMA. Writes upsert one UTF-8 text value (at most 8192
    bytes); reads return {"found": bool, "value": str | None}. Writes and
    deletes return {"ok": True} without revealing previous values.

    The operator creates the database in a dedicated private directory,
    outside all worker-readable roots, with no worker-accessible aliases or
    hardlinks. The whole directory is protected, including WAL/journal files.
    Connections are opened per request in the parent with SQLite lock timeouts,
    a progress budget, fixed parameterized SQL, and an authorizer rejecting
    triggers and unrelated SQL operations. No arbitrary schemas, SQL, table
    names, credentials, or connection objects are accepted from the worker.
    """
    if not hasattr(sqlite3.Connection, "setlimit"):
        raise RuntimeError("SQLite record mediation requires Python 3.11 or later")
    if not _NAME.fullmatch(database_id):
        raise ValueError("database_id must be 1-128 ASCII letters, digits, '_' or '-'")
    if not math.isfinite(timeout_s) or timeout_s <= 0:
        raise ValueError("timeout_s must be finite and positive")
    database = Path(path).resolve(strict=True)
    if not database.is_file():
        raise ValueError("SQLite database must be an existing regular file")
    prefix = database_id + "/"

    def record_key(record: str) -> str:
        if not record.startswith(prefix) or not _NAME.fullmatch(record[len(prefix) :]):
            raise ValueError("unsupported SQLite record selector")
        return record[len(prefix) :]

    def key_for(line: ObjectGrantLine) -> str:
        if (
            line.class_name != RECORDS.class_name
            or line.enforcer
            not in {EnforcementKind.BROKER, EnforcementKind.LANGUAGE_SANDBOX}
            or line.lowering != RECORDS.lowering
            or line.attributes
            or line.operation not in RECORDS.methods
            or not line.selector.startswith(prefix)
            or not _NAME.fullmatch(line.selector[len(prefix) :])
        ):
            raise ValueError("unsupported SQLite record semantics")
        return record_key(line.selector)

    def assess(line: ObjectGrantLine, host: HostAttestation) -> ResourceSupport:
        try:
            key_for(line)
        except ValueError:
            return ResourceSupport(
                SupportLevel.UNSUPPORTED, "unsupported SQLite record semantics"
            )
        if line.enforcer is EnforcementKind.BROKER and not _CAPABILITIES.issubset(
            host.capabilities
        ):
            return ResourceSupport(
                SupportLevel.UNSUPPORTED, "SQLite isolation capabilities unavailable"
            )
        if line.enforcer is EnforcementKind.LANGUAGE_SANDBOX:
            return ResourceSupport(
                SupportLevel.EXACT,
                "fixed single-record operations; the interpreted language has no filesystem or SQLite objects",
                witness="sqlite.record.v1:tests/security/test_sqlite_mediator.py",
            )
        return ResourceSupport(
            SupportLevel.EXACT,
            "fixed single-record operations; no worker SQL or direct database access",
            witness="sqlite.record.v1:tests/security/test_sqlite_mediator.py",
            protected_paths=(str(database.parent),),
            required_capabilities=_CAPABILITIES,
        )

    def connect(*, writing: bool) -> sqlite3.Connection:
        connection = sqlite3.connect(
            database.as_uri() + "?mode=rw",
            uri=True,
            timeout=timeout_s,
            isolation_level=None,
            cached_statements=0,
        )
        deadline = time.monotonic() + timeout_s
        steps = 0

        def progress() -> bool:
            nonlocal steps
            steps += 100
            return steps > 100_000 or time.monotonic() >= deadline

        try:
            connection.setlimit(sqlite3.SQLITE_LIMIT_LENGTH, 65_536)
            connection.setlimit(sqlite3.SQLITE_LIMIT_ATTACHED, 0)
            connection.set_progress_handler(progress, 100)
            connection.execute("PRAGMA trusted_schema=OFF")
            connection.execute("BEGIN IMMEDIATE" if writing else "BEGIN")
            # Validate within the transaction so a concurrent schema change
            # cannot insert triggers/generated columns before execution.
            row = connection.execute(
                "SELECT type, sql FROM sqlite_schema WHERE name = 'records'"
            ).fetchone()
            if row != ("table", SQLITE_RECORD_SCHEMA):
                raise ValueError("database does not have the required records schema")
            if connection.execute(
                "SELECT 1 FROM sqlite_schema WHERE type = 'trigger' AND tbl_name = 'records'"
            ).fetchone():
                raise ValueError("record triggers are not supported")
            return connection
        except BaseException:
            connection.close()
            raise

    def activate(
        lines: tuple[ObjectGrantLine, ...], context: ResourceInvocation
    ) -> None:
        for line in lines:
            key_for(line)
        connection = connect(writing=False)
        connection.close()

    def execute(
        operation: str, record: str, payload: Mapping[str, Any]
    ) -> dict[str, Any]:
        key = record_key(record)
        if operation == "write":
            if set(payload) != {"value"} or not isinstance(payload["value"], str):
                raise ValueError("write requires only a text value")
            if len(payload["value"].encode("utf-8")) > _MAX_VALUE_BYTES:
                raise ValueError("record value exceeds 8192 UTF-8 bytes")
        elif payload:
            raise ValueError("read and delete accept no payload")

        def authorize(
            action: int,
            table: str | None,
            column: str | None,
            db: str | None,
            source: str | None,
        ) -> int:
            if source is not None:
                return sqlite3.SQLITE_DENY
            if action in {sqlite3.SQLITE_SELECT, sqlite3.SQLITE_TRANSACTION}:
                return sqlite3.SQLITE_OK
            if db != "main" or table != "records":
                return sqlite3.SQLITE_DENY
            if action == sqlite3.SQLITE_READ and column in {"key", "value"}:
                return sqlite3.SQLITE_OK
            if operation == "write" and (
                action == sqlite3.SQLITE_INSERT
                or (action == sqlite3.SQLITE_UPDATE and column == "value")
            ):
                return sqlite3.SQLITE_OK
            if operation == "delete" and action == sqlite3.SQLITE_DELETE:
                return sqlite3.SQLITE_OK
            return sqlite3.SQLITE_DENY

        connection = connect(writing=operation != "read")
        try:
            connection.set_authorizer(authorize)
            if operation == "read":
                row = connection.execute(
                    "SELECT value FROM records WHERE key = ?", (key,)
                ).fetchone()
                value = row[0] if row else None
                if row and (
                    not isinstance(value, str)
                    or len(value.encode("utf-8")) > _MAX_VALUE_BYTES
                ):
                    raise ValueError("stored record is not a supported text value")
                result = {"found": row is not None, "value": value}
            elif operation == "write":
                connection.execute(
                    "INSERT INTO records (key, value) VALUES (?, ?) "
                    "ON CONFLICT(key) DO UPDATE SET value = excluded.value",
                    (key, payload["value"]),
                )
                result = {"ok": True}
            else:
                connection.execute("DELETE FROM records WHERE key = ?", (key,))
                result = {"ok": True}
            connection.commit()
            return result
        finally:
            connection.close()

    class SQLiteRecords(RecordsAPI):
        def read(self, record: str) -> RecordRead:
            return cast(RecordRead, execute("read", record, {}))

        def write(self, record: str, value: str) -> RecordMutation:
            return cast(RecordMutation, execute("write", record, {"value": value}))

        def delete(self, record: str) -> RecordMutation:
            return cast(RecordMutation, execute("delete", record, {}))

    return RECORDS.bind(
        implementation=SQLiteRecords(),
        assess=assess,
        activate=activate,
    )


def sqlite_record_mediator(
    path: str | Path,
    *,
    database_id: str,
    timeout_s: float = 1.0,
) -> ResourceMediatorAdapter:
    """Compatibility adapter for `ObjectBrokerDispatcher(mediators=...)`."""
    return sqlite_records_resource(
        path, database_id=database_id, timeout_s=timeout_s
    ).adapter
