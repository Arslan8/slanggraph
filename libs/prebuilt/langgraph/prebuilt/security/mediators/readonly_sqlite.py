"""Reusable read-only SQLite metadata and query mediation."""

from __future__ import annotations

import math
import re
import sqlite3
import time
from abc import ABC, abstractmethod
from collections.abc import Mapping
from pathlib import Path
from typing import Any

from langgraph.prebuilt.security.enforcement import HostAttestation, SupportLevel
from langgraph.prebuilt.security.mediators.contracts import ResourceContract
from langgraph.prebuilt.security.object_policy import ObjectGrantLine
from langgraph.prebuilt.security.resource_mediator import (
    ResourceInvocation,
    ResourceSupport,
)

_MAX_ARGUMENT_BYTES = 64 * 1024
_MAX_RESULT_BYTES = 256 * 1024
_MAX_ROWS = 1000
_TABLE = re.compile(r"[A-Za-z_][A-Za-z0-9_]{0,127}\Z")
_FORBIDDEN_SQL = re.compile(
    r"\b(attach|detach|insert|update|delete|replace|create|drop|alter|reindex|"
    r"vacuum|pragma|load_extension)\b",
    re.IGNORECASE,
)


class ReadOnlySQLiteAPI(ABC):
    """Inspect and query one setup-bound SQLite database."""

    __slots__ = ()

    @abstractmethod
    def list_tables(self) -> str:
        raise NotImplementedError

    @abstractmethod
    def schema(self, table_names: str) -> str:
        raise NotImplementedError

    @abstractmethod
    def query(self, query: str) -> str:
        raise NotImplementedError


READONLY_SQLITE = ResourceContract(
    ReadOnlySQLiteAPI,
    class_name="readonly_sqlite",
    object_kind="database",
    lowering="library.sqlite.readonly.v1",
)
readonly_sqlite = READONLY_SQLITE.client(export=__name__ + ".readonly_sqlite")


def _bounded(value: str) -> str:
    if type(value) is not str or len(value.encode("utf-8")) > _MAX_RESULT_BYTES:
        raise ValueError("SQLite result exceeds 262144 UTF-8 bytes")
    return value


class _ReadOnlySQLiteMediator:
    def assess(self, line: ObjectGrantLine, host: HostAttestation) -> ResourceSupport:
        del line, host
        return ResourceSupport(
            SupportLevel.EXACT,
            "read-only operations on one setup-bound SQLite database with inert bounded output",
            witness="tests/security/test_library_mediators.py",
        )

    def validate(
        self,
        operation: str,
        arguments: Mapping[str, Any],
        context: ResourceInvocation,
    ) -> None:
        del context
        if operation == "list_tables":
            if arguments:
                raise ValueError("list_tables accepts no arguments")
            return
        expected = "table_names" if operation == "schema" else "query"
        if set(arguments) != {expected} or type(arguments[expected]) is not str:
            raise ValueError(f"{operation} requires one text argument")
        if len(arguments[expected].encode("utf-8")) > _MAX_ARGUMENT_BYTES:
            raise ValueError("SQLite argument exceeds 65536 UTF-8 bytes")


def readonly_sqlite_resource(
    path: str | Path, *, timeout_s: float = 2.0
) -> ResourceContract[ReadOnlySQLiteAPI]:
    """Bind a read-only SQLite database for language or broker mediation.

    The path and connection remain in trusted setup. The database is opened in
    SQLite read-only and query-only modes for each operation. Only metadata
    reads and one `SELECT`/`WITH` statement are exposed; output is inert text.
    """
    if not math.isfinite(timeout_s) or timeout_s <= 0:
        raise ValueError("timeout_s must be finite and positive")
    database = Path(path).resolve(strict=True)
    if not database.is_file():
        raise ValueError("SQLite database must be an existing regular file")

    def connect() -> sqlite3.Connection:
        connection = sqlite3.connect(
            database.as_uri() + "?mode=ro",
            uri=True,
            timeout=timeout_s,
            isolation_level=None,
            cached_statements=0,
        )
        deadline = time.monotonic() + timeout_s
        connection.execute("PRAGMA query_only=ON")
        connection.execute("PRAGMA trusted_schema=OFF")
        connection.set_progress_handler(lambda: time.monotonic() >= deadline, 1000)
        return connection

    class Backend(ReadOnlySQLiteAPI):
        def list_tables(self) -> str:
            with connect() as connection:
                rows = connection.execute(
                    "SELECT name FROM sqlite_schema "
                    "WHERE type = 'table' AND name NOT LIKE 'sqlite_%' ORDER BY name"
                ).fetchall()
            return _bounded(", ".join(str(row[0]) for row in rows))

        def schema(self, table_names: str) -> str:
            requested = [
                name.strip() for name in table_names.split(",") if name.strip()
            ]
            if any(not _TABLE.fullmatch(name) for name in requested):
                raise ValueError("invalid SQLite table name")
            with connect() as connection:
                available = {
                    row[0]
                    for row in connection.execute(
                        "SELECT name FROM sqlite_schema "
                        "WHERE type = 'table' AND name NOT LIKE 'sqlite_%'"
                    )
                }
                names = requested or sorted(available)
                if any(name not in available for name in names):
                    raise ValueError("unknown SQLite table")
                parts = []
                for name in names:
                    definition = connection.execute(
                        "SELECT sql FROM sqlite_schema WHERE type = 'table' AND name = ?",
                        (name,),
                    ).fetchone()[0]
                    quoted = name.replace('"', '""')
                    rows = connection.execute(
                        f'SELECT * FROM "{quoted}" LIMIT 3'
                    ).fetchall()
                    parts.append(f"{definition}\nSample rows: {rows}")
            return _bounded("\n\n".join(parts))

        def query(self, query: str) -> str:
            normalized = query.strip()
            if not re.match(r"(?is)^(select|with)\b", normalized):
                raise PermissionError("only SELECT or WITH queries are permitted")
            if _FORBIDDEN_SQL.search(normalized):
                raise PermissionError("SQLite mutation or control is forbidden")
            with connect() as connection:
                cursor = connection.execute(normalized)
                rows = cursor.fetchmany(_MAX_ROWS + 1)
            if len(rows) > _MAX_ROWS:
                raise ValueError("SQLite result exceeds 1000 rows")
            return _bounded(str(rows))

    return READONLY_SQLITE.bind(
        implementation=Backend(), mediator=_ReadOnlySQLiteMediator()
    )
