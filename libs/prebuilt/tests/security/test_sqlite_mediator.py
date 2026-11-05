"""Database semantics and hostile-worker tests for the SQLite mediator."""

from __future__ import annotations

import hashlib
import shutil
import sqlite3
import subprocess
import sys
import time
from dataclasses import replace
from pathlib import Path

import pytest

from langgraph.prebuilt.security import (
    SQLITE_RECORD_SCHEMA,
    EnforcementKind,
    HostExecutionDenied,
    LinuxToolSpec,
    ObjectBrokerDispatcher,
    ObjectGrant,
    ObjectGrantLine,
    Principal,
    Requirement,
    ResourceInvocation,
    SupportLevel,
    Tool,
    ToolCall,
    ToolDac,
    sqlite_record_mediator,
)
from langgraph.prebuilt.security.capabilities import probe_landlock_abi
from tests.security.test_enforcement import _context, _host

pytestmark = pytest.mark.skipif(
    sys.version_info < (3, 11), reason="SQLite limits require Python 3.11+"
)


@pytest.fixture
def database(tmp_path):
    directory = tmp_path / "private"
    directory.mkdir()
    path = directory / "records.sqlite"
    connection = sqlite3.connect(path)
    try:
        connection.execute("PRAGMA journal_mode=WAL")
        connection.execute(SQLITE_RECORD_SCHEMA)
        connection.executemany(
            "INSERT INTO records VALUES (?, ?)",
            [("alice", "hello"), ("bob", "secret")],
        )
        connection.commit()
        # Keep real WAL and shared-memory sidecars alive for bypass tests.
        yield path
    finally:
        connection.close()


@pytest.fixture
def line():
    return ObjectGrantLine(
        "record",
        "db_record",
        "read",
        "notes/alice",
        {},
        Requirement.NEED,
        EnforcementKind.BROKER,
        "sqlite.record.v1",
    )


@pytest.fixture
def context():
    return ResourceInvocation(
        "alice", "session", "database_tool", "call", "grant", _context()
    )


def contents(database):
    with sqlite3.connect(database) as connection:
        return dict(connection.execute("SELECT key, value FROM records"))


def test_crud_is_single_record_and_values_are_never_sql(database, line, context):
    adapter = sqlite_record_mediator(database, database_id="notes")
    adapter.activate((line,), context)
    assert adapter.invoke(line, {}, context) == {"found": True, "value": "hello"}
    injection = "'); DELETE FROM records; --"
    assert adapter.invoke(
        replace(line, operation="write"), {"value": injection}, context
    ) == {"ok": True}
    assert contents(database) == {"alice": injection, "bob": "secret"}
    assert adapter.invoke(replace(line, operation="delete"), {}, context) == {
        "ok": True
    }
    assert adapter.invoke(line, {}, context) == {"found": False, "value": None}
    assert contents(database) == {"bob": "secret"}
    adapter.invoke(replace(line, operation="write"), {"value": "recreated"}, context)
    assert contents(database) == {"alice": "recreated", "bob": "secret"}


@pytest.mark.parametrize(
    "change",
    [
        {"selector": "other/alice"},
        {"selector": "notes/../bob"},
        {"selector": "notes/alice' OR 1=1 --"},
        {"selector": "notes/"},
        {"selector": "notes/alice/extra"},
        {"operation": "sql"},
        {"class_name": "fs"},
        {"attributes": {"tenant": "other"}},
        {"lowering": None},
        {"lowering": "other.v1"},
        {"enforcer": EnforcementKind.KERNEL},
    ],
)
def test_assessment_rejects_unknown_semantics(database, line, change):
    adapter = sqlite_record_mediator(database, database_id="notes")
    host = replace(
        _host(), capabilities=frozenset({"broker:spawn-bound", "seccomp:minimal"})
    )
    assert adapter.assess(line, host).support is SupportLevel.EXACT
    assert (
        adapter.assess(replace(line, **change), host).support
        is SupportLevel.UNSUPPORTED
    )
    assert (
        adapter.assess(line, replace(host, capabilities=frozenset())).support
        is SupportLevel.UNSUPPORTED
    )


@pytest.mark.parametrize(
    "operation,payload",
    [
        ("read", {"sql": "SELECT * FROM records"}),
        ("read", {"selector": "notes/bob"}),
        ("delete", {"where": "1=1"}),
        ("write", {}),
        ("write", {"value": 1}),
        ("write", {"value": "x", "table": "other"}),
        ("write", {"value": "x" * 8193}),
        ("write", {"value": "é" * 4097}),
    ],
)
def test_invalid_payloads_do_not_touch_database(
    database, line, context, operation, payload
):
    adapter = sqlite_record_mediator(database, database_id="notes")
    with pytest.raises(ValueError):
        adapter.invoke(replace(line, operation=operation), payload, context)
    assert contents(database) == {"alice": "hello", "bob": "secret"}


@pytest.mark.parametrize(
    "schema",
    [
        "CREATE VIEW records AS SELECT 'alice' AS key, 'secret' AS value",
        "CREATE TABLE records (key TEXT PRIMARY KEY, value TEXT, extra TEXT)",
        "CREATE VIRTUAL TABLE records USING fts5(key, value)",
    ],
)
def test_unknown_schemas_fail_before_effect(database, line, context, schema):
    with sqlite3.connect(database) as connection:
        connection.execute("DROP TABLE records")
        connection.execute(schema)
    adapter = sqlite_record_mediator(database, database_id="notes")
    adapter.activate((line,), context)
    with pytest.raises(ValueError, match="required records schema"):
        adapter.invoke(line, {}, context)


def test_schema_is_rechecked_after_activation(database, line, context):
    adapter = sqlite_record_mediator(database, database_id="notes")
    adapter.activate((line,), context)
    with sqlite3.connect(database) as connection:
        connection.execute("""
            CREATE TRIGGER widen AFTER UPDATE ON records BEGIN
                UPDATE records SET value = 'changed' WHERE key = 'bob';
            END
        """)
    with pytest.raises(ValueError, match="triggers"):
        adapter.invoke(replace(line, operation="write"), {"value": "changed"}, context)
    assert contents(database) == {"alice": "hello", "bob": "secret"}


def test_locked_database_times_out_without_effect(database, line, context):
    adapter = sqlite_record_mediator(database, database_id="notes", timeout_s=0.05)
    connection = sqlite3.connect(database)
    try:
        connection.execute("BEGIN EXCLUSIVE")
        started = time.monotonic()
        with pytest.raises(sqlite3.OperationalError, match="locked"):
            adapter.invoke(
                replace(line, operation="write"), {"value": "changed"}, context
            )
        assert time.monotonic() - started < 2
    finally:
        connection.close()
    assert contents(database) == {"alice": "hello", "bob": "secret"}


@pytest.mark.parametrize("value", ["x" * 8193, b"blob"], ids=["oversized", "blob"])
def test_unsupported_stored_values_are_not_returned(database, line, context, value):
    with sqlite3.connect(database) as connection:
        connection.execute("UPDATE records SET value = ? WHERE key = 'alice'", (value,))
    adapter = sqlite_record_mediator(database, database_id="notes")
    with pytest.raises(ValueError, match="supported text"):
        adapter.invoke(line, {}, context)


WORKER = """
import ctypes
import os
import sqlite3
from langgraph.prebuilt.security import object_request

def run(database):
    result = {}
    for name, operation, selector, payload in [
        ("allowed", "read", "notes/alice", {}),
        ("other_row", "read", "notes/bob", {}),
        ("write", "write", "notes/alice", {"value": "changed"}),
        ("delete", "delete", "notes/alice", {}),
        ("sql", "read", "notes/alice", {"sql": "SELECT * FROM records"}),
    ]:
        try:
            result[name] = object_request("db_record", operation, selector, payload)
        except PermissionError:
            result[name] = "denied"
    libc = ctypes.CDLL(None, use_errno=True)
    for suffix in ("", "-wal", "-shm"):
        fd = libc.open((database + suffix).encode(), os.O_RDONLY)
        result["direct" + suffix] = "blocked" if fd < 0 else "escaped"
        if fd >= 0:
            os.close(fd)
    try:
        connection = sqlite3.connect("file:" + database + "?mode=ro", uri=True)
        connection.execute("SELECT * FROM records").fetchall()
        result["sqlite"] = "escaped"
        connection.close()
    except sqlite3.Error:
        result["sqlite"] = "blocked"
    return result
"""


@pytest.mark.skipif(probe_landlock_abi() < 5, reason="Landlock ABI 5 required")
@pytest.mark.parametrize("expose_database", [False, True])
def test_host_and_record_mediation_compose(database, line, tmp_path, expose_database):
    source = tmp_path / "worker.py"
    source.write_text(WORKER)
    for suffix in ("-wal", "-shm"):
        assert Path(str(database) + suffix).is_file()
    roots = tuple(Path(p) for p in sys.path if p and Path(p).is_dir())
    if expose_database:
        roots += (database.parent,)
    dispatcher = ObjectBrokerDispatcher(
        {
            "database_tool": LinuxToolSpec(
                "worker:run", source, hashlib.sha256(source.read_bytes()).hexdigest()
            )
        },
        runtime_roots=roots,
        mediators=(sqlite_record_mediator(database, database_id="notes"),),
    )
    principal = Principal("alice", frozenset(), frozenset(), "session")
    call = ToolCall(
        Tool("database_tool", ToolDac("owner", {"*": "x"}), frozenset(), ()),
        {"database": str(database)},
        {},
        "call",
        0,
    )
    grant = ObjectGrant("alice", "database_tool", "call", "policy", (line,))
    if expose_database:
        with pytest.raises(HostExecutionDenied, match="required_authority_removed"):
            dispatcher.invoke(principal, call, grant)
    else:
        result = dispatcher.invoke(principal, call, grant).value
        assert result == {
            "allowed": {"found": True, "value": "hello"},
            "other_row": "denied",
            "write": "denied",
            "delete": "denied",
            "sql": "denied",
            "direct": "blocked",
            "direct-wal": "blocked",
            "direct-shm": "blocked",
            "sqlite": "blocked",
        }
    assert contents(database) == {"alice": "hello", "bob": "secret"}


@pytest.mark.skipif(probe_landlock_abi() < 5, reason="Landlock ABI 5 required")
@pytest.mark.skipif(shutil.which("cedar") is None, reason="Cedar CLI required")
def test_database_example_uses_real_cedar_and_toolnode():
    repository = Path(__file__).resolve().parents[4]
    result = subprocess.run(
        [sys.executable, str(repository / "workspace/06_database/demo.py")],
        cwd=repository,
        capture_output=True,
        text=True,
        timeout=30,
    )
    assert result.returncode == 0, result.stdout + result.stderr
    assert result.stdout.count("ALLOW ") == 5
    assert result.stdout.count("DENY ") == 3
    assert "Bob's record stayed unchanged" in result.stdout
