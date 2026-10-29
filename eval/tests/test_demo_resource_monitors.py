from __future__ import annotations

import json
import sqlite3
import sys
from datetime import UTC, datetime, timedelta
from pathlib import Path

import pytest
from apps.demos.resource_monitors.backends import (
    EmptySearchBackend,
    FrozenSearchBackend,
    PersistentPythonBackend,
    ReadOnlySQLBackend,
    TFIDFRetrieverBackend,
    TravelSQLiteBackend,
)


def test_read_only_sql_monitor_allows_select_and_refuses_mutation(tmp_path: Path) -> None:
    database = tmp_path / "example.sqlite"
    with sqlite3.connect(database) as connection:
        connection.execute("CREATE TABLE records (id INTEGER, value TEXT)")
        connection.execute("INSERT INTO records VALUES (1, 'allowed')")

    backend = ReadOnlySQLBackend(database)
    assert backend.list_tables() == "records"
    assert "allowed" in backend.query("SELECT value FROM records")
    with pytest.raises(PermissionError, match="read-only"):
        backend.query("UPDATE records SET value = 'forbidden'")


def test_frozen_retrieval_monitors_search_the_supplied_corpus() -> None:
    retriever = TFIDFRetrieverBackend(["alpha apples", "beta bananas"], limit=1)
    assert retriever.search("banana") == "beta bananas"

    search = FrozenSearchBackend(
        [
            {"title": "A", "url": "frozen:a", "content": "alpha apples"},
            {"title": "B", "url": "frozen:b", "content": "beta bananas"},
        ],
        limit=1,
    )
    assert json.loads(search.search("banana"))[0]["url"] == "frozen:b"
    assert EmptySearchBackend().search("anything") == "[]"


def test_travel_monitor_binds_logical_principal_and_preserves_mutations(
    tmp_path: Path,
) -> None:
    database = tmp_path / "travel.sqlite"
    now = datetime.now(UTC)
    departure = now + timedelta(days=1)
    with sqlite3.connect(database) as connection:
        connection.executescript(
            """
            CREATE TABLE tickets (ticket_no TEXT, book_ref TEXT, passenger_id TEXT);
            CREATE TABLE flights (
              flight_id INTEGER, flight_no TEXT, departure_airport TEXT,
              arrival_airport TEXT, scheduled_departure TEXT,
              scheduled_arrival TEXT
            );
            CREATE TABLE ticket_flights (
              ticket_no TEXT, flight_id INTEGER, fare_conditions TEXT
            );
            CREATE TABLE boarding_passes (
              ticket_no TEXT, flight_id INTEGER, seat_no TEXT
            );
            """
        )
        connection.execute("INSERT INTO tickets VALUES ('T1', 'B1', 'P1')")
        connection.execute(
            "INSERT INTO flights VALUES (1, 'F1', 'A', 'B', ?, ?)",
            (departure.isoformat(), (departure + timedelta(hours=1)).isoformat()),
        )
        connection.execute(
            "INSERT INTO flights VALUES (2, 'F2', 'A', 'B', ?, ?)",
            (departure.isoformat(), (departure + timedelta(hours=1)).isoformat()),
        )
        connection.execute("INSERT INTO ticket_flights VALUES ('T1', 1, 'Economy')")
        connection.execute("INSERT INTO boarding_passes VALUES ('T1', 1, '1A')")

    backend = TravelSQLiteBackend(database, "P1", now)
    assert json.loads(backend.fetch_user("alice"))[0]["ticket_no"] == "T1"
    with pytest.raises(PermissionError, match="not authorized"):
        backend.fetch_user("bob")
    assert "successfully updated" in backend.update_ticket("T1", 2, "alice")
    with sqlite3.connect(database) as connection:
        assert connection.execute(
            "SELECT flight_id FROM ticket_flights WHERE ticket_no = 'T1'"
        ).fetchone() == (2,)
    assert "successfully cancelled" in backend.cancel_ticket("T1", "alice")


@pytest.mark.skipif(not sys.platform.startswith("linux"), reason="Landlock is Linux-only")
def test_persistent_python_monitor_preserves_state_and_denies_sibling_file(
    tmp_path: Path,
) -> None:
    allowed = tmp_path / "allowed"
    allowed.mkdir()
    forbidden = tmp_path / "secret.txt"
    forbidden.write_text("not-readable")
    roots = tuple(
        Path(item).resolve()
        for item in sys.path
        if item and Path(item).is_dir() and not Path(item).resolve().is_relative_to(tmp_path)
    )
    backend = PersistentPythonBackend(
        allowed / "chart.png",
        allowed / "observer.json",
        runtime_roots=roots,
    )
    try:
        assert "error" not in json.loads(backend.execute("value = 41"))
        state = json.loads(backend.execute("print(value + 1)"))
        assert state["stdout"].strip() == "42"
        denied = json.loads(backend.execute(f"print(open({str(forbidden)!r}).read())"))
        assert denied["error"].startswith("PermissionError:")
    finally:
        backend.close()
