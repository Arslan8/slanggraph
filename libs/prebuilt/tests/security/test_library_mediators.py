"""Language-route regressions for registered reusable library mediators."""

from __future__ import annotations

import sqlite3
from datetime import datetime, timezone

import pytest

from langgraph.prebuilt.security import (
    SQLITE_RECORD_SCHEMA,
    EnforcementKind,
    ObjectGrant,
    ObjectGrantLine,
    Principal,
    Requirement,
    SecurityConfigurationError,
    Tool,
    ToolCall,
    ToolDac,
    airline_sqlite_resource,
    parse_security_manifest,
    random_values_resource,
    readonly_sqlite_resource,
    sklearn_json_search_resource,
    sklearn_text_retrieval_resource,
    sqlite_records_resource,
)
from langgraph.prebuilt.security.execution import HostExecutionDenied
from langgraph.prebuilt.security.mediators.objects import _local, local_resources
from langgraph.prebuilt.security.object_policy import _LanguageSandboxDispatcher
from tests.security.fixtures.mediated_tools import (
    arbitrary_import,
    backend_traversal,
    change_flight,
    fetch_itinerary,
    health_booking,
    imported_record_read,
    list_database_tables,
    module_alias_record_read,
    query_database,
    search_policy,
    search_procedure,
    search_web,
    travel_booking,
    unregistered_record_member,
)


def _dispatcher(tool, resource, manifest):
    parsed = parse_security_manifest(
        resource.class_declaration(enforced_by="language_sandbox")
        + f"\ntool {tool.name} {{\nruns inprocess\n{manifest}\n}}"
    )
    return _LanguageSandboxDispatcher(tool, parsed, resources=(resource,))


def _invoke(dispatcher, tool, arguments, lines):
    principal = Principal("alice", frozenset(), frozenset(), "session")
    call = ToolCall(
        Tool(tool.name, ToolDac("owner", {"*": "x"}), frozenset(), ()),
        arguments,
        {},
        "call",
        0,
    )
    grant = ObjectGrant("alice", tool.name, "call", "policy", tuple(lines))
    return dispatcher.invoke(principal, call, grant).value


def _line(resource, operation, selector):
    return ObjectGrantLine(
        operation,
        resource.class_name,
        operation,
        selector,
        {},
        Requirement.NEED,
        EnforcementKind.LANGUAGE_SANDBOX,
        resource.lowering,
    )


def test_sqlite_registered_import_runs_and_checks_each_effect(tmp_path):
    database = tmp_path / "records.sqlite"
    with sqlite3.connect(database) as connection:
        connection.execute(SQLITE_RECORD_SCHEMA)
        connection.executemany(
            "INSERT INTO records VALUES (?, ?)",
            [("alice", "allowed"), ("bob", "forbidden")],
        )
    resource = sqlite_records_resource(database, database_id="notes")
    dispatcher = _dispatcher(
        imported_record_read, resource, "db_record read @{record} need"
    )
    allowed = _line(resource, "read", "notes/alice")
    assert _invoke(
        dispatcher, imported_record_read, {"record": "notes/alice"}, (allowed,)
    ) == {"found": True, "value": "allowed"}
    with pytest.raises(HostExecutionDenied, match="not_granted"):
        _invoke(
            dispatcher,
            imported_record_read,
            {"record": "notes/alice"},
            (_line(resource, "read", "notes/bob"),),
        )
    database.unlink()


def test_registered_module_alias_exposes_only_the_client(tmp_path):
    database = tmp_path / "records.sqlite"
    with sqlite3.connect(database) as connection:
        connection.execute(SQLITE_RECORD_SCHEMA)
        connection.execute("INSERT INTO records VALUES ('alice', 'allowed')")
    resource = sqlite_records_resource(database, database_id="notes")
    dispatcher = _dispatcher(
        module_alias_record_read, resource, "db_record read @{record} need"
    )
    assert (
        _invoke(
            dispatcher,
            module_alias_record_read,
            {"record": "notes/alice"},
            (_line(resource, "read", "notes/alice"),),
        )["value"]
        == "allowed"
    )


def test_selector_dispatch_cannot_survive_its_invocation(tmp_path):
    database = tmp_path / "records.sqlite"
    with sqlite3.connect(database) as connection:
        connection.execute(SQLITE_RECORD_SCHEMA)
        connection.execute("INSERT INTO records VALUES ('alice', 'allowed')")
    resource = sqlite_records_resource(database, database_id="notes")
    principal = Principal("alice", frozenset(), frozenset(), "session")
    call = ToolCall(
        Tool(
            imported_record_read.name,
            ToolDac("owner", {"*": "x"}),
            frozenset(),
            (),
        ),
        {"record": "notes/alice"},
        {},
        "call",
        0,
    )
    grant = ObjectGrant(
        "alice",
        imported_record_read.name,
        "call",
        "policy",
        (_line(resource, "read", "notes/alice"),),
    )
    with local_resources((resource,), principal, call, grant):
        dispatch = _local.get()
        assert dispatch(("db_record", "notes/alice"), "read", {})["found"]
    with pytest.raises(HostExecutionDenied, match="invocation_closed"):
        dispatch(("db_record", "notes/alice"), "read", {})


@pytest.mark.parametrize(
    "candidate,reason",
    [
        (unregistered_record_member, "unmodeled call"),
        (backend_traversal, "attribute access"),
        (arbitrary_import, "unregistered_import"),
    ],
)
def test_imports_expose_only_registered_interfaces(candidate, reason, tmp_path):
    database = tmp_path / "records.sqlite"
    with sqlite3.connect(database) as connection:
        connection.execute(SQLITE_RECORD_SCHEMA)
    resource = sqlite_records_resource(database, database_id="notes")
    with pytest.raises(SecurityConfigurationError, match=reason):
        _dispatcher(candidate, resource, "db_record read @{record} need")


def test_two_tools_reuse_one_randomness_integration():
    resource = random_values_resource()
    health = _dispatcher(
        health_booking, resource, resource.permission("appointment_time")
    )
    assert health.admission.language_proofs()["func"]["effects"] == [
        "langgraph.prebuilt.security.mediators.randomness.random_values.appointment_time"
    ]
    travel = _dispatcher(
        travel_booking,
        resource,
        resource.permission("appointment_time")
        + "\n"
        + resource.permission("booking_reference"),
    )
    time_line = _line(resource, "appointment_time", resource._object_id)
    health_result = _invoke(health, health_booking, {"name": "Alice"}, (time_line,))
    assert health_result["name"] == "Alice"
    assert len(health_result["time"]) == 8
    travel_result = _invoke(
        travel,
        travel_booking,
        {"name": "Alice"},
        (
            time_line,
            _line(resource, "booking_reference", resource._object_id),
        ),
    )
    assert len(travel_result["reference"]) == 6


def test_sklearn_integration_is_useful_reusable_and_grant_scoped():
    pytest.importorskip("sklearn")
    resource = sklearn_text_retrieval_resource(
        ("retention policy is seven years", "travel policy permits rail"), top_k=1
    )
    line = _line(resource, "search", resource._object_id)
    for candidate in (search_policy, search_procedure):
        dispatcher = _dispatcher(candidate, resource, resource.permission("search"))
        assert "seven years" in _invoke(
            dispatcher, candidate, {"query": "retention"}, (line,)
        )
        with pytest.raises(HostExecutionDenied, match="not_granted"):
            _invoke(dispatcher, candidate, {"query": "retention"}, ())


def test_sklearn_json_search_returns_only_inert_registered_fields():
    pytest.importorskip("sklearn")
    resource = sklearn_json_search_resource(
        (
            {
                "url": "https://example.test/a",
                "title": "Rail",
                "content": "rail policy",
            },
            {"url": "https://example.test/b", "title": "Air", "content": "air policy"},
        ),
        top_k=1,
    )
    dispatcher = _dispatcher(search_web, resource, resource.permission("search"))
    result = _invoke(
        dispatcher,
        search_web,
        {"query": "rail"},
        (_line(resource, "search", resource._object_id),),
    )
    assert result == '[{"url":"https://example.test/a","content":"rail policy"}]'


def test_readonly_sqlite_is_reusable_grant_scoped_and_rejects_mutation(tmp_path):
    database = tmp_path / "application.sqlite"
    with sqlite3.connect(database) as connection:
        connection.execute("CREATE TABLE cities (name TEXT PRIMARY KEY)")
        connection.executemany("INSERT INTO cities VALUES (?)", [("NYC",), ("SF",)])
    resource = readonly_sqlite_resource(database)

    list_line = _line(resource, "list_tables", resource._object_id)
    listing = _dispatcher(
        list_database_tables, resource, resource.permission("list_tables")
    )
    assert _invoke(listing, list_database_tables, {}, (list_line,)) == "cities"

    query_line = _line(resource, "query", resource._object_id)
    querying = _dispatcher(query_database, resource, resource.permission("query"))
    assert "NYC" in _invoke(
        querying,
        query_database,
        {"query": "SELECT name FROM cities ORDER BY name"},
        (query_line,),
    )
    with pytest.raises(HostExecutionDenied, match="not_granted"):
        _invoke(
            querying,
            query_database,
            {"query": "SELECT name FROM cities"},
            (),
        )
    with pytest.raises(PermissionError, match="only SELECT"):
        _invoke(
            querying,
            query_database,
            {"query": "DELETE FROM cities"},
            (query_line,),
        )
    with sqlite3.connect(database) as connection:
        assert connection.execute("SELECT count(*) FROM cities").fetchone() == (2,)


def test_airline_sqlite_binds_principal_and_checks_mutation_grant(tmp_path):
    database = tmp_path / "airline.sqlite"
    with sqlite3.connect(database) as connection:
        connection.executescript(
            """
            CREATE TABLE tickets(ticket_no TEXT PRIMARY KEY, book_ref TEXT, passenger_id TEXT);
            CREATE TABLE flights(flight_id INTEGER PRIMARY KEY, flight_no TEXT,
              departure_airport TEXT, arrival_airport TEXT, scheduled_departure TEXT,
              scheduled_arrival TEXT);
            CREATE TABLE ticket_flights(ticket_no TEXT, flight_id INTEGER, fare_conditions TEXT);
            CREATE TABLE boarding_passes(ticket_no TEXT, flight_id INTEGER, seat_no TEXT);
            INSERT INTO tickets VALUES ('T1', 'B1', 'P1');
            INSERT INTO flights VALUES (1, 'F1', 'SFO', 'JFK', '2027-01-01T12:00:00+00:00', '2027-01-01T18:00:00+00:00');
            INSERT INTO flights VALUES (2, 'F2', 'SFO', 'JFK', '2027-01-02T12:00:00+00:00', '2027-01-02T18:00:00+00:00');
            INSERT INTO flights VALUES (3, 'F3', 'JFK', 'SFO', '2027-01-03T12:00:00+00:00', '2027-01-03T18:00:00+00:00');
            INSERT INTO ticket_flights VALUES ('T1', 1, 'Economy');
            INSERT INTO ticket_flights VALUES ('T1', 3, 'Economy');
            INSERT INTO boarding_passes VALUES ('T1', 1, '1A');
            """
        )
    resource = airline_sqlite_resource(
        database,
        passenger_id="P1",
        principal_id="alice",
        frozen_now=datetime(2026, 1, 1, tzinfo=timezone.utc),
    )
    fetch = _dispatcher(fetch_itinerary, resource, resource.permission("fetch_user"))
    assert '"ticket_no":"T1"' in _invoke(
        fetch,
        fetch_itinerary,
        {},
        (_line(resource, "fetch_user", resource._object_id),),
    )
    update = _dispatcher(change_flight, resource, resource.permission("update_ticket"))
    with pytest.raises(HostExecutionDenied, match="not_granted"):
        _invoke(update, change_flight, {"ticket_no": "T1", "flight_id": 2}, ())
    assert "successfully updated" in _invoke(
        update,
        change_flight,
        {"ticket_no": "T1", "flight_id": 2},
        (_line(resource, "update_ticket", resource._object_id),),
    )
    with sqlite3.connect(database) as connection:
        assert connection.execute(
            "SELECT flight_id FROM ticket_flights WHERE ticket_no = 'T1' ORDER BY flight_id"
        ).fetchall() == [(2,), (3,)]
