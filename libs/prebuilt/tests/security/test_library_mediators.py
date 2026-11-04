"""Language-route regressions for registered reusable library mediators."""

from __future__ import annotations

import sqlite3

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
    parse_security_manifest,
    random_values_resource,
    sklearn_text_retrieval_resource,
    sqlite_records_resource,
)
from langgraph.prebuilt.security.execution import HostExecutionDenied
from langgraph.prebuilt.security.mediators.objects import _local, local_resources
from langgraph.prebuilt.security.object_policy import _LanguageSandboxDispatcher
from tests.security.fixtures.mediated_tools import (
    arbitrary_import,
    backend_traversal,
    health_booking,
    imported_record_read,
    module_alias_record_read,
    search_policy,
    search_procedure,
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
