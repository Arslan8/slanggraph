"""Source-backed tools used by reusable mediator admission tests."""

# ruff: noqa: PLC0415 - local imports are the security surface under test.

from langchain_core.tools import tool


@tool
def imported_record_read(record: str) -> dict:
    """Read a record through a locally imported registered client."""
    from langgraph.prebuilt.security.mediators.records import records as db

    return db.read(record)


@tool
def module_alias_record_read(record: str) -> dict:
    """Read a record through a registered module alias."""
    import langgraph.prebuilt.security.mediators.records as record_api

    return record_api.records.read(record)


@tool
def unregistered_record_member(record: str) -> dict:
    """Attempt an unregistered member of an otherwise registered client."""
    from langgraph.prebuilt.security.mediators.records import records as db

    return db.connection(record)


@tool
def backend_traversal(record: str) -> str:
    """Attempt object traversal from a registered client alias."""
    from langgraph.prebuilt.security.mediators.records import records as db

    return str(db.__class__)


@tool
def arbitrary_import(record: str) -> str:
    """Attempt to import an unregistered Python module."""
    import sqlite3

    return str(sqlite3.connect(record))


@tool
def health_booking(name: str) -> dict:
    """Create appointment data using the registered random-value interface."""
    from langgraph.prebuilt.security.mediators.randomness import (
        random_values as random_api,
    )

    return {"name": name, "time": random_api.appointment_time()}


@tool
def travel_booking(name: str) -> dict:
    """Create travel data using the same registered random-value interface."""
    from langgraph.prebuilt.security.mediators.randomness import (
        random_values as random_api,
    )

    return {
        "name": name,
        "time": random_api.appointment_time(),
        "reference": random_api.booking_reference(),
    }


@tool
def search_policy(query: str) -> str:
    """Search a setup-bound text index."""
    from langgraph.prebuilt.security.mediators.retrieval import (
        text_retrieval as search,
    )

    return search.search(query)


@tool
def search_procedure(query: str) -> str:
    """A second tool reusing the same setup-bound text index."""
    from langgraph.prebuilt.security.mediators.retrieval import (
        text_retrieval as search,
    )

    return search.search(query)


@tool
def search_web(query: str) -> str:
    """Search a setup-bound JSON result index."""
    from langgraph.prebuilt.security.mediators.retrieval import json_search as search

    return search.search(query)


@tool
def list_database_tables() -> str:
    """List tables through the registered read-only SQLite interface."""
    from langgraph.prebuilt.security.mediators.readonly_sqlite import (
        readonly_sqlite as database,
    )

    return database.list_tables()


@tool
def query_database(query: str) -> str:
    """Run one read-only query through the registered SQLite interface."""
    from langgraph.prebuilt.security.mediators.readonly_sqlite import (
        readonly_sqlite as database,
    )

    return database.query(query)


@tool
def fetch_itinerary() -> str:
    """Fetch the setup-bound passenger itinerary."""
    from langgraph.prebuilt.security.mediators.airline_sqlite import (
        airline_sqlite as airline,
    )

    return airline.fetch_user()


@tool
def change_flight(ticket_no: str, flight_id: int) -> str:
    """Change one setup-bound passenger ticket."""
    from langgraph.prebuilt.security.mediators.airline_sqlite import (
        airline_sqlite as airline,
    )

    return airline.update_ticket(ticket_no, flight_id)
