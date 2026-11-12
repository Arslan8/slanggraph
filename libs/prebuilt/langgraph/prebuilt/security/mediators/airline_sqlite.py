"""Principal-bound airline operations over a setup-owned SQLite database."""

from __future__ import annotations

import json
import sqlite3
from abc import ABC, abstractmethod
from collections.abc import Mapping
from datetime import datetime
from pathlib import Path
from typing import Any

from langgraph.prebuilt.security.enforcement import HostAttestation, SupportLevel
from langgraph.prebuilt.security.mediators.contracts import ResourceContract
from langgraph.prebuilt.security.object_policy import ObjectGrantLine
from langgraph.prebuilt.security.resource_mediator import (
    ResourceInvocation,
    ResourceSupport,
)

_MAX_RESULT_BYTES = 256 * 1024


class AirlineSQLiteAPI(ABC):
    __slots__ = ()

    @abstractmethod
    def fetch_user(self) -> str:
        raise NotImplementedError

    @abstractmethod
    def search_flights(
        self,
        departure_airport: str,
        arrival_airport: str,
        start_time: str,
        end_time: str,
        limit: int,
    ) -> str:
        raise NotImplementedError

    @abstractmethod
    def update_ticket(self, ticket_no: str, new_flight_id: int) -> str:
        raise NotImplementedError

    @abstractmethod
    def cancel_ticket(self, ticket_no: str) -> str:
        raise NotImplementedError


AIRLINE_SQLITE = ResourceContract(
    AirlineSQLiteAPI,
    class_name="airline_sqlite",
    object_kind="database",
    lowering="library.airline.sqlite.v1",
)
airline_sqlite = AIRLINE_SQLITE.client(export=__name__ + ".airline_sqlite")


class _AirlineMediator:
    def __init__(self, principal_id: str) -> None:
        self.principal_id = principal_id

    def assess(self, line: ObjectGrantLine, host: HostAttestation) -> ResourceSupport:
        del line, host
        return ResourceSupport(
            SupportLevel.EXACT,
            "principal-bound parameterized airline operations with inert bounded output",
            witness="tests/security/test_library_mediators.py",
        )

    def validate(
        self,
        operation: str,
        arguments: Mapping[str, Any],
        context: ResourceInvocation,
    ) -> None:
        del operation
        if context.principal_id != self.principal_id:
            raise PermissionError("airline resource principal is not authorized")
        if any(type(key) is not str for key in arguments):
            raise TypeError("airline arguments require plain string keys")


def airline_sqlite_resource(
    path: str | Path,
    *,
    passenger_id: str,
    principal_id: str,
    frozen_now: datetime,
) -> ResourceContract[AirlineSQLiteAPI]:
    """Bind the ACE airline schema to one passenger and invocation principal."""
    if any(
        type(value) is not str or not value for value in (passenger_id, principal_id)
    ):
        raise ValueError("passenger_id and principal_id must be nonempty strings")
    if type(frozen_now) is not datetime:
        raise TypeError("frozen_now must be a datetime")
    database = Path(path).resolve(strict=True)
    if not database.is_file():
        raise ValueError("airline database must be an existing regular file")

    def bounded(rows: Any) -> str:
        result = json.dumps(rows, default=str, separators=(",", ":"))
        if len(result.encode("utf-8")) > _MAX_RESULT_BYTES:
            raise ValueError("airline result exceeds 262144 UTF-8 bytes")
        return result

    def connect() -> sqlite3.Connection:
        connection = sqlite3.connect(database, timeout=2.0)
        connection.execute("PRAGMA trusted_schema=OFF")
        return connection

    class Backend(AirlineSQLiteAPI):
        def fetch_user(self) -> str:
            query = """
            SELECT t.ticket_no, t.book_ref, f.flight_id, f.flight_no,
                   f.departure_airport, f.arrival_airport, f.scheduled_departure,
                   f.scheduled_arrival, bp.seat_no, tf.fare_conditions
            FROM tickets t JOIN ticket_flights tf ON t.ticket_no = tf.ticket_no
            JOIN flights f ON tf.flight_id = f.flight_id
            JOIN boarding_passes bp ON bp.ticket_no = t.ticket_no AND bp.flight_id = f.flight_id
            WHERE t.passenger_id = ?
            """
            with connect() as connection:
                cursor = connection.execute(query, (passenger_id,))
                names = [item[0] for item in cursor.description]
                rows = [
                    dict(zip(names, row, strict=True)) for row in cursor.fetchmany(1001)
                ]
            if len(rows) > 1000:
                raise ValueError("airline result exceeds 1000 rows")
            return bounded(rows)

        def search_flights(
            self,
            departure_airport: str,
            arrival_airport: str,
            start_time: str,
            end_time: str,
            limit: int,
        ) -> str:
            if not 1 <= limit <= 100:
                raise ValueError("flight search limit must be between 1 and 100")
            query = "SELECT * FROM flights WHERE 1 = 1"
            parameters: list[Any] = []
            for field, value in (
                ("departure_airport", departure_airport),
                ("arrival_airport", arrival_airport),
            ):
                if value:
                    query += f" AND {field} = ?"
                    parameters.append(value)
            if start_time:
                query += " AND scheduled_departure >= ?"
                parameters.append(start_time)
            if end_time:
                query += " AND scheduled_departure <= ?"
                parameters.append(end_time)
            query += " LIMIT ?"
            parameters.append(limit)
            with connect() as connection:
                cursor = connection.execute(query, parameters)
                names = [item[0] for item in cursor.description]
                rows = [dict(zip(names, row, strict=True)) for row in cursor.fetchall()]
            return bounded(rows)

        def update_ticket(self, ticket_no: str, new_flight_id: int) -> str:
            with connect() as connection:
                owner = connection.execute(
                    "SELECT 1 FROM tickets WHERE ticket_no = ? AND passenger_id = ?",
                    (ticket_no, passenger_id),
                ).fetchone()
                flight = connection.execute(
                    "SELECT departure_airport, arrival_airport, scheduled_departure "
                    "FROM flights WHERE flight_id = ?",
                    (new_flight_id,),
                ).fetchone()
                if owner is None:
                    return "Current signed-in passenger does not own this ticket."
                if flight is None:
                    return "Invalid new flight ID provided."
                departure = datetime.fromisoformat(flight[2])
                now = frozen_now
                if departure.tzinfo is None and now.tzinfo is not None:
                    departure = departure.replace(tzinfo=now.tzinfo)
                if (departure - now).total_seconds() < 3 * 3600:
                    return "Not permitted to reschedule to a flight less than 3 hours away."
                current = connection.execute(
                    "SELECT tf.flight_id FROM ticket_flights AS tf "
                    "JOIN flights AS f ON f.flight_id = tf.flight_id "
                    "WHERE tf.ticket_no = ? AND f.departure_airport = ? "
                    "AND f.arrival_airport = ? ORDER BY f.scheduled_departure LIMIT 1",
                    (ticket_no, flight[0], flight[1]),
                ).fetchone()
                if current is None:
                    return "No matching existing ticket leg found for the new flight route."
                connection.execute(
                    "UPDATE ticket_flights SET flight_id = ? "
                    "WHERE ticket_no = ? AND flight_id = ?",
                    (new_flight_id, ticket_no, current[0]),
                )
            return "Ticket successfully updated to new flight."

        def cancel_ticket(self, ticket_no: str) -> str:
            with connect() as connection:
                owner = connection.execute(
                    "SELECT 1 FROM tickets WHERE ticket_no = ? AND passenger_id = ?",
                    (ticket_no, passenger_id),
                ).fetchone()
                if owner is None:
                    return "Current signed-in passenger does not own this ticket."
                if (
                    connection.execute(
                        "SELECT 1 FROM ticket_flights WHERE ticket_no = ?", (ticket_no,)
                    ).fetchone()
                    is None
                ):
                    return "No existing ticket found for the given ticket number."
                connection.execute(
                    "DELETE FROM ticket_flights WHERE ticket_no = ?", (ticket_no,)
                )
            return "Ticket successfully cancelled."

    return AIRLINE_SQLITE.bind(
        implementation=Backend(), mediator=_AirlineMediator(principal_id)
    )
