"""Tool-side travel operations over the typed travel resource."""

from langgraph.prebuilt.security.mediators.airline_sqlite import airline_sqlite as travel


def fetch_user_flight_information() -> str:
    return travel.fetch_user()


def search_flights(
    departure_airport: str = "",
    arrival_airport: str = "",
    start_time: str = "",
    end_time: str = "",
    limit: int = 20,
) -> str:
    return travel.search_flights(
        departure_airport,
        arrival_airport,
        start_time,
        end_time,
        limit,
    )


def update_ticket_to_new_flight(ticket_no: str, new_flight_id: int) -> str:
    return travel.update_ticket(ticket_no, new_flight_id)


def cancel_ticket(ticket_no: str) -> str:
    return travel.cancel_ticket(ticket_no)
