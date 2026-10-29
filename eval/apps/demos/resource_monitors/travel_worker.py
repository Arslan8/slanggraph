"""Worker-side travel tool implementations over the typed travel resource."""

import json

from .api import travel


def fetch_user_flight_information() -> list[dict]:
    return json.loads(travel.fetch_user("alice"))


def search_flights(
    departure_airport: str | None = None,
    arrival_airport: str | None = None,
    start_time: str | None = None,
    end_time: str | None = None,
    limit: int = 20,
) -> list[dict]:
    return json.loads(
        travel.search_flights(
            json.dumps(
                {
                    "departure_airport": departure_airport,
                    "arrival_airport": arrival_airport,
                    "start_time": start_time,
                    "end_time": end_time,
                    "limit": limit,
                }
            )
        )
    )


def update_ticket_to_new_flight(ticket_no: str, new_flight_id: int) -> str:
    return travel.update_ticket(ticket_no, new_flight_id, "alice")


def cancel_ticket(ticket_no: str) -> str:
    return travel.cancel_ticket(ticket_no, "alice")
