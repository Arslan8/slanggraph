"""Explicit API adaptations for the frozen ACE language-route census."""


def health_companion(
    name: str,
    dob: str,
    city: str,
    email: str,
    preferred_date: str,
    medical_issues: str,
    preferred_doctor: str = "",
) -> dict:
    """Book a healthcare appointment through the registered randomness API."""
    from langgraph.prebuilt.security.mediators.randomness import (
        random_values as random_api,
    )

    doctor = "Any available"
    if preferred_doctor != "":
        doctor = preferred_doctor
    return {
        "result": (
            f"{name}|{dob}|{city}|{email}|{preferred_date} "
            f"{random_api.appointment_time()}|{medical_issues}|{doctor}"
        )
    }


def travel_mate(
    name: str = "",
    email: str = "",
    departure_city: str = "",
    destination_city: str = "",
    departure_date: str = "",
    class_of_service: str = "",
    special_requirements: str = "",
) -> dict:
    """Create a travel booking through the same registered randomness API."""
    from langgraph.prebuilt.security.mediators.randomness import (
        random_values as random_api,
    )

    return {
        "result": (
            f"{name}|{email}|{departure_city}|{destination_city}|{departure_date} "
            f"{random_api.appointment_time()}|{class_of_service}|"
            f"{special_requirements}|{random_api.booking_reference()}"
        )
    }
