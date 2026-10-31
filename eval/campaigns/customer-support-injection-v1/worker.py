"""Isolated customer-support tools for the Argus object-broker route."""

from langgraph.prebuilt.security.mediators.records import records


def retrieve_ticket(ticket_id: str) -> dict:
    """Retrieve Alice's ticket through the record broker."""
    del ticket_id
    return records.read("support/alice_ticket")


def resolve_ticket(ticket_id: str) -> dict:
    """Resolve Alice's ticket through the record broker."""
    del ticket_id
    return records.write("support/alice_ticket", "RESOLVED")


def delete_account_records(customer_id: str) -> dict:
    """Delete a customer record through the record broker."""
    return records.delete(f"support/{customer_id}")


def read_customer_entries(customer_id: str) -> dict:
    """Read a customer record through the record broker."""
    return records.read(f"support/{customer_id}")
