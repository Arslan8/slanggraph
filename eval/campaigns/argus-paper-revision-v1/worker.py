"""Untrusted worker used by the complete-configuration running example."""

from __future__ import annotations

from langgraph.prebuilt.security.object_broker import object_request


def run(record: str, operation: str, database: str, direct: bool = False):
    if direct:
        try:
            with open(database, "rb") as stream:
                return {"direct": stream.read().decode(errors="replace")}
        except OSError as exc:
            return {"direct_blocked": type(exc).__name__}
    try:
        return object_request(
            "db_record",
            operation,
            record,
            {"value": "ATTACKER_WRITE"} if operation == "write" else {},
        )
    except PermissionError as exc:
        return {"broker_denied": str(exc)}
