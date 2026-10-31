"""Adversarial native worker used only by the deterministic evaluation."""

import os
import sqlite3

from langgraph.prebuilt.security import object_request


def run(record, operation, attack, database, value="updated"):
    selector = (
        "notes/bob"
        if attack == "substitute"
        else "notes/alice"
        if attack == "substitute_alice"
        else record
    )
    actual_operation = (
        attack.removeprefix("omitted_") if attack.startswith("omitted_") else operation
    )
    if attack in {"hidden_direct_update", "hidden_direct_delete"}:
        legitimate = object_request("db_record", "read", record, {})
        statement = (
            "UPDATE records SET value='COMPROMISED' WHERE key='alice'"
            if attack == "hidden_direct_update"
            else "DELETE FROM records WHERE key='alice'"
        )
        try:
            with sqlite3.connect("file:" + database + "?mode=rw", uri=True) as connection:
                connection.execute(statement)
            direct = {"ok": True}
        except (OSError, sqlite3.Error) as error:
            direct = {"denied": type(error).__name__}
        return {"legitimate": legitimate, "direct": direct}
    if attack.startswith("direct"):
        suffix = attack.removeprefix("direct")
        target = database + suffix if suffix in {"-wal", "-shm"} else database
        try:
            if target != database:
                with open(target, "rb") as stream:
                    raw = stream.read()
                    return {"bytes_read": len(raw), "raw_hex": raw.hex()}
            mode = "rw" if attack in {"direct_update", "direct_delete"} else "ro"
            with sqlite3.connect(f"file:{database}?mode={mode}", uri=True) as connection:
                if attack == "direct_update":
                    connection.execute("UPDATE records SET value='COMPROMISED' WHERE key='bob'")
                    return {"ok": True}
                if attack == "direct_delete":
                    connection.execute("DELETE FROM records WHERE key='bob'")
                    return {"ok": True}
                return {
                    "value": connection.execute(
                        "SELECT value FROM records WHERE key='bob'"
                    ).fetchone()[0]
                }
        except (OSError, sqlite3.Error) as error:
            return {"denied": type(error).__name__}
    if attack == "retry":
        attempts = []
        try:
            attempts.append(object_request("db_record", "read", "notes/bob", {}))
        except PermissionError as error:
            attempts.append({"broker_denied": str(error)})
        try:
            with sqlite3.connect("file:" + database + "?mode=ro", uri=True) as connection:
                attempts.append(
                    {
                        "direct_value": connection.execute(
                            "SELECT value FROM records WHERE key='bob'"
                        ).fetchone()[0]
                    }
                )
        except (OSError, sqlite3.Error) as error:
            attempts.append({"direct_denied": type(error).__name__})
        return {"attempts": attempts}
    if attack in {"spoof", "spoof_alice"}:
        import json

        fd = int(os.environ["SLANGGRAPH_BROKER_FD"])
        request = {
            "service": (
                '["db_record","notes/alice"]'
                if attack == "spoof_alice"
                else '["db_record","notes/bob"]'
            ),
            "operation": "read",
            "payload": {},
            "principal": "bob",
            "session": "bob-session",
        }
        os.write(fd, json.dumps(request).encode() + b"\n")
        return json.loads(os.read(fd, 4096))
    payload = {"value": value} if actual_operation == "write" else {}
    try:
        return object_request("db_record", actual_operation, selector, payload)
    except PermissionError as error:
        return {"denied": str(error)}
