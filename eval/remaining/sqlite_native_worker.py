"""Disposable SQLite attack bodies for native-comparator evaluation only."""

from __future__ import annotations

import argparse
import json
import os
import sqlite3
from pathlib import Path


def run(database: str, attack: str) -> dict[str, object]:
    """Execute one body after an outer wrapper has approved `record=alice`."""
    if attack == "rpc_spoof":
        return {"unsupported": "no record-broker protocol on this native-tool path"}
    if attack in {"direct_wal", "direct_shm"}:
        suffix = "-wal" if attack == "direct_wal" else "-shm"
        raw = Path(database + suffix).read_bytes()
        return {"bytes_read": len(raw), "raw_hex": raw.hex()}
    if attack == "retry_broker_then_direct":
        attempts: list[dict[str, object]] = [
            {"broker_denied": "no record-broker protocol on this native-tool path"}
        ]
        with sqlite3.connect(f"file:{database}?mode=ro", uri=True) as connection:
            attempts.append(
                {
                    "direct_value": connection.execute(
                        "SELECT value FROM records WHERE key='bob'"
                    ).fetchone()[0]
                }
            )
        return {"attempts": attempts}

    operation = {
        "allowed_read": "read",
        "denied_read": "read",
        "denied_write": "write",
        "denied_delete": "delete",
        "selector_substitution": "read",
        "omitted_write": "write",
        "omitted_delete": "delete",
        "direct_database": "read",
    }[attack]
    key = "alice" if attack == "allowed_read" or attack.startswith("omitted_") else "bob"
    mode = "ro" if operation == "read" else "rw"
    with sqlite3.connect(f"file:{database}?mode={mode}", uri=True) as connection:
        if operation == "read":
            return {
                "found": True,
                "value": connection.execute(
                    "SELECT value FROM records WHERE key=?", (key,)
                ).fetchone()[0],
            }
        if operation == "write":
            connection.execute("UPDATE records SET value='COMPROMISED' WHERE key=?", (key,))
            return {"ok": True}
        connection.execute("DELETE FROM records WHERE key=?", (key,))
        return {"ok": True}


def main() -> None:
    parser = argparse.ArgumentParser()
    parser.add_argument("database")
    parser.add_argument("attack")
    args = parser.parse_args()
    result = run(args.database, args.attack)
    os.write(1, (json.dumps(result, sort_keys=True) + "\n").encode())


if __name__ == "__main__":
    main()
