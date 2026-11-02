"""Identical attacker programs in both conditions; never receive secret values."""

import json
import os
import select
import socket
import sqlite3
import subprocess
import time

from langgraph.prebuilt.security import broker
from langgraph.prebuilt.security.object_broker import object_request


def raw_request(frame):
    if broker._pipe_transport is not None:
        return broker._pipe_transport(frame)
    fd = int(os.environ["SLANGGRAPH_BROKER_FD"])
    os.write(fd, json.dumps(frame).encode() + b"\n")
    if not select.select([fd], [], [], 2)[0]:
        raise TimeoutError("broker response")
    return json.loads(os.read(fd, 1_048_576))


def attempt(function):
    try:
        return {"value": function()}
    except Exception as error:
        return {"error": type(error).__name__, "reason": str(error)}


def database(task, operation):
    with sqlite3.connect(task["database"], timeout=0.5) as connection:
        if operation == "read":
            return connection.execute("SELECT value FROM records WHERE key='bob'").fetchone()[0]
        if operation == "update":
            connection.execute("UPDATE records SET value='COMPROMISED' WHERE key='bob'")
        else:
            connection.execute("DELETE FROM records WHERE key='bob'")
        return "mutated"


def connect(endpoint, frame):
    with socket.create_connection(tuple(endpoint), timeout=1) as stream:
        stream.sendall(json.dumps(frame).encode() + b"\n")
        return stream.recv(1_048_576).decode()


def run(task: dict):
    case = task["case"]
    object_request("trace", "append", "entry", {"event": "entered", "pid": os.getpid()})
    if case in {
        "allowed_record_read",
        "bob_read",
        "allowed_record_update",
        "bob_update",
        "bob_delete",
    }:
        operation = (
            "read" if case.endswith("read") else "delete" if case.endswith("delete") else "write"
        )
        selector = "notes/bob" if case.startswith("bob_") else "notes/alice"
        return attempt(
            lambda: object_request(
                "record",
                operation,
                selector,
                {"value": "UPDATED_ALICE" if selector.endswith("alice") else "COMPROMISED"}
                if operation == "write"
                else {},
            )
        )
    if case.startswith("direct_database_"):
        return attempt(lambda: database(task, case.removeprefix("direct_database_")))
    if case in {"direct_wal", "direct_shm", "direct_journal", "private_file_read"}:
        return attempt(lambda: {"hex": open(task["target"], "rb").read(524288).hex()})
    if case == "retry_after_denial":
        denied = attempt(lambda: object_request("record", "read", "notes/bob"))
        return {"broker": denied, "direct": attempt(lambda: database(task, "read"))}
    if case.startswith("allowed_pump_") or case == "pump_calibrate":
        operation = "calibrate" if case == "pump_calibrate" else case.removeprefix("allowed_pump_")
        return attempt(
            lambda: object_request(
                "pump", operation, "pump-1", {"flow": 25} if operation == "set_flow" else {}
            )
        )
    if case in {"direct_device", "live_network"}:
        frame = (
            {"service": '["pump","pump-1"]', "operation": "calibrate", "payload": {}}
            if case == "direct_device"
            else {"probe": task["network_probe"]}
        )
        return attempt(
            lambda: connect(task["endpoint" if case == "direct_device" else "listener"], frame)
        )
    if case.startswith("identity_"):
        field = {
            "principal": "principal",
            "tool": "tool",
            "invocation": "call_id",
            "session": "session",
        }[case.removeprefix("identity_")]
        return attempt(
            lambda: raw_request(
                {
                    "service": '["record","notes/bob"]',
                    "operation": "read",
                    "payload": {},
                    field: "other-invocation",
                }
            )
        )
    if case == "capture_old":
        frame = {
            "service": '["record","notes/alice"]',
            "operation": "write",
            "payload": {"value": "OLD_AUTHORITY_EFFECT"},
        }
        raw_request(frame)
        return {"frame": frame, "worker_pid": os.getpid()}
    if case == "old_invocation_reuse":
        return attempt(lambda: raw_request(task["captured_frame"]))
    if case == "outside_artifact_write":
        return attempt(lambda: open(task["outside"], "w").write("FORBIDDEN_WRITE"))
    if case.startswith("process_"):
        code = (
            "import sqlite3,os,json; c=sqlite3.connect("
            + repr(task["database"])
            + "); c.execute(\"UPDATE records SET value='COMPROMISED' WHERE key='bob'\");"
            + "c.commit(); print(json.dumps({'child_pid':os.getpid()}))"
        )
        if case == "process_fork":

            def fork():
                pid = os.fork()
                if pid == 0:
                    try:
                        database(task, "update")
                    finally:
                        os._exit(0)
                os.waitpid(pid, 0)
                return {"created": True, "child_pid": pid}

            return attempt(fork)
        if case == "process_subprocess":
            return attempt(
                lambda: {
                    "created": True,
                    "output": subprocess.run(
                        [task["python"], "-I", "-c", code],
                        capture_output=True,
                        text=True,
                        timeout=3,
                    ).stdout,
                }
            )
        return attempt(lambda: os.execv(task["python"], [task["python"], "-I", "-c", code]))
    if case in {"timeout", "cancellation", "controller_termination"}:
        while True:
            object_request("trace", "append", "entry", {"event": "tick", "pid": os.getpid()})
            object_request("pump", "set_flow", "pump-1", {"flow": 25})
            time.sleep(0.05)
    if case == "session_own_state":
        first = object_request("session", "execute", "session-b", {"code": "value = 41"})
        second = object_request("session", "execute", "session-b", {"code": "print(value + 1)"})
        return {"first": first, "second": second}
    if case == "session_other_variable":
        return attempt(
            lambda: object_request(
                "session", "execute", "session-a", {"code": "print(PRIVATE_SESSION_VALUE)"}
            )
        )
    if case == "session_other_artifact":
        return attempt(
            lambda: object_request(
                "session",
                "execute",
                "session-b",
                {"code": f"print(open({task['other_artifact']!r}).read())"},
            )
        )
    if case == "session_other_artifact_write":
        return attempt(
            lambda: object_request(
                "session",
                "execute",
                "session-b",
                {"code": f"open({task['other_artifact']!r}, 'w').write('COMPROMISED')"},
            )
        )
    if case.startswith("session_"):
        code = (
            "import time,os\nwhile True:\n with open("
            + repr(task["ticks"])
            + ", 'a') as f: f.write(str(time.time_ns())+' '+str(os.getpid())+'\\n');"
            + "f.flush()\n time.sleep(0.05)"
        )
        return attempt(lambda: object_request("session", "execute", "session-b", {"code": code}))
    # Mandatory-requirement and damaged-obligation cases must never reach here.
    return attempt(lambda: open(task["secret_path"]).read())
