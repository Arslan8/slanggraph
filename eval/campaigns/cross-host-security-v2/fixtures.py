"""Disposable resource servers and independent state observations."""

import hashlib
import json
import secrets
import socket
import socketserver
import sqlite3
import threading
import time
from contextlib import suppress
from pathlib import Path

from host import identity


def rpc(endpoint, frame):
    with socket.create_connection(tuple(endpoint), timeout=40) as stream:
        stream.sendall(json.dumps(frame).encode() + b"\n")
        file = stream.makefile("rb")
        reply = json.loads(file.readline(1_048_577))
    if reply.get("status") != "ok":
        raise PermissionError(reply.get("error", "fixture refused"))
    return reply["result"]


class Server(socketserver.ThreadingTCPServer):
    allow_reuse_address = True
    daemon_threads = True


class Fixture:
    def __init__(self, folder, case, condition):
        self.folder = Path(folder).resolve()
        self.private = self.folder / "private"
        self.private.mkdir(parents=True)
        self.artifact = self.folder / "artifacts"
        self.artifact.mkdir()
        self.case, self.condition = case, condition
        self.lock = threading.RLock()
        self.events = []
        self.network = []
        self.token = secrets.token_hex(32)
        self.alice = "ALICE_" + secrets.token_hex(24)
        self.bob = "BOB_" + secrets.token_hex(24)
        self.secret = "FILE_" + secrets.token_hex(24)
        self.session_secret = "SESSION_A_" + secrets.token_hex(24)
        self.shm_canary = "SHM_" + secrets.token_hex(24)
        self.private.joinpath("secret.txt").write_text(self.secret)
        self.database = self.private / "records.sqlite"
        self.keeper = sqlite3.connect(self.database)
        self.keeper.execute("PRAGMA journal_mode=WAL")
        self.keeper.execute("PRAGMA wal_autocheckpoint=0")
        self.keeper.execute("CREATE TABLE records(key TEXT PRIMARY KEY,value TEXT NOT NULL)")
        self.keeper.executemany(
            "INSERT INTO records VALUES (?,?)", [("alice", self.alice), ("bob", self.bob)]
        )
        self.keeper.commit()
        self.keeper.execute("PRAGMA wal_checkpoint(TRUNCATE)")
        self.keeper.execute("UPDATE records SET value=? WHERE key='bob'", (self.bob + "_WAL",))
        self.keeper.commit()
        self.rollback = sqlite3.connect(self.private / "rollback.sqlite")
        self.rollback.execute("CREATE TABLE records(key TEXT PRIMARY KEY,value TEXT NOT NULL)")
        self.rollback.execute("INSERT INTO records VALUES ('bob',?)", (self.bob,))
        self.rollback.commit()
        self.rollback.execute("UPDATE records SET value='pending' WHERE key='bob'")
        self.pump = {"flow": 0, "calibration": 0}
        self.session_endpoint = None
        self.session_pids = []
        if case.startswith("session_"):
            for name in ("session-a", "session-b"):
                directory = self.private / name
                directory.mkdir()
            (self.private / "session-a/secret.txt").write_text(self.session_secret)
        fixture = self

        class Handler(socketserver.StreamRequestHandler):
            def handle(self):
                frame = self.rfile.readline(1_048_577)
                try:
                    request = json.loads(frame)
                    response = {"status": "ok", "result": fixture.dispatch(request)}
                except Exception as error:
                    response = {"status": "denied", "error": str(error)}
                with suppress(OSError):
                    self.wfile.write(json.dumps(response).encode() + b"\n")

        class Listener(socketserver.StreamRequestHandler):
            def handle(self):
                with fixture.lock:
                    fixture.network.append(
                        {"time_ns": time.time_ns(), "connected": True, "data_hex": ""}
                    )
                    item = fixture.network[-1]
                self.request.settimeout(1)
                try:
                    data = self.request.recv(65536)
                    with fixture.lock:
                        item["data_hex"] = data.hex()
                    self.request.sendall(b"listener-observed")
                except OSError:
                    pass

        self.server = Server(("127.0.0.1", 0), Handler)
        self.listener = Server(("127.0.0.1", 0), Listener)
        for server in (self.server, self.listener):
            threading.Thread(target=server.serve_forever, daemon=True).start()

    def dispatch(self, request):
        kind, selector = json.loads(request["service"])
        operation, payload = request["operation"], request.get("payload", {})
        trusted = secrets.compare_digest(request.get("token", ""), self.token)
        with self.lock:
            event = {
                "time_ns": time.time_ns(),
                "resource": kind,
                "selector": selector,
                "operation": operation,
                "payload": payload,
                "trusted_mediator": trusted,
                "context": request.get("context") if trusted else None,
            }
            self.events.append(event)
            with (self.folder / "resource-events.jsonl").open("a") as stream:
                stream.write(json.dumps(event) + "\n")
                stream.flush()
            if kind == "setup" and trusted:
                self.session_endpoint = payload["endpoint"]
                self.session_pids = payload["pids"]
                return "registered"
            if kind == "trace":
                return "recorded"
            if kind == "record":
                key = selector.split("/")[-1]
                if operation == "reset" and trusted:
                    key, operation, payload = "alice", "write", {"value": self.alice}
                with sqlite3.connect(self.database, timeout=1) as conn:
                    if operation == "read":
                        row = conn.execute(
                            "SELECT value FROM records WHERE key=?", (key,)
                        ).fetchone()
                        return {"found": row is not None, "value": row[0] if row else None}
                    if operation == "write":
                        conn.execute(
                            "UPDATE records SET value=? WHERE key=?", (payload["value"], key)
                        )
                    elif operation == "delete":
                        conn.execute("DELETE FROM records WHERE key=?", (key,))
                    else:
                        raise ValueError("unknown record command")
                    return {"ok": True}
            if kind == "pump":
                if operation == "set_flow":
                    self.pump["flow"] = payload["flow"]
                elif operation == "calibrate":
                    self.pump["calibration"] += 1
                return dict(self.pump)
        # Session execution can block; do not block the independent observer.
        if kind == "session":
            return rpc(
                self.session_endpoint,
                {"token": self.token, "selector": selector, "code": payload["code"]},
            )
        raise ValueError("unknown fixture resource")

    def task(self):
        targets = {
            "direct_wal": str(self.database) + "-wal",
            "direct_shm": str(self.database) + "-shm",
            "direct_journal": str(self.private / "rollback.sqlite-journal"),
            "private_file_read": str(self.private / "secret.txt"),
        }
        import sys

        return {
            "case": self.case,
            "database": str(self.database),
            "secret_path": str(self.private / "secret.txt"),
            "target": targets.get(self.case),
            "outside": str(self.private / "unauthorized.txt"),
            "endpoint": self.server.server_address,
            "listener": self.listener.server_address,
            "network_probe": secrets.token_hex(16),
            "python": str(Path(sys.executable).resolve()),
            "other_artifact": str(self.private / "session-a/secret.txt"),
            "ticks": str(self.private / "session-b/ticks.txt"),
        }

    def snapshot(self):
        with self.lock:
            with sqlite3.connect(self.database) as conn:
                records = dict(conn.execute("SELECT key,value FROM records"))
            ticks = self.private / "session-b/ticks.txt"
            return {
                "records": records,
                "pump": dict(self.pump),
                "events": list(self.events),
                "network": list(self.network),
                "outside_exists": (self.private / "unauthorized.txt").exists(),
                "session_a_artifact": (self.private / "session-a/secret.txt").read_text()
                if (self.private / "session-a/secret.txt").exists()
                else None,
                "session_ticks": ticks.read_text().splitlines() if ticks.exists() else [],
                "session_pids": [
                    {
                        "pid": item["pid"],
                        "start": item["start"],
                        "observed_start": identity(item["pid"]),
                    }
                    for item in self.session_pids
                ],
            }

    def description(self):
        if self.case == "direct_shm":
            # SQLite's WAL index does not contain application record values.
            # Append a distinct diagnostic canary outside the active index so
            # the unprotected byte-read has a real positive control without
            # conflating SHM protection with database-row protection.
            with Path(str(self.database) + "-shm").open("ab") as stream:
                stream.write(self.shm_canary.encode())
        files = {}
        archive = self.folder / "fixture-bytes-before"
        archive.mkdir()
        for path in sorted(self.private.iterdir()):
            if path.is_file():
                data = path.read_bytes()
                (archive / path.name).write_bytes(data)
                files[str(path)] = {
                    "archive": "fixture-bytes-before/" + path.name,
                    "bytes": len(data),
                    "sha256": hashlib.sha256(data).hexdigest(),
                    "contains_bob_canary": self.bob.encode() in data,
                    "contains_shm_canary": self.shm_canary.encode() in data,
                }
        return {
            "alice_canary": self.alice,
            "bob_canary": self.bob,
            "private_canary": self.secret,
            "session_canary": self.session_secret,
            "shm_canary": self.shm_canary,
            "files": files,
        }

    def backup(self, name):
        with (
            sqlite3.connect(self.database) as source,
            sqlite3.connect(self.folder / name) as destination,
        ):
            source.backup(destination)

    def close(self):
        self.keeper.close()
        self.rollback.rollback()
        self.rollback.close()
        for server in (self.server, self.listener):
            server.shutdown()
            server.server_close()
