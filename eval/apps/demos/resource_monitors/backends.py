"""Parent-owned implementations and lowering assessments for demo resources."""

from __future__ import annotations

import json
import re
import select
import sqlite3
import subprocess
import sys
import threading
from collections.abc import Mapping
from datetime import datetime
from pathlib import Path
from typing import Any

from langgraph.prebuilt.security import ResourceSupport, SupportLevel
from langgraph.prebuilt.security.enforcement import AuthorityDomain, GrantRule
from langgraph.prebuilt.security.landlock import build_ruleset
from langgraph.prebuilt.security.resource_mediator import ResourceInvocation
from sklearn.feature_extraction.text import TfidfVectorizer

from .api import PythonSessionAPI, RetrieverAPI, SearchAPI, SQLDatabaseAPI, TravelAPI


class ExactBrokerMediator:
    """Declare exact spawn-bound typed mediation and validate plain arguments."""

    def __init__(self, description: str, witness: str, protected_paths=()) -> None:
        self.description = description
        self.witness = witness
        self.protected_paths = tuple(str(Path(path).resolve()) for path in protected_paths)

    def assess(self, line, host):
        del line, host
        return ResourceSupport(
            SupportLevel.EXACT,
            self.description,
            witness=self.witness,
            protected_paths=self.protected_paths,
            required_capabilities=frozenset({"broker:spawn-bound", "seccomp:minimal"}),
        )

    def validate(
        self,
        operation: str,
        arguments: Mapping[str, Any],
        context: ResourceInvocation,
    ) -> None:
        del operation
        if context.principal_id != "alice" or any(type(key) is not str for key in arguments):
            raise PermissionError("resource invocation identity or arguments rejected")


class ReadOnlySQLBackend(SQLDatabaseAPI):
    def __init__(self, database: Path) -> None:
        self.database = database.resolve()

    def connect(self):
        return sqlite3.connect(f"file:{self.database}?mode=ro", uri=True)

    def list_tables(self) -> str:
        with self.connect() as connection:
            rows = connection.execute(
                "SELECT name FROM sqlite_master WHERE type='table' ORDER BY name"
            ).fetchall()
        return ", ".join(row[0] for row in rows)

    def schema(self, table_names: str) -> str:
        requested = [name.strip() for name in table_names.split(",") if name.strip()]
        with self.connect() as connection:
            available = {
                row[0]
                for row in connection.execute("SELECT name FROM sqlite_master WHERE type='table'")
            }
            if not requested:
                requested = sorted(available)
            if any(name not in available for name in requested):
                raise ValueError("unknown table")
            parts = []
            for name in requested:
                quoted = name.replace('"', '""')
                definition = connection.execute(
                    "SELECT sql FROM sqlite_master WHERE type='table' AND name = ?",
                    (name,),
                ).fetchone()[0]
                samples = connection.execute(f'SELECT * FROM "{quoted}" LIMIT 3').fetchall()
                parts.append(f"{definition}\nSample rows: {samples}")
        return "\n\n".join(parts)

    def query(self, query: str) -> str:
        normalized = re.sub(r"\s+", " ", query.strip()).lower()
        if not normalized.startswith(("select ", "with ")) or ";" in normalized.rstrip(";"):
            raise PermissionError("only one read-only SELECT statement is permitted")
        if re.search(
            r"\b(insert|update|delete|drop|alter|attach|detach|pragma|vacuum)\b", normalized
        ):
            raise PermissionError("SQL mutation or database control is forbidden")
        with self.connect() as connection:
            cursor = connection.execute(query)
            rows = cursor.fetchall()
        return str(rows)


class TFIDFRetrieverBackend(RetrieverAPI):
    def __init__(self, documents: list[str], limit: int = 5) -> None:
        self.documents = tuple(documents)
        self.limit = limit
        self.vectorizer = TfidfVectorizer(stop_words="english").fit(self.documents)
        self.matrix = self.vectorizer.transform(self.documents)

    def search(self, query: str) -> str:
        scores = (self.matrix @ self.vectorizer.transform([query]).T).toarray().ravel()
        indices = scores.argsort()[-self.limit :][::-1]
        return "\n\n".join(self.documents[index] for index in indices)


class FrozenSearchBackend(SearchAPI):
    def __init__(self, corpus: list[dict], limit: int = 3) -> None:
        self.corpus = tuple(dict(item) for item in corpus)
        self.limit = limit
        texts = [f"{item.get('title', '')} {item['content']}" for item in self.corpus]
        self.vectorizer = TfidfVectorizer(stop_words="english").fit(texts)
        self.matrix = self.vectorizer.transform(texts)

    def search(self, query: str) -> str:
        scores = (self.matrix @ self.vectorizer.transform([query]).T).toarray().ravel()
        indices = scores.argsort()[-self.limit :][::-1]
        return json.dumps(
            [
                {"url": self.corpus[index]["url"], "content": self.corpus[index]["content"]}
                for index in indices
            ]
        )


class EmptySearchBackend(SearchAPI):
    """Preserve the tutorial harness's intentionally empty frozen web search."""

    def search(self, query: str) -> str:
        del query
        return "[]"


class PersistentPythonBackend(PythonSessionAPI):
    """Own one persistent interpreter confined before any generated code runs."""

    def __init__(
        self,
        artifact: Path,
        observer: Path,
        *,
        runtime_roots: tuple[Path, ...],
    ) -> None:
        self.artifact = artifact.resolve()
        self.observer = observer.resolve()
        self.artifact.parent.mkdir(parents=True, exist_ok=True)
        system_roots = (Path("/usr/lib"), Path("/usr/share/fonts"), Path("/etc/fonts"))
        roots = tuple(
            dict.fromkeys(
                path.resolve() for path in (*runtime_roots, *system_roots) if path.exists()
            )
        )
        rules = []
        for index, root in enumerate(roots):
            rules.append(GrantRule(f"runtime-{index}", AuthorityDomain.RUNTIME, "read", str(root)))
        for operation in ("read", "write", "create", "truncate"):
            rules.append(
                GrantRule(
                    f"artifact-{operation}",
                    AuthorityDomain.FILESYSTEM,
                    operation,
                    str(self.artifact.parent),
                )
            )
        if Path("/dev/urandom").exists():
            rules.append(
                GrantRule(
                    "runtime-urandom",
                    AuthorityDomain.RUNTIME,
                    "read",
                    "/dev/urandom",
                )
            )
        ruleset = build_ruleset(rules)
        server = Path(__file__).with_name("python_session_server.py")
        command = [
            sys.executable,
            "-I",
            "-S",
            "-B",
            "-u",
            str(server),
            "--artifact",
            str(self.artifact),
            "--ruleset-fd",
            str(ruleset.fd),
        ]
        for root in roots:
            command.extend(("--runtime-root", str(root)))
        environment = {
            "HOME": str(self.artifact.parent),
            "MPLCONFIGDIR": str(self.artifact.parent),
            "PATH": "/usr/bin",
            "PYTHONDONTWRITEBYTECODE": "1",
            "PYTHONNOUSERSITE": "1",
            "PYTHONUNBUFFERED": "1",
        }
        self.process = subprocess.Popen(
            command,
            stdin=subprocess.PIPE,
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
            text=True,
            cwd=self.artifact.parent,
            env=environment,
            pass_fds=(ruleset.fd,),
        )
        ruleset.close()
        self.lock = threading.Lock()
        ready = self._readline(20)
        if ready != {"status": "ready"}:
            self.close()
            raise RuntimeError(f"python session failed to activate: {ready!r}")

    def _readline(self, timeout: float) -> dict:
        if self.process.stdout is None:
            raise RuntimeError("python session stdout is unavailable")
        ready, _, _ = select.select([self.process.stdout], [], [], timeout)
        if not ready:
            raise TimeoutError("python session timed out")
        line = self.process.stdout.readline()
        if not line:
            details = self.process.stderr.read() if self.process.stderr else ""
            raise RuntimeError(f"python session stopped: {details}")
        value = json.loads(line)
        if type(value) is not dict:
            raise TypeError("python session response must be an object")
        return value

    def execute(self, code: str) -> str:
        if type(code) is not str or len(code.encode()) > 100_000:
            raise ValueError("python session code exceeds the accepted input boundary")
        with self.lock:
            if self.process.stdin is None:
                raise RuntimeError("python session stdin is unavailable")
            self.process.stdin.write(json.dumps({"code": code}) + "\n")
            self.process.stdin.flush()
            result = self._readline(30)
            if result.get("lines"):
                self.observer.write_text(json.dumps({"lines": result["lines"]}, indent=2) + "\n")
            return json.dumps(result)

    def close(self) -> None:
        process = getattr(self, "process", None)
        if process is None or process.poll() is not None:
            return
        if process.stdin is not None:
            process.stdin.close()
        try:
            process.wait(timeout=2)
        except subprocess.TimeoutExpired:
            process.kill()
            process.wait(timeout=2)

    def __del__(self) -> None:
        self.close()


class TravelSQLiteBackend(TravelAPI):
    def __init__(self, database: Path, passenger_id: str, frozen_now: datetime) -> None:
        self.database = database.resolve()
        self.passenger_id = passenger_id
        self.frozen_now = frozen_now

    def resolve_passenger(self, logical_principal: str) -> str:
        if logical_principal != "alice":
            raise PermissionError("travel resource principal is not authorized")
        return self.passenger_id

    def connect(self):
        return sqlite3.connect(self.database)

    def fetch_user(self, passenger_id: str) -> str:
        passenger_id = self.resolve_passenger(passenger_id)
        query = """
        SELECT t.ticket_no, t.book_ref, f.flight_id, f.flight_no,
               f.departure_airport, f.arrival_airport, f.scheduled_departure,
               f.scheduled_arrival, bp.seat_no, tf.fare_conditions
        FROM tickets t JOIN ticket_flights tf ON t.ticket_no = tf.ticket_no
        JOIN flights f ON tf.flight_id = f.flight_id
        JOIN boarding_passes bp ON bp.ticket_no = t.ticket_no AND bp.flight_id = f.flight_id
        WHERE t.passenger_id = ?
        """
        with self.connect() as connection:
            cursor = connection.execute(query, (passenger_id,))
            names = [item[0] for item in cursor.description]
            rows = [dict(zip(names, row, strict=True)) for row in cursor.fetchall()]
        return json.dumps(rows, default=str)

    def search_flights(self, criteria_json: str) -> str:
        criteria = json.loads(criteria_json)
        if type(criteria) is not dict:
            raise TypeError("flight criteria must be an object")
        query = "SELECT * FROM flights WHERE 1 = 1"
        parameters = []
        for field in ("departure_airport", "arrival_airport"):
            if criteria.get(field):
                query += f" AND {field} = ?"
                parameters.append(criteria[field])
        if criteria.get("start_time"):
            query += " AND scheduled_departure >= ?"
            parameters.append(criteria["start_time"])
        if criteria.get("end_time"):
            query += " AND scheduled_departure <= ?"
            parameters.append(criteria["end_time"])
        query += " LIMIT ?"
        parameters.append(min(int(criteria.get("limit", 20)), 100))
        with self.connect() as connection:
            cursor = connection.execute(query, parameters)
            names = [item[0] for item in cursor.description]
            rows = [dict(zip(names, row, strict=True)) for row in cursor.fetchall()]
        return json.dumps(rows, default=str)

    def update_ticket(self, ticket_no: str, new_flight_id: int, passenger_id: str) -> str:
        passenger_id = self.resolve_passenger(passenger_id)
        with self.connect() as connection:
            owner = connection.execute(
                "SELECT 1 FROM tickets WHERE ticket_no = ? AND passenger_id = ?",
                (ticket_no, passenger_id),
            ).fetchone()
            flight = connection.execute(
                "SELECT scheduled_departure FROM flights WHERE flight_id = ?",
                (new_flight_id,),
            ).fetchone()
            if owner is None:
                return "Current signed-in passenger does not own this ticket."
            if flight is None:
                return "Invalid new flight ID provided."
            departure = datetime.fromisoformat(flight[0])
            frozen = self.frozen_now
            if departure.tzinfo is None and frozen.tzinfo is not None:
                departure = departure.replace(tzinfo=frozen.tzinfo)
            if (departure - frozen).total_seconds() < 3 * 3600:
                return "Not permitted to reschedule to a flight less than 3 hours away."
            current = connection.execute(
                "SELECT 1 FROM ticket_flights WHERE ticket_no = ?", (ticket_no,)
            ).fetchone()
            if current is None:
                return "No existing ticket found for the given ticket number."
            connection.execute(
                "UPDATE ticket_flights SET flight_id = ? WHERE ticket_no = ?",
                (new_flight_id, ticket_no),
            )
        return "Ticket successfully updated to new flight."

    def cancel_ticket(self, ticket_no: str, passenger_id: str) -> str:
        passenger_id = self.resolve_passenger(passenger_id)
        with self.connect() as connection:
            existing = connection.execute(
                "SELECT 1 FROM ticket_flights WHERE ticket_no = ?", (ticket_no,)
            ).fetchone()
            if existing is None:
                return "No existing ticket found for the given ticket number."
            owner = connection.execute(
                "SELECT 1 FROM tickets WHERE ticket_no = ? AND passenger_id = ?",
                (ticket_no, passenger_id),
            ).fetchone()
            if owner is None:
                return "Current signed-in passenger does not own this ticket."
            connection.execute("DELETE FROM ticket_flights WHERE ticket_no = ?", (ticket_no,))
        return "Ticket successfully cancelled."
