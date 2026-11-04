# ruff: noqa: E501
# Preserve embedded worker source and Cedar policy literals verbatim.
"""SQLite component ablations with fixed Cedar policy and resource-side snapshots."""

import argparse
import hashlib
import json
import platform
import sqlite3
import subprocess
import sys
import tempfile
import time
import uuid
from dataclasses import replace
from pathlib import Path

from langchain_core.tools import tool
from langgraph.prebuilt.security import (
    SQLITE_RECORD_SCHEMA,
    LeanLifecycleChecker,
    LinuxToolSpec,
    ObjectBrokerDispatcher,
    Principal,
    SqliteAuditSink,
    Tool,
    ToolCall,
    ToolDac,
    cedar_security,
    sqlite_record_mediator,
)
from langgraph.prebuilt.security.mediators.records import RECORDS

ROOT = Path(__file__).resolve().parents[2]
sys.path.insert(0, str(ROOT / "eval/scripts"))
from mechanism_evidence_plugin import serial  # noqa: E402

MANIFEST = """runs linux
map operation=read db_record read @{record} need
map operation=write db_record write @{record} need
map operation=delete db_record delete @{record} need
returns sensitive"""
POLICY = """permit(principal == slangGraph::User::"alice", action in [slangGraph::Action::"db_record::read", slangGraph::Action::"db_record::write", slangGraph::Action::"db_record::delete"], resource)
when { resource.selector == "notes/alice" };"""
MODES = [
    "call_authorization_native",
    "filesystem_accessible",
    "incomplete_broker_reference",
    "production_composition",
]
CASES = [
    ("allowed_read", "notes/alice", "read", "none"),
    ("allowed_write", "notes/alice", "write", "none"),
    ("allowed_delete", "notes/alice", "delete", "none"),
    ("denied_read", "notes/bob", "read", "none"),
    ("denied_write", "notes/bob", "write", "none"),
    ("denied_delete", "notes/bob", "delete", "none"),
    ("selector_substitution", "notes/alice", "read", "substitute"),
    ("omitted_write", "notes/alice", "read", "omitted_write"),
    ("omitted_delete", "notes/alice", "read", "omitted_delete"),
    ("direct_database", "notes/alice", "read", "direct"),
    ("direct_wal", "notes/alice", "read", "direct-wal"),
    ("direct_shm", "notes/alice", "read", "direct-shm"),
    ("retry_broker_then_direct", "notes/alice", "read", "retry"),
    ("rpc_spoof", "notes/alice", "read", "spoof"),
]


@tool("record_task")
def record_task(
    record: str, operation: str, attack: str, database: str, value: str = "updated"
) -> dict:
    """Operate on a declared record in the confined worker."""
    raise RuntimeError("no unconfined fallback")


def state(database):
    with sqlite3.connect(database) as conn:
        return dict(conn.execute("SELECT key,value FROM records ORDER BY key"))


def run(output, repetitions, checker):
    output.mkdir(parents=True, exist_ok=False)
    source = Path(__file__).with_name("record_worker.py")
    code = source.read_text()
    for name, text in [("manifest.slp", MANIFEST), ("policy.cedar", POLICY), ("worker.py", code)]:
        (output / name).write_text(text)
    source_hash = hashlib.sha256(code.encode()).hexdigest()
    (output / "plan.json").write_text(
        json.dumps(
            dict(
                cases=CASES,
                modes=MODES,
                repetitions=repetitions,
                worker_sha256=source_hash,
                route=(
                    "ObjectPolicyHostExecutor/ObjectBrokerDispatcher/"
                    "prepared Landlock worker/inline Lean lifecycle/SQLite records"
                    if checker is not None
                    else "legacy mixed-route composition"
                ),
                safety="Incomplete modes are explicit reference harnesses outside secure mode",
            ),
            indent=2,
        )
    )
    with (output / "trials.jsonl").open("w") as stream:
        for repetition in range(repetitions):
            for mode in MODES:
                for case_id, record, operation, attack in CASES:
                    with tempfile.TemporaryDirectory(prefix="slg-composition-") as folder:
                        database = Path(folder) / "records.sqlite"
                        keeper = sqlite3.connect(database)
                        keeper.execute("PRAGMA journal_mode=WAL")
                        keeper.execute(SQLITE_RECORD_SCHEMA)
                        canary = "BOB_" + uuid.uuid4().hex
                        keeper.executemany(
                            "INSERT INTO records VALUES (?,?)",
                            [("alice", "allowed"), ("bob", canary)],
                        )
                        keeper.commit()
                        mediator = sqlite_record_mediator(database, database_id="notes")
                        dispatcher = ObjectBrokerDispatcher(
                            {
                                "record_task": LinuxToolSpec(
                                    "record_worker:run", source, source_hash
                                )
                            },
                            runtime_roots=tuple(
                                Path(p).resolve() for p in sys.path if p and Path(p).is_dir()
                            ),
                            mediators=(mediator,),
                            lifecycle_checker=checker,
                            worker_pool_capacity=1 if checker is not None else 0,
                        )
                        security = cedar_security(
                            record_task,
                            manifest=MANIFEST,
                            classes=RECORDS.class_declaration(),
                            policy=POLICY,
                            dispatcher=dispatcher,
                        )
                        audit_sink = None
                        if checker is not None:
                            audit_sink = SqliteAuditSink(Path(folder) / "security.sqlite")
                            security = replace(security, audit_sink=audit_sink)
                        executor = security.host_executor
                        args = dict(
                            record=record,
                            operation=operation,
                            attack=attack,
                            database=str(database),
                        )
                        principal = Principal(
                            "alice", frozenset(), frozenset(), f"session-{repetition}"
                        )
                        call = ToolCall(
                            Tool("record_task", ToolDac("owner", {"*": "x"}), frozenset(), ()),
                            args,
                            {},
                            uuid.uuid4().hex,
                            0,
                        )
                        before = state(database)
                        start = time.perf_counter()
                        result = None
                        error = None
                        grant = None
                        receipt = None
                        phase = "authorization"
                        try:
                            if mode == "production_composition":
                                if checker is not None:
                                    prepared_grant = executor._authorize(principal, call, ())
                                    dispatcher.prewarm(principal, call, prepared_grant)
                                value = executor.invoke(principal, call, ())
                                result = value.value
                                receipt = serial(value.receipt)
                            else:
                                # Same installed policy; reference modes deliberately retain native access.
                                grant = executor._authorize(principal, call, ())
                                phase = "execution"
                                if attack == "spoof":
                                    result = {
                                        "unsupported": "reference modes have no RPC identity protocol"
                                    }
                                else:
                                    actual = (
                                        attack.removeprefix("omitted_")
                                        if attack.startswith("omitted_")
                                        else operation
                                    )
                                    selector = (
                                        "notes/bob" if attack in {"substitute", "retry"} else record
                                    )
                                    if (
                                        mode == "incomplete_broker_reference"
                                        and not attack.startswith("direct")
                                        and attack != "retry"
                                    ):
                                        matched = [
                                            line
                                            for line in grant.lines
                                            if line.selector == selector
                                            and line.operation == actual
                                        ]
                                        if not matched:
                                            result = {
                                                "denied": "exact operation/selector absent from grant"
                                            }
                                        else:
                                            result = mediator.invoke(
                                                matched[0],
                                                {"value": "updated"} if actual == "write" else {},
                                                None,
                                            )
                                    else:
                                        native = """import sqlite3
from pathlib import Path
if p['attack'].startswith('direct') and p['attack'] != 'direct':
    raw=Path(p['database']+p['attack'].removeprefix('direct')).read_bytes()
    result={'bytes_read':len(raw), 'raw_hex':raw.hex()}
else:
    with sqlite3.connect(p['database']) as conn:
        key='bob' if p['attack'] in {'direct','retry'} else p['selector'].split('/')[1]
        if p['actual']=='read':
            result={'found':True,'value':conn.execute('SELECT value FROM records WHERE key=?',(key,)).fetchone()[0]}
        elif p['actual']=='write':
            conn.execute('UPDATE records SET value=? WHERE key=?',('updated',key))
            result={'ok':True}
        else:
            conn.execute('DELETE FROM records WHERE key=?',(key,))
            result={'ok':True}
"""
                                        parameters = dict(
                                            database=str(database),
                                            attack=attack,
                                            selector=selector,
                                            actual=actual,
                                        )
                                        if mode == "filesystem_accessible":
                                            from slanggraph_eval.isolation.alternatives import (
                                                runtime_reads,
                                            )

                                            completed = subprocess.run(
                                                [
                                                    sys.executable,
                                                    str(
                                                        Path(__file__).with_name(
                                                            "filesystem_worker.py"
                                                        )
                                                    ),
                                                ],
                                                input=json.dumps(
                                                    dict(
                                                        source=native,
                                                        parameters=parameters,
                                                        readable=[
                                                            *runtime_reads(),
                                                            sys.base_prefix,
                                                        ],
                                                        writable=[str(database.parent)],
                                                    )
                                                ),
                                                capture_output=True,
                                                text=True,
                                                timeout=10,
                                                check=True,
                                            )
                                            response = json.loads(completed.stdout)
                                            result = response.get("value", {"error": response})
                                        else:
                                            namespace = {"p": parameters}
                                            exec(native, namespace)
                                            result = namespace["result"]
                            phase = "completed"
                        except Exception as exc:
                            error = {"type": type(exc).__name__, "message": str(exc)}
                        elapsed = (time.perf_counter() - start) * 1000
                        grants = executor.authorization_grants()
                        if grants:
                            grant = grants[-1]
                        after = state(database)
                        disclosure = canary in json.dumps(
                            result
                        ) or canary.encode().hex() in json.dumps(result)
                        forbidden = (
                            disclosure
                            or after.get("bob") != before["bob"]
                            or (attack.startswith("omitted_") and after != before)
                        )
                        legitimate = (
                            (
                                case_id == "allowed_read"
                                and result == {"found": True, "value": "allowed"}
                            )
                            or (case_id == "allowed_write" and after.get("alice") == "updated")
                            or (case_id == "allowed_delete" and "alice" not in after)
                        )
                        row = dict(
                            case_id=case_id,
                            session=repetition,
                            repeat=repetition,
                            mode=mode,
                            concrete_executor="ObjectPolicyHostExecutor/ObjectBrokerDispatcher"
                            if mode == "production_composition"
                            else mode,
                            isolation_route=(
                                "host isolation: prepared Landlock worker with a "
                                "spawn-bound SQLite broker and inline Lean lifecycle checks"
                                if mode == "production_composition" and checker is not None
                                else "reference route"
                            ),
                            source_revision=source_hash,
                            host=platform.node(),
                            principal=serial(principal),
                            policy_identity=hashlib.sha256(POLICY.encode()).hexdigest(),
                            manifest_identity=hashlib.sha256(MANIFEST.encode()).hexdigest(),
                            grant_identity=grant.digest if grant else "not-applicable",
                            grant=serial(grant),
                            attempted_operation=args,
                            authorization="granted" if grant else "denied",
                            lowering=serial(dispatcher.lowering_records()),
                            activation=receipt or "not-applicable",
                            effect_trace=serial(dispatcher.audit_records()),
                            resource_before=before,
                            resource_after=after,
                            observed_effect=forbidden,
                            legitimate_result=bool(legitimate),
                            result=result,
                            error=error,
                            last_phase=phase,
                            elapsed_ms=elapsed,
                            classification="unsupported"
                            if result and "unsupported" in result
                            else "observed_effect"
                            if forbidden
                            else "completed"
                            if not error
                            else "refused",
                        )
                        stream.write(json.dumps(row, sort_keys=True) + "\n")
                        stream.flush()
                        dispatcher.close()
                        if audit_sink is not None:
                            audit_sink.close()
                        keeper.close()
            print(f"SQLite repetition {repetition} complete", flush=True)


if __name__ == "__main__":
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--output", type=Path, required=True)
    parser.add_argument("--repetitions", type=int, default=20)
    parser.add_argument("--checker-library", type=Path)
    parser.add_argument("--checker-runtime", type=Path)
    args = parser.parse_args()
    if (args.checker_library is None) != (args.checker_runtime is None):
        parser.error("select both --checker-library and --checker-runtime")
    checker = None
    if args.checker_library is not None:
        library = args.checker_library.resolve(strict=True)
        runtime = args.checker_runtime.resolve(strict=True)
        checker = LeanLifecycleChecker(
            str(library),
            hashlib.sha256(library.read_bytes()).hexdigest(),
            str(runtime),
            hashlib.sha256(runtime.read_bytes()).hexdigest(),
        )
    run(args.output, args.repetitions, checker)
