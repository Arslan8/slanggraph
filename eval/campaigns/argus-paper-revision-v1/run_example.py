"""Run the Alice/Bob trace through closed admission and the complete Linux route."""

from __future__ import annotations

import argparse
import ast
import dataclasses
import enum
import hashlib
import json
import sqlite3
import sys
import tempfile
from dataclasses import replace
from pathlib import Path

from langchain_core.messages import AIMessage
from langchain_core.tools import tool
from langgraph.graph import END, START, MessagesState, StateGraph
from langgraph.prebuilt import ToolNode
from langgraph.prebuilt.security import (
    SQLITE_RECORD_SCHEMA,
    LinuxToolSpec,
    MemoryAuditSink,
    ObjectBrokerDispatcher,
    Principal,
    cedar_security,
    install_mac_policy,
    sqlite_record_mediator,
    with_principal,
)
from langgraph.prebuilt.security.admission import describe
from langgraph.prebuilt.security.lean_lifecycle import LeanLifecycleChecker
from langgraph.prebuilt.security.mediators.records import RECORDS
from langgraph.prebuilt.security.types import Tool, ToolCall, ToolDac

ROOT = Path(__file__).resolve().parents[3]
WORKER = Path(__file__).with_name("worker.py")
ALICE = "ALICE_ALLOWED_VALUE"
BOB = "BOB_SECRET_ARGUS_REVISION_CANARY"
CALLER_POLICY = """permit(
    principal == slangGraph::User::\"alice\",
    action == slangGraph::Action::\"db_record::read\",
    resource
) when { resource.selector == \"notes/alice\" };"""
OPERATOR_POLICY = """forbid(
    principal == slangGraph::User::\"blocked\",
    action,
    resource
);"""
MANIFEST = """runs linux
db_record read notes/alice need
returns normal"""


@tool
def read_record(record: str, operation: str, database: str, direct: bool = False) -> dict:
    """Read one record through the Argus resource boundary."""
    raise AssertionError("the coordinator-side schema body must never execute")


def serial(value):
    if dataclasses.is_dataclass(value):
        return {
            field.name: serial(getattr(value, field.name)) for field in dataclasses.fields(value)
        }
    if isinstance(value, enum.Enum):
        return value.value
    if isinstance(value, dict):
        return {str(key): serial(item) for key, item in value.items()}
    if isinstance(value, tuple | list | set | frozenset):
        return [serial(item) for item in value]
    if value is None or isinstance(value, str | bool | int | float):
        return value
    return str(value)


def database_state(path: Path) -> dict[str, str]:
    with sqlite3.connect(path) as connection:
        return dict(connection.execute("SELECT key, value FROM records ORDER BY key"))


def invoke(graph, security, args: dict, call_id: str):
    request = {
        "messages": [
            AIMessage(
                content="",
                tool_calls=[
                    {"name": "read_record", "args": args, "id": call_id, "type": "tool_call"}
                ],
            )
        ]
    }
    principal = Principal("alice", frozenset(), frozenset(), "revision-session")
    config = with_principal(
        {},
        principal,
        modules=security.modules,
    )
    security.host_executor.prewarm(
        principal,
        ToolCall(
            Tool("read_record", ToolDac("owner", {}), frozenset(), ()),
            args,
            {},
            call_id,
            0,
        ),
        (),
        count=1,
    )
    result = graph.invoke(request, config)
    message = result["messages"][-1]
    try:
        return json.loads(message.content)
    except json.JSONDecodeError:
        try:
            return ast.literal_eval(message.content)
        except (SyntaxError, ValueError):
            return {"security_denial": message.content}


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--checker-library", type=Path, required=True)
    parser.add_argument("--checker-runtime", type=Path, required=True)
    parser.add_argument("--output", type=Path, required=True)
    args = parser.parse_args()
    checker_path = args.checker_library.resolve(strict=True)
    runtime_path = args.checker_runtime.resolve(strict=True)
    checker = LeanLifecycleChecker(
        str(checker_path),
        hashlib.sha256(checker_path.read_bytes()).hexdigest(),
        str(runtime_path),
        hashlib.sha256(runtime_path.read_bytes()).hexdigest(),
    )
    checker.require_inline()
    args.output.mkdir(parents=True, exist_ok=False)
    install_mac_policy(OPERATOR_POLICY)
    with tempfile.TemporaryDirectory(prefix="argus-revision-example-") as directory:
        database = Path(directory) / "records.sqlite"
        with sqlite3.connect(database) as connection:
            connection.execute(SQLITE_RECORD_SCHEMA)
            connection.executemany(
                "INSERT INTO records VALUES (?, ?)",
                [("alice", ALICE), ("bob", BOB)],
            )
        mediator = sqlite_record_mediator(database, database_id="notes")
        dispatcher = ObjectBrokerDispatcher(
            {
                "read_record": LinuxToolSpec(
                    "worker:run",
                    WORKER,
                    hashlib.sha256(WORKER.read_bytes()).hexdigest(),
                )
            },
            runtime_roots=tuple(
                Path(item).resolve() for item in sys.path if item and Path(item).is_dir()
            ),
            mediators=(mediator,),
            lifecycle_checker=checker,
            worker_pool_capacity=1,
        )
        audit = MemoryAuditSink()
        security = replace(
            cedar_security(
                read_record,
                manifest=MANIFEST,
                classes=RECORDS.class_declaration(enforced_by="broker"),
                policy=CALLER_POLICY,
                dispatcher=dispatcher,
            ),
            closed_admission=True,
            audit_sink=audit,
        )
        builder = StateGraph(MessagesState)
        builder.add_node("tools", ToolNode([read_record], security=security))
        builder.add_edge(START, "tools")
        builder.add_edge("tools", END)
        graph = builder.compile(security=security)
        admission = [describe(item) for item in graph.builder._security_admission]
        before = database_state(database)
        common = {"database": str(database)}
        allowed = invoke(
            graph,
            security,
            {**common, "record": "notes/alice", "operation": "read"},
            "allowed-read",
        )
        denied_bob = invoke(
            graph,
            security,
            {**common, "record": "notes/bob", "operation": "read"},
            "denied-bob",
        )
        denied_write = invoke(
            graph,
            security,
            {**common, "record": "notes/alice", "operation": "write"},
            "denied-write",
        )
        denied_direct = invoke(
            graph,
            security,
            {
                **common,
                "record": "notes/alice",
                "operation": "read",
                "direct": True,
            },
            "denied-direct",
        )
        after = database_state(database)
        evidence = {
            "schema": 1,
            "configuration": "linux-complete-object-broker-lean-v1",
            "manifest": MANIFEST,
            "caller_policy": CALLER_POLICY,
            "operator_policy": OPERATOR_POLICY,
            "checker": {
                "path": str(checker_path),
                "sha256": checker.binary_sha256,
                "runtime_path": str(runtime_path),
                "runtime_sha256": checker.runtime_sha256,
                "inline": checker.inline,
            },
            "admission": admission,
            "authorization_grants": serial(security.host_executor.authorization_grants()),
            "lowering": serial(dispatcher.lowering_records()),
            "activation": serial(dispatcher.activation_receipts()),
            "broker_audit": serial(dispatcher.audit_records()),
            "security_audit": serial(audit.records()),
            "resource_before": before,
            "resource_after": after,
            "outcomes": {
                "allowed_read": allowed,
                "denied_bob_read": denied_bob,
                "denied_write": denied_write,
                "denied_direct_database": denied_direct,
            },
        }
        evidence["assertions"] = {
            "alice_read_correct": ALICE in json.dumps(allowed),
            "bob_not_disclosed": BOB not in json.dumps(evidence["outcomes"]),
            "writes_absent": before == after,
            "direct_access_blocked": "direct_blocked" in denied_direct,
            "closed_admission_recorded": bool(admission),
            "authorization_recorded": len(evidence["authorization_grants"]) == 8,
            "lowering_recorded": len(evidence["lowering"]) == 4,
            "activation_recorded": len(evidence["activation"]) == 4,
            "lean_grant_and_lifecycle_checked": checker.statistics()["inline_calls"] >= 12,
            "inline_checker_only": checker.statistics()["subprocess_calls"] == 0,
            "prepared_worker_hits": dispatcher.worker_pool_stats()["hits"] == 4,
            "no_online_policy_relowering": dispatcher.worker_pool_stats()["policy_lowerings"] == 1,
        }
        evidence["complete"] = all(evidence["assertions"].values())
        (args.output / "invocation.json").write_text(json.dumps(evidence, indent=2) + "\n")
        dispatcher.close()
    print(json.dumps({"complete": evidence["complete"], "output": str(args.output)}))
    return 0 if evidence["complete"] else 1


if __name__ == "__main__":
    raise SystemExit(main())
