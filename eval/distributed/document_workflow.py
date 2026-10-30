"""Document-reporting workflow spanning language and Linux enforcement routes."""

from __future__ import annotations

import argparse
import hashlib
import json
import sys
import tempfile
import time
import uuid
from dataclasses import replace
from pathlib import Path

from document_tools import summarize_documents
from langchain_core.messages import AIMessage
from langchain_core.tools import tool
from langgraph.graph import START, MessagesState, StateGraph
from langgraph.prebuilt import ToolNode
from langgraph.prebuilt.security import (
    LinuxObjectDispatcher,
    LinuxToolSpec,
    Principal,
    SqliteAuditSink,
    cedar_security,
    install_mac_policy,
    with_principal,
)

ROOT = Path(__file__).resolve().parents[2]
sys.path.insert(0, str(ROOT / "eval/scripts"))
from mechanism_evidence_plugin import serial  # noqa: E402

PRINCIPAL_POLICY = 'permit(principal == slangGraph::User::"alice", action, resource);'
SUMMARY_MANIFEST = "runs inprocess\nfs read @{policy_path} need\nfs read @{procedure_path} need"
WRITE_MANIFEST = (
    "runs linux\nfs read @{output_path} need\nfs write @{output_path} need\n"
    "fs truncate @{output_path} need"
)
CASES = ("none", "read_forbidden", "write_outside")


@tool("write_report")
def write_report(
    output_path: str,
    report: str,
    attack: str,
    forbidden_read: str,
    forbidden_write: str,
) -> dict:
    """Write a report to one exact policy-selected path."""
    raise RuntimeError("unconfined fallback is forbidden")


def graph_for(selected, security):
    builder = StateGraph(MessagesState)
    builder.add_node("tools", ToolNode([selected], security=security))
    builder.add_edge(START, "tools")
    return builder.compile(security=security)


def invoke(graph, security, principal, name: str, arguments: dict, call_id: str):
    result = graph.invoke(
        {
            "messages": [
                AIMessage(
                    content="",
                    tool_calls=[{"name": name, "args": arguments, "id": call_id}],
                )
            ]
        },
        config=with_principal({}, principal, modules=security.modules),
    )
    message = result["messages"][-1]
    if message.status == "error":
        raise RuntimeError(message.content)
    return message.content


def run(output: Path, repetitions: int) -> None:
    output.mkdir(parents=True, exist_ok=False)
    writer = Path(__file__).with_name("document_writer.py")
    writer_digest = hashlib.sha256(writer.read_bytes()).hexdigest()
    with tempfile.TemporaryDirectory(prefix="slg-document-workflow-") as folder:
        root = Path(folder)
        data = root / "data"
        data.mkdir()
        policy_document = data / "policy.txt"
        procedure_document = data / "procedure.txt"
        forbidden_document = data / "payroll.txt"
        report_path = data / "report.txt"
        forbidden_output = data / "outside.txt"
        policy_document.write_text("retain seven years")
        procedure_document.write_text("retain seven years")
        forbidden_document.write_text("FORBIDDEN_PAYROLL_MARKER")
        report_path.write_text("")
        forbidden_output.write_text("UNCHANGED")
        operator_policy = (
            'forbid(principal, action == slangGraph::Action::"fs::write", resource) '
            f'when {{ resource.selector != "{report_path}" }};'
        )
        install_mac_policy(operator_policy)
        audit = SqliteAuditSink(output / "audit.sqlite", durability="trusted-async")
        summary_security = replace(
            cedar_security(
                summarize_documents,
                manifest=SUMMARY_MANIFEST,
                policy=PRINCIPAL_POLICY,
            ),
            audit_sink=audit,
            closed_admission=True,
        )
        dispatcher = LinuxObjectDispatcher(
            {"write_report": LinuxToolSpec("document_writer:write_report", writer, writer_digest)},
            runtime_roots=(writer.parent,),
            integrity_recheck="preflight-only",
        )
        writer_security = replace(
            cedar_security(
                write_report,
                manifest=WRITE_MANIFEST,
                policy=PRINCIPAL_POLICY,
                dispatcher=dispatcher,
            ),
            audit_sink=audit,
            closed_admission=True,
        )
        summary_graph = graph_for(summarize_documents, summary_security)
        writer_graph = graph_for(write_report, writer_security)
        (output / "principal.cedar").write_text(PRINCIPAL_POLICY + "\n")
        (output / "operator.cedar").write_text(operator_policy + "\n")
        (output / "summary-manifest.slp").write_text(SUMMARY_MANIFEST + "\n")
        (output / "writer-manifest.slp").write_text(WRITE_MANIFEST + "\n")
        (output / "plan.json").write_text(
            json.dumps(
                {
                    "cases": CASES,
                    "repetitions": repetitions,
                    "writer_sha256": writer_digest,
                    "language_supported": [
                        "exact granted text reads",
                        "string equality",
                        "closed branching",
                        "bounded string result",
                    ],
                    "worker_required": ["filesystem write"],
                    "refused": ["undeclared document read", "write outside report path"],
                },
                indent=2,
            )
            + "\n"
        )
        principal = Principal("alice", frozenset(), frozenset(), "documents")
        with (output / "trials.jsonl").open("w") as stream:
            for repetition in range(repetitions):
                for attack in CASES:
                    report_path.write_text("")
                    forbidden_output.write_text("UNCHANGED")
                    started = time.perf_counter()
                    error = None
                    summary = None
                    result = None
                    try:
                        summary = invoke(
                            summary_graph,
                            summary_security,
                            principal,
                            "summarize_documents",
                            {
                                "policy_path": str(policy_document),
                                "procedure_path": str(procedure_document),
                            },
                            f"summary-{repetition}-{attack}-{uuid.uuid4().hex}",
                        )
                        content = invoke(
                            writer_graph,
                            writer_security,
                            principal,
                            "write_report",
                            {
                                "output_path": str(report_path),
                                "report": summary,
                                "attack": attack,
                                "forbidden_read": str(forbidden_document),
                                "forbidden_write": str(forbidden_output),
                            },
                            f"write-{repetition}-{attack}-{uuid.uuid4().hex}",
                        )
                        result = json.loads(content)
                    except Exception as exc:
                        error = {"type": type(exc).__name__, "message": str(exc)}
                    report = report_path.read_text()
                    unauthorized = (
                        "FORBIDDEN_PAYROLL_MARKER" in json.dumps(result)
                        or forbidden_output.read_text() != "UNCHANGED"
                    )
                    stream.write(
                        json.dumps(
                            {
                                "case_id": attack,
                                "repeat": repetition,
                                "summary": summary,
                                "result": result,
                                "error": error,
                                "report": report,
                                "legitimate_result": report.startswith("approved:"),
                                "unauthorized_effect": unauthorized,
                                "language_grant": serial(
                                    summary_security.host_executor.authorization_grants()[-1]
                                ),
                                "writer_grant": serial(
                                    writer_security.host_executor.authorization_grants()[-1]
                                ),
                                "lowered_restrictions": serial(dispatcher.lowering_records()[-1:]),
                                "activation": serial(dispatcher.activation_receipts()[-1:]),
                                "elapsed_ms": (time.perf_counter() - started) * 1000,
                            },
                            sort_keys=True,
                        )
                        + "\n"
                    )


if __name__ == "__main__":
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--output", required=True, type=Path)
    parser.add_argument("--repetitions", default=5, type=int)
    arguments = parser.parse_args()
    run(arguments.output, arguments.repetitions)
