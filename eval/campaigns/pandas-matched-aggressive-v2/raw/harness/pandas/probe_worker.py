"""Probe a proposed boundary adaptation; never count this as an application run."""

import hashlib
import json
import os
import sys
from pathlib import Path

from langchain_core.messages import AIMessage
from langchain_core.tools import tool
from langgraph.graph import START, MessagesState, StateGraph
from langgraph.prebuilt import ToolNode
from langgraph.prebuilt.security import (
    DacOverrides,
    Effect,
    LinuxSandboxExecutor,
    LinuxToolSpec,
    MemoryAuditSink,
    Principal,
    ResourceArg,
    SecurityConfig,
    dac,
    effects,
    parse_profiles,
    with_principal,
)


def main():
    output = Path(sys.argv[1]).resolve()
    output.mkdir(parents=True, exist_ok=False)
    upstream = Path("/data/slanggraph-eval-upstreams/ai-data-science-team")
    packages = upstream / ".venv/lib/python3.13/site-packages"
    source = packages / "ai_data_science_team/utils/sandbox.py"
    artifact = Path(__file__).with_name("worker_candidate.py").resolve()
    profile = f"""
tool compute {{
  owner analyst
  grant analyst: call
  runs linux
  syscalls @minimal
  fs read ${{sandbox_source}} need
}}
principal alice {{
  roles analyst
  fs read {packages}/**
}}
"""
    plan = {
        "kind": "integration feasibility only",
        "profile": profile,
        "artifact_sha256": hashlib.sha256(artifact.read_bytes()).hexdigest(),
        "sandbox_sha256": hashlib.sha256(source.read_bytes()).hexdigest(),
        "model": None,
        "boundary_change": "Replace outer upstream subprocess with fresh worker",
    }
    (output / "plan.json").write_text(json.dumps(plan, indent=2) + "\n")
    os.sched_setaffinity(0, {min(os.sched_getaffinity(0))})
    audit = MemoryAuditSink()
    try:
        profiles = parse_profiles(profile, source="candidate.slp")
        executor = LinuxSandboxExecutor(
            profiles,
            {
                "compute": LinuxToolSpec(
                    "worker_candidate:compute", artifact, plan["artifact_sha256"]
                )
            },
            runtime_roots=(artifact.parent, packages),
            python_executable=upstream / ".venv/bin/python",
        )
        security = SecurityConfig(
            dac_overrides=DacOverrides(profiles=profiles.tools),
            host_executor=executor,
            audit_sink=audit,
        )

        @tool
        @dac(owner="analyst", grants={"analyst": "x", "*": "-"})
        @effects(
            Effect.EXEC, Effect.READ, resources=[ResourceArg("sandbox_source", "path", "realpath")]
        )
        def compute(sandbox_source: str, code: str, data: dict) -> dict:
            """Execute a generated table computation in the isolated worker."""
            raise RuntimeError("In-process fallback is forbidden")

        builder = StateGraph(MessagesState)
        builder.add_node("compute", ToolNode([compute], security=security))
        builder.add_edge(START, "compute")
        graph = builder.compile()
        principal = Principal("alice", frozenset({"analyst"}), frozenset(), "probe")
        result = graph.invoke(
            {
                "messages": [
                    AIMessage(
                        content="",
                        tool_calls=[
                            {
                                "name": "compute",
                                "args": {
                                    "sandbox_source": str(source),
                                    "code": "def evaluate(data):\n"
                                    "    return data.groupby('region').sum().reset_index()",
                                    "data": {"region": ["North", "North"], "sales": [100, 100]},
                                },
                                "id": "probe-1",
                            }
                        ],
                    )
                ]
            },
            config=with_principal({}, principal),
        )
        record = {
            "messages": [message.model_dump() for message in result["messages"]],
            "activation_receipts": [r.canonical() for r in executor.activation_receipts()],
        }
    except Exception as exc:
        record = {"error_type": type(exc).__name__, "error": str(exc)}
    record["audit"] = [str(event) for event in audit.records()]
    (output / "result.json").write_text(json.dumps(record, indent=2, default=str) + "\n")
    print(json.dumps(record, default=str)[:1800])


if __name__ == "__main__":
    main()
