"""Admit and execute every non-placeholder tool in a frozen ACE collection."""

from __future__ import annotations

import argparse
import ast
import hashlib
import importlib.util
import json
import subprocess
import sys
import uuid
from dataclasses import replace
from pathlib import Path

from langchain_core.messages import AIMessage
from langchain_core.tools import StructuredTool
from langgraph.graph import START, MessagesState, StateGraph
from langgraph.prebuilt import ToolNode
from langgraph.prebuilt.security import (
    LinuxObjectDispatcher,
    LinuxToolSpec,
    Principal,
    cedar_security,
    parse_security_manifest,
    with_principal,
)
from langgraph.prebuilt.security.manifest_consistency import (
    check_manifest_consistency,
)

POLICY = (
    'permit(principal == slangGraph::User::"alice", '
    'action == slangGraph::Action::"call", resource);'
)
MANIFEST = "runs inprocess\nreturns normal"
ARGUMENTS = {
    "delete_gmail_message": {"message_id": "synthetic-message"},
    "empty_arg_test": {},
    "google_drive_retrieve": {"query": "synthetic query"},
    "health_companion": {
        "name": "Alice Example",
        "dob": "2000-01-01",
        "city": "Example City",
        "email": "alice@example.invalid",
        "preferred_date": "2030-01-01",
        "medical_issues": "synthetic",
    },
    "metro_hail": {"start_point": "Main Street", "end_point": "Elm Avenue"},
    "poem_generator": {},
    "quick_ride": {"start_point": "Main Street", "end_point": "Elm Avenue"},
    "travel_mate": {
        "name": "Alice Example",
        "email": "alice@example.invalid",
        "departure_city": "Origin",
        "destination_city": "Destination",
        "departure_date": "2030-01-01",
        "class_of_service": "economy",
        "special_requirements": "none",
    },
}


def _main_function(source: str) -> ast.FunctionDef | ast.AsyncFunctionDef | None:
    tree = ast.parse(source)
    entries = [
        node
        for node in tree.body
        if isinstance(node, (ast.FunctionDef, ast.AsyncFunctionDef)) and node.name == "main"
    ]
    return entries[0] if len(entries) == 1 else None


def _placeholder(source: str) -> bool:
    function = _main_function(source)
    if function is None:
        return False
    body = list(function.body)
    if (
        body
        and isinstance(body[0], ast.Expr)
        and isinstance(body[0].value, ast.Constant)
        and isinstance(body[0].value.value, str)
    ):
        body.pop(0)
    return len(body) == 1 and (
        isinstance(body[0], ast.Pass)
        or (
            isinstance(body[0], ast.Return)
            and (
                body[0].value is None
                or (isinstance(body[0].value, ast.Constant) and body[0].value.value is None)
            )
        )
    )


def _load(path: Path, name: str):
    spec = importlib.util.spec_from_file_location(f"ace_census_{name}", path)
    if spec is None or spec.loader is None:
        raise RuntimeError("source module is not loadable")
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module.main


def _execute(path: Path, name: str, *, host_isolated: bool) -> dict:
    before = hashlib.sha256(path.read_bytes()).hexdigest()
    stage = "load"
    try:
        function = _load(path, name)
        tool = StructuredTool.from_function(
            function,
            name=name,
            description=(function.__doc__ or f"Execute the frozen {name} tool."),
        )
        stage = "admission"
        dispatcher = (
            LinuxObjectDispatcher(
                {name: LinuxToolSpec(f"{name}:main", path, before)},
                runtime_roots=tuple(
                    Path(item).resolve() for item in sys.path if item and Path(item).is_dir()
                ),
                integrity_recheck="preflight-only",
            )
            if host_isolated
            else None
        )
        security = replace(
            cedar_security(
                tool,
                manifest="runs linux\nreturns normal" if host_isolated else MANIFEST,
                policy=POLICY,
                dispatcher=dispatcher,
            ),
            closed_admission=True,
        )
        node = ToolNode([tool], security=security)
        builder = StateGraph(MessagesState)
        builder.add_node("tools", node)
        builder.add_edge(START, "tools")
        graph = builder.compile(security=security)
        stage = "execution"
        principal = Principal("alice", frozenset(), frozenset(), "census")
        config = with_principal({}, principal, modules=security.modules)
        result = graph.invoke(
            {
                "messages": [
                    AIMessage(
                        content="",
                        tool_calls=[
                            {
                                "name": name,
                                "args": ARGUMENTS[name],
                                "id": uuid.uuid4().hex,
                                "type": "tool_call",
                            }
                        ],
                    )
                ]
            },
            config=config,
        )
        return {
            "admission_succeeded": True,
            "execution_attempted": True,
            "execution_succeeded": True,
            "result": str(result["messages"][-1].content),
            "error": None,
            "source_unchanged": before == hashlib.sha256(path.read_bytes()).hexdigest(),
            "route": "linux_host" if host_isolated else "language",
        }
    except Exception as exc:
        return {
            "admission_succeeded": stage == "execution",
            "execution_attempted": stage == "execution",
            "execution_succeeded": False,
            "result": None,
            "error": {
                "stage": stage,
                "type": type(exc).__name__,
                "message": str(exc),
            },
            "source_unchanged": before == hashlib.sha256(path.read_bytes()).hexdigest(),
            "route": "linux_host" if host_isolated else "language",
        }


def run(output: Path, ace_root: Path) -> None:
    output.mkdir(parents=True, exist_ok=False)
    source_root = ace_root / "benchmarks/case_studies/case_1/tools/source"
    manifest_path = ace_root / "benchmarks/case_studies/case_1/tools/manifest.json"
    manifest = json.loads(manifest_path.read_text())
    selected_names = {
        entry["path"]
        for entry in manifest
        if entry.get("enabled", True)
        and isinstance(entry.get("path"), str)
        and (source_root / f"{entry['path']}.py").exists()
    }
    revision = subprocess.check_output(
        ["git", "rev-parse", "HEAD"], cwd=ace_root, text=True
    ).strip()
    rows = []
    for path in sorted(source_root.glob("*.py")):
        name = path.stem
        if name not in selected_names:
            continue
        source = path.read_text()
        placeholder = _placeholder(source)
        static_report = check_manifest_consistency(
            source,
            # The runtime call below is authoritative; this report preserves
            # the source-level rejection reason for unsupported tools.
            parse_security_manifest(f"tool {name} {{\n{MANIFEST}\n}}"),
            tool_name=name,
            function="main",
        )
        skipped = {
            "admission_succeeded": False,
            "execution_attempted": False,
            "execution_succeeded": False,
            "result": None,
            "error": {
                "stage": "selection",
                "type": "Placeholder",
                "message": "pass-only tool",
            },
            "source_unchanged": True,
            "route": "not_attempted_placeholder",
        }
        language = dict(skipped) if placeholder else _execute(path, name, host_isolated=False)
        host = dict(skipped) if placeholder else _execute(path, name, host_isolated=True)
        classification = (
            "placeholder_excluded"
            if placeholder
            else "works_unchanged"
            if language["execution_succeeded"] and language["source_unchanged"]
            else "requires_host_isolation"
            if host["execution_succeeded"] and host["source_unchanged"]
            else "requires_adaptation"
        )
        rows.append(
            {
                "tool": name,
                "source": str(path.relative_to(ace_root)),
                "source_sha256": hashlib.sha256(path.read_bytes()).hexdigest(),
                "placeholder": placeholder,
                "classification": classification,
                "static_report": static_report,
                "language_route": language,
                "host_route": host,
            }
        )
    (output / "trials.jsonl").write_text(
        "".join(json.dumps(row, sort_keys=True) + "\n" for row in rows)
    )
    real = [row for row in rows if not row["placeholder"]]
    counts = {
        label: sum(row["classification"] == label for row in rows)
        for label in (
            "placeholder_excluded",
            "works_unchanged",
            "requires_host_isolation",
            "requires_adaptation",
        )
    }
    (output / "summary.json").write_text(
        json.dumps(
            {
                "collection": "ACE case-study-1 enabled tools with checked-in source",
                "selection_rule": (
                    "Every enabled manifest entry with source/<path>.py; pass-only "
                    "implementations are reported and excluded from the real-tool denominator"
                ),
                "ace_revision": revision,
                "manifest_sha256": hashlib.sha256(manifest_path.read_bytes()).hexdigest(),
                "source_files": len(rows),
                "real_tools": len(real),
                "counts": counts,
                "real_language_admission_successes": sum(
                    row["language_route"]["admission_succeeded"] for row in real
                ),
                "real_language_execution_successes": sum(
                    row["language_route"]["execution_succeeded"] for row in real
                ),
                "host_isolated_execution_successes": sum(
                    row["host_route"]["execution_succeeded"] for row in real
                ),
                "claim": (
                    "Only non-placeholder tools that passed closed admission and "
                    "executed through ToolNode count as works_unchanged."
                ),
            },
            indent=2,
        )
        + "\n"
    )


if __name__ == "__main__":
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--output", required=True, type=Path)
    parser.add_argument("--ace-root", required=True, type=Path)
    arguments = parser.parse_args()
    run(arguments.output, arguments.ace_root)
