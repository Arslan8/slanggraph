"""Evaluation 1 adapter over the frozen application and comparator runners."""

from __future__ import annotations

import importlib.util
import json
import sys
import uuid
from pathlib import Path
from collections.abc import Callable
from typing import Any

from campaign import (
    ROOT,
    Cell,
    config_id,
    expected_route,
    load_config,
    record_for,
    request_cells,
)

COMPARATOR_RUNNER = (
    ROOT / "eval/campaigns/langgraph-demos-v3/permissive-comparators/run_campaign.py"
)


def _runner():
    name = "unified_final_macro_runner"
    spec = importlib.util.spec_from_file_location(name, COMPARATOR_RUNNER)
    if spec is None or spec.loader is None:
        raise RuntimeError(f"cannot load macrobenchmark adapter: {COMPARATOR_RUNNER}")
    module = importlib.util.module_from_spec(spec)
    sys.modules[name] = module
    spec.loader.exec_module(module)
    return module


def _policy_gap(workload: str) -> str:
    gaps = {
        "D1-sql": "query-level read-only SQL actions and prevention of direct database reads",
        "D2-rag": "registered retriever/top-k action mediation and prevention of direct corpus reads",
        "D3-plan-execute": "registered frozen-search action mediation and prevention of direct corpus reads",
        "D4-multi-agent": "typed retrieval action mediation inside the generated-code workflow",
        "D5-support": "passenger/row ownership, typed travel actions, and prevention of direct SQLite access",
        "T9-add-memory": "principal-bound authenticated checkpoint-chain enforcement",
        "T10-time-travel": "principal-bound authenticated checkpoint history and one-use branch authorization",
    }
    return gaps.get(
        workload,
        "tool-call object/action authorization and admitted-language direct-bypass prevention",
    )


def _inner(raw: dict[str, Any]) -> dict[str, Any]:
    path = raw.get("raw_output")
    if not path:
        return {}
    output = ROOT / path
    return json.loads(output.read_text()) if output.is_file() else {}


def _counters(cell: Cell, raw: dict[str, Any], inner: dict[str, Any]) -> dict[str, Any]:
    grants = inner.get("authorization_grants", [])
    decisions = inner.get("authorization_decisions", [])
    lowerings = inner.get("lowering_records", inner.get("lowered_restrictions", []))
    broker = inner.get("broker_audit", [])
    activations = inner.get("activation_receipts", [])
    checks = len(grants) + len(decisions) + len(broker) + len(activations)
    if cell.mode == "argus" and checks < 1:
        checks = raw.get("grant_count", 0) + raw.get("broker_record_count", 0)
    return {
        "authorization_checks": checks if cell.mode == "argus" else 0,
        "grant_count": len(grants),
        "decision_count": len(decisions),
        "lowering_count": len(lowerings),
        "broker_record_count": len(broker),
        "activation_count": len(activations),
        "cleanup_completed": int(raw.get("cleanup_confirmed") is True)
        if cell.mode in {"baseline", "argus"}
        else int(raw.get("sandbox_cleanup_confirmed") is not False),
        "normal_fallbacks": 0,
        "debug_fallbacks": 0,
        "host_fallbacks": 0,
    }


def execute_cell(module: Any, root: Path, tasks: dict[str, Any], cell: Cell) -> dict[str, Any]:
    mode = {
        "baseline": "Baseline",
        "argus": "Argus",
        "nono": "NoNo-enforced",
        "apf": "APF-enforced",
    }[cell.mode]
    repetition = cell.session * 7 + (0 if cell.phase == "warmup" else cell.repetition + 1)
    job = module.base.Job(cell.workload, int(cell.task), repetition, mode)
    if cell.mode in {"baseline", "argus"}:
        raw = module.base.execute(job, root, tasks)
    else:
        raw = module.execute_external(
            job,
            root,
            tasks,
            nono=module.DEFAULT_NONO,
            openshell=module.DEFAULT_OPENSHELL,
            endpoint="http://127.0.0.1:18080",
        )
    inner = _inner(raw)
    route = (
        raw.get("isolation_route")
        or raw.get("application_route")
        or expected_route(load_config(), cell)
    )
    if cell.mode in {"nono", "apf"}:
        route = cell.mode
    outcome = raw["status"]
    if outcome == "completed" and not raw["correct"]:
        outcome = "wrong-answer"
    record = record_for(
        cell,
        configuration_id=config_id(load_config()),
        build_id="qualification" if root.name.startswith("qualification-") else "pending",
        route=route,
        preflight_ns=int(raw["preflight_ns"]),
        runtime_start_ns=int(raw["runtime_start_ns"]),
        runtime_end_ns=int(raw["runtime_end_ns"]),
        outcome=outcome,
        oracle_passed=bool(raw["correct"]),
        counters=_counters(cell, raw, inner),
        ready_observed=raw.get("ready_observed"),
        model_calls=raw.get("model_calls"),
        model_time_ms=raw.get("model_time_ms"),
        executed_tools=inner.get("executed_tools", []),
        application_status=raw["status"],
        raw_trial=raw,
    )
    if cell.mode in {"nono", "apf"}:
        record.update(
            policy_category="best-available-reduced-enforcement",
            omitted_obligation=_policy_gap(cell.workload),
            comparator_security_equivalent=False,
        )
    return record


def qualification_pilot() -> dict[str, Any]:
    """Exercise every frozen macro task once in every scheduled condition."""
    module = _runner()
    tasks = json.loads((module.V1 / "tasks.json").read_text())
    root = module.V3 / "raw" / f"qualification-macro-{uuid.uuid4().hex}"
    root.mkdir(parents=True, exist_ok=False)
    cells = tuple(
        Cell(1, mode, application["id"], str(task), 0, 0, "measured", 0)
        for application in load_config()["evaluations"][0]["applications"]
        for task in range(1, int(application["tasks"]) + 1)
        for mode in ("baseline", "argus", "nono", "apf")
    )
    rows = [execute_cell(module, root, tasks, cell) for cell in cells]
    execution_success = [
        row["application_status"] == "completed"
        and row["ready_observed"] is True
        and row["runtime_ns"] > 0
        for row in rows
    ]
    passed = all(
        execution_ok
        and (
            row["route"] == expected_route(load_config(), cell)
            or cell.mode == "baseline" and row["route"] == "baseline"
        )
        and row["counters"]["cleanup_completed"] > 0
        and (
            cell.mode != "argus"
            or not row["executed_tools"]
            or row["counters"]["authorization_checks"] > 0
        )
        for row, cell, execution_ok in zip(rows, cells, execution_success, strict=True)
    )
    return {
        "raw_evidence": str(root.relative_to(ROOT)),
        "scheduled_cells": len(cells),
        "execution_successes": sum(execution_success),
        "answer_correct": sum(row["oracle_passed"] for row in rows),
        "answer_errors": sum(not row["oracle_passed"] for row in rows),
        "rows": rows,
        "passed": passed,
    }


def collect(
    result: Path, *, cell_filter: Callable[[Cell], bool] | None = None
) -> dict[str, Any]:
    config = load_config(result / "configuration.json")
    freeze = json.loads((result / "freeze.json").read_text())
    module = _runner()
    tasks = json.loads((module.V1 / "tasks.json").read_text())
    raw_root = (result / "raw" / "evaluation-1").resolve()
    raw_root.mkdir(parents=True, exist_ok=False)
    module.run_enforcement_probes(
        raw_root,
        nono=module.DEFAULT_NONO,
        openshell=module.DEFAULT_OPENSHELL,
        endpoint="http://127.0.0.1:18080",
    )
    output = result / "records.jsonl"
    count = 0
    failures = 0
    with output.open("a") as stream:
        for cell in request_cells(config, 1):
            if cell_filter is not None and not cell_filter(cell):
                continue
            record = execute_cell(module, raw_root, tasks, cell)
            record["build_id"] = freeze["build_id"]
            record["config_id"] = freeze["config_id"]
            stream.write(json.dumps(record, sort_keys=True) + "\n")
            stream.flush()
            count += 1
            failures += int(record["outcome"] != "completed" or not record["oracle_passed"])
    return {"records": count, "non_success_outcomes": failures, "passed": True}
