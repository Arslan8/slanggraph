"""Evaluation 4 adapter for the frozen Pandas application campaign."""

from __future__ import annotations

import json
import subprocess
import sys
import uuid
from pathlib import Path
from typing import Any

from campaign import ROOT, Cell, config_id, load_config, record_for

RUNNER = ROOT / "eval/apps/pandas/closed_campaign.py"
RAW = ROOT / "eval/campaigns/unified-final-v1/raw-pandas-qualification"


def _run(output: Path, *arguments: str) -> subprocess.CompletedProcess[str]:
    output.parent.mkdir(parents=True, exist_ok=True)
    return subprocess.run(
        [sys.executable, str(RUNNER), "--output", str(output), *arguments],
        cwd=ROOT,
        capture_output=True,
        text=True,
        timeout=None,
        check=False,
    )


def _rows(output: Path) -> list[dict[str, Any]]:
    path = output / "trials.jsonl"
    if not path.is_file():
        return []
    return [json.loads(line) for line in path.read_text().splitlines() if line.strip()]


def qualification_pilot() -> dict[str, Any]:
    """Run all ten live tasks in both modes and both resource controls."""
    output = RAW / f"unified-final-qualification-{uuid.uuid4().hex}"
    matched = _run(output, "--repetitions", "1", "--configuration", "matched")
    rows = _rows(output)
    attacks = []
    for attack in ("read_bob", "update_bob"):
        attack_output = RAW / f"unified-final-qualification-{attack}-{uuid.uuid4().hex}"
        completed = _run(
            attack_output,
            "--pilot",
            "--repetitions",
            "1",
            "--configuration",
            "slangGraph",
            "--attack",
            attack,
        )
        attack_rows = _rows(attack_output)
        attacks.append(
            {
                "attack": attack,
                "returncode": completed.returncode,
                "raw_evidence": str(attack_output.relative_to(ROOT)),
                "rows": attack_rows,
                "passed": completed.returncode == 0
                and len(attack_rows) == 1
                and attack_rows[0]["observed_effect"] is False,
            }
        )
    passed = (
        matched.returncode == 0
        and len(rows) == 20
        and all(
            row["status"] == "completed"
            and row["legitimate_result"]
            and row["ready_observed"]
            and row["runtime_ns"] > 0
            for row in rows
        )
        and all(item["passed"] for item in attacks)
    )
    return {
        "raw_evidence": str(output.relative_to(ROOT)),
        "matched_returncode": matched.returncode,
        "matched_stdout": matched.stdout,
        "matched_stderr": matched.stderr,
        "rows": rows,
        "attacks": attacks,
        "passed": passed,
    }


def _record(row: dict[str, Any], config: dict[str, Any], build_id: str) -> dict[str, Any]:
    mode = "baseline" if row["mode"] == "Baseline" else "argus"
    cell = Cell(
        4,
        mode,
        "pandas",
        row["case_id"],
        int(row["session"]),
        int(row["repeat"]),
        row["phase"],
        int(row["seed"]),
    )
    outcome = row["status"]
    if outcome == "completed" and not row["legitimate_result"]:
        outcome = "wrong-answer"
    checks = int(row.get("computation_calls", 0)) + int(row.get("dataset_reads", 0))
    return record_for(
        cell,
        configuration_id=config_id(config),
        build_id=build_id,
        route="unprotected" if mode == "baseline" else "host",
        preflight_ns=int(row["preflight_ns"]),
        runtime_start_ns=int(row["runtime_start_ns"]),
        runtime_end_ns=int(row["runtime_end_ns"]),
        outcome=outcome,
        oracle_passed=bool(row["legitimate_result"]),
        counters={
            "authorization_checks": checks if mode == "argus" else 0,
            "cleanup_completed": int(row.get("cleanup_confirmed") is True),
            "normal_fallbacks": 0,
            "debug_fallbacks": 0,
            "host_fallbacks": 0,
            "computation_calls": row.get("computation_calls", 0),
            "dataset_reads": row.get("dataset_reads", 0),
        },
        model_calls=row.get("model_calls"),
        model_time_ms=row.get("model_ms"),
        retries=row.get("retries"),
        application_status=row["status"],
        raw_trial=row,
    )


def collect(result: Path) -> dict[str, Any]:
    config = load_config(result / "configuration.json")
    freeze = json.loads((result / "freeze.json").read_text())
    output = result / "raw" / "evaluation-4"
    completed = _run(
        output,
        "--configuration",
        "matched",
        "--unified-schedule",
        str(result / "schedule.json"),
    )
    if completed.returncode != 0:
        detail = f"{completed.stdout}\n{completed.stderr}"
        raise RuntimeError(f"Pandas campaign failed ({completed.returncode}):\n{detail}")
    rows = _rows(output)
    records = [_record(row, config, freeze["build_id"]) for row in rows]
    with (result / "records.jsonl").open("a") as stream:
        for record in records:
            stream.write(json.dumps(record, sort_keys=True) + "\n")
    attacks = []
    for attack in ("read_bob", "update_bob"):
        attack_output = result / "raw" / f"evaluation-4-{attack}"
        attack_run = _run(
            attack_output,
            "--pilot",
            "--repetitions",
            "1",
            "--configuration",
            "slangGraph",
            "--attack",
            attack,
        )
        attack_rows = _rows(attack_output)
        attacks.append(
            {
                "attack": attack,
                "returncode": attack_run.returncode,
                "raw_evidence": str(attack_output.relative_to(result)),
                "rows": attack_rows,
                "passed": attack_run.returncode == 0
                and len(attack_rows) == 1
                and attack_rows[0]["observed_effect"] is False,
            }
        )
    (result / "pandas-security.json").write_text(json.dumps(attacks, indent=2) + "\n")
    return {
        "records": len(records),
        "non_success_outcomes": sum(
            record["outcome"] != "completed" or not record["oracle_passed"] for record in records
        ),
        "security_controls_passed": all(item["passed"] for item in attacks),
        "passed": len(records) == 700 and all(item["passed"] for item in attacks),
    }
