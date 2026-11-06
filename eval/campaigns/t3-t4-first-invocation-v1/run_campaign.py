#!/usr/bin/env python3
"""Run the two weather demos with the retained four-mode protocol."""

from __future__ import annotations

import argparse
import hashlib
import importlib.util
import json
import math
import os
import platform
import random
import statistics
import subprocess
import sys
from pathlib import Path
from types import ModuleType
from typing import Any

HERE = Path(__file__).resolve().parent
ROOT = HERE.parents[2]
V1 = ROOT / "eval/campaigns/langgraph-demos-v1"
V3 = ROOT / "eval/campaigns/langgraph-demos-v3"
RETAINED = V3 / "raw/matched-comparators-final-c976a2070"
COMPARATOR_RUNNER = V3 / "permissive-comparators/run_campaign.py"
DEFAULT_OUTPUT = HERE / "raw"
SEED = 20261028
MODES = ("Baseline", "Argus", "NoNo-enforced", "APF-enforced")
APPLICATIONS = ("T3-fixed-weather", "T4-parallel-weather")


def load_comparator_runner() -> ModuleType:
    spec = importlib.util.spec_from_file_location("t3_t4_retained_runner", COMPARATOR_RUNNER)
    if spec is None or spec.loader is None:
        raise RuntimeError(f"cannot load comparator runner: {COMPARATOR_RUNNER}")
    module = importlib.util.module_from_spec(spec)
    sys.modules[spec.name] = module
    spec.loader.exec_module(module)
    return module


runner = load_comparator_runner()
base = runner.base


def sha256(path: Path) -> str:
    return hashlib.sha256(path.read_bytes()).hexdigest()


def nearest_rank_p95(values: list[float]) -> float:
    return sorted(values)[math.ceil(0.95 * len(values)) - 1]


def summarize(records: list[dict[str, Any]]) -> dict[str, Any]:
    result: dict[str, Any] = {}
    for application in APPLICATIONS:
        result[application] = {}
        baseline_values = [
            float(record["invocation_ms"])
            for record in records
            if record["application"] == application and record["mode"] == "Baseline"
        ]
        baseline_mean = statistics.mean(baseline_values)
        for mode in MODES:
            selected = [
                record
                for record in records
                if record["application"] == application and record["mode"] == mode
            ]
            values = [float(record["invocation_ms"]) for record in selected]
            mean = statistics.mean(values)
            result[application][mode] = {
                "sample_count": len(selected),
                "correct_count": sum(record["correct"] is True for record in selected),
                "all_correct": all(record["correct"] is True for record in selected),
                "mean_invocation_ms": mean,
                "median_invocation_ms": statistics.median(values),
                "p95_invocation_ms": nearest_rank_p95(values),
                "baseline_relative_delta_ms": mean - baseline_mean,
                "baseline_relative_ratio": mean / baseline_mean,
                "baseline_relative_percent": 100.0 * (mean - baseline_mean) / baseline_mean,
                "samples_ms": values,
            }
    return result


def main() -> None:
    parser = argparse.ArgumentParser()
    parser.add_argument("--run-id", required=True)
    parser.add_argument("--output-root", type=Path, default=DEFAULT_OUTPUT)
    parser.add_argument("--nono", type=Path, default=runner.DEFAULT_NONO)
    parser.add_argument("--openshell", type=Path, default=runner.DEFAULT_OPENSHELL)
    parser.add_argument("--openshell-endpoint", default="http://127.0.0.1:18080")
    args = parser.parse_args()

    for executable in (args.nono, args.openshell, runner.APF_EXPORTER):
        if not executable.is_file():
            raise RuntimeError(f"missing comparator executable: {executable}")

    root = (args.output_root / args.run_id).resolve()
    root.mkdir(parents=True, exist_ok=False)
    tasks = json.loads((V1 / "tasks.json").read_text())
    revision = subprocess.run(
        ["git", "rev-parse", "HEAD"],
        cwd=ROOT,
        capture_output=True,
        text=True,
        check=True,
    ).stdout.strip()
    retained_configuration = json.loads((RETAINED / "configuration.json").read_text())
    configuration = {
        "run_id": args.run_id,
        "evaluated_revision": revision,
        "branch": subprocess.run(
            ["git", "branch", "--show-current"],
            cwd=ROOT,
            capture_output=True,
            text=True,
            check=True,
        ).stdout.strip(),
        "protocol": (
            "five repetition blocks; both workloads and all four modes shuffled within each "
            "block; fresh process per execution; jobs run sequentially"
        ),
        "scope": list(APPLICATIONS),
        "modes": list(MODES),
        "repetitions": 5,
        "execution_count": 40,
        "shuffle_seed": SEED,
        "primary_timer": ("first graph.invoke only, after graph/policy preparation; no warmup"),
        "secondary_timers": (
            "preparation_ms, process_wall_ms, sandbox_preparation_ms, "
            "sandbox_cleanup_ms, and end_to_end_wall_ms retained separately"
        ),
        "audit_enabled": False,
        "argus_operator_mac_installed": True,
        "argus_expected_route": "language",
        "argus_host_fallback_allowed": False,
        "fresh_identity": (
            "fresh child process and principal session per execution; deterministic tutorial "
            "call labels are process-local and never reused within a process"
        ),
        "runner_command": [os.fspath(Path(sys.executable).absolute()), *sys.argv],
        "host": {
            "platform": platform.platform(),
            "machine": platform.machine(),
            "python": sys.version,
        },
        "source": {
            "application": "eval/apps/demos/tool_calling_protected.py",
            "application_sha256": sha256(ROOT / "eval/apps/demos/tool_calling_protected.py"),
            "scoped_runner": str(Path(__file__).resolve().relative_to(ROOT)),
            "scoped_runner_sha256": sha256(Path(__file__).resolve()),
            "reused_runner": str(COMPARATOR_RUNNER.relative_to(ROOT)),
            "reused_runner_sha256": sha256(COMPARATOR_RUNNER),
            "retained_campaign": str(RETAINED.relative_to(ROOT)),
            "retained_configuration_sha256": sha256(RETAINED / "configuration.json"),
        },
        "nono": {
            **retained_configuration["nono"],
            "binary": str(args.nono.resolve()),
            "sha256": sha256(args.nono),
        },
        "apf_openshell": {
            **retained_configuration["apf_openshell"],
            "cli": str(args.openshell.resolve()),
            "cli_sha256": sha256(args.openshell),
            "endpoint": args.openshell_endpoint,
            "image_tag": runner.APF_IMAGE,
        },
    }
    (root / "configuration.json").write_text(json.dumps(configuration, indent=2) + "\n")

    records: list[dict[str, Any]] = []
    schedule: list[dict[str, Any]] = []
    for repetition in range(5):
        jobs = [
            base.Job(application, 1, repetition, mode)
            for application in APPLICATIONS
            for mode in MODES
        ]
        random.Random(SEED + repetition).shuffle(jobs)
        for position, job in enumerate(jobs):
            schedule.append(
                {
                    "repetition": repetition,
                    "position": position,
                    "application": job.application,
                    "mode": job.mode,
                }
            )
            if job.mode in {"Baseline", "Argus"}:
                record = base.execute(job, root, tasks)
                record["configuration"] = "retained application-comparison protocol"
                record["security_equivalent_to_argus"] = job.mode == "Argus"
                trial = (
                    root
                    / f"rep-{job.repetition}"
                    / job.application
                    / "task-1"
                    / job.mode
                    / "trial.json"
                )
                trial.write_text(json.dumps(record, indent=2) + "\n")
            else:
                record = runner.execute_external(
                    job,
                    root,
                    tasks,
                    nono=args.nono,
                    openshell=args.openshell,
                    endpoint=args.openshell_endpoint,
                )
            if job.mode == "Argus" and record.get("isolation_route") != "language":
                raise RuntimeError(f"Argus did not use language isolation: {record}")
            records.append(record)
            print(
                f"block={repetition} position={position} {job.application} {job.mode}: "
                f"status={record['status']} correct={record['correct']} "
                f"invocation_ms={record.get('invocation_ms')}",
                flush=True,
            )

    if len(records) != 40:
        raise RuntimeError(f"expected exactly 40 executions, got {len(records)}")
    (root / "schedule.json").write_text(json.dumps(schedule, indent=2) + "\n")
    (root / "trials.json").write_text(json.dumps(records, indent=2) + "\n")
    summary = {
        "evaluated_revision": revision,
        "execution_count": len(records),
        "all_completed": all(record["status"] == "completed" for record in records),
        "all_correct": all(record["correct"] is True for record in records),
        "results": summarize(records),
    }
    (root / "summary.json").write_text(json.dumps(summary, indent=2) + "\n")


if __name__ == "__main__":
    main()
