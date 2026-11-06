#!/usr/bin/env python3
"""Run paired weather-workload measurements in independent Python processes."""

from __future__ import annotations

import argparse
import hashlib
import json
import os
import platform
import statistics
import subprocess
import sys
from pathlib import Path

HERE = Path(__file__).resolve().parent
ROOT = HERE.parents[2]


def command_output(*command: str) -> str:
    return subprocess.run(
        command,
        cwd=ROOT,
        check=True,
        capture_output=True,
        text=True,
    ).stdout.strip()


def percentile(values: list[float], fraction: float) -> float:
    ordered = sorted(values)
    return ordered[max(0, min(len(ordered) - 1, int(len(ordered) * fraction + 0.999999) - 1))]


def summary(values: list[float]) -> dict[str, float | int]:
    return {
        "n": len(values),
        "mean_ms": statistics.mean(values),
        "median_ms": statistics.median(values),
        "p95_ms": percentile(values, 0.95),
        "min_ms": min(values),
        "max_ms": max(values),
    }


def main() -> None:
    parser = argparse.ArgumentParser()
    parser.add_argument("--processes", type=int, default=30)
    parser.add_argument("--repeats", type=int, default=20)
    parser.add_argument("--output-dir", type=Path, default=HERE / "raw" / "final")
    parser.add_argument("--aggregate-only", action="store_true")
    args = parser.parse_args()
    output_dir = args.output_dir.resolve()
    samples_dir = output_dir / "processes"
    samples_dir.mkdir(parents=True, exist_ok=True)

    # Preserve the virtual-environment launcher path. Resolving its symlink
    # would run the base interpreter without this environment's packages.
    python = Path(sys.executable).absolute()
    commands = []
    if not args.aggregate_only:
        for process_index in range(args.processes):
            mode_order = ("Baseline", "Argus") if process_index % 2 == 0 else ("Argus", "Baseline")
            for demo in ("fixed-weather", "parallel-weather"):
                for mode in mode_order:
                    output = samples_dir / f"{process_index:03d}-{demo}-{mode.lower()}.json"
                    command = [
                        os.fspath(python),
                        os.fspath(HERE / "worker.py"),
                        "--demo",
                        demo,
                        "--mode",
                        mode,
                        "--repeats",
                        str(args.repeats),
                        "--process-index",
                        str(process_index),
                        "--output",
                        os.fspath(output),
                    ]
                    subprocess.run(command, cwd=ROOT, check=True)
                    commands.append(command)

    records = [json.loads(path.read_text()) for path in sorted(samples_dir.glob("*.json"))]
    aggregate: dict[str, object] = {}
    for demo in ("fixed-weather", "parallel-weather"):
        aggregate[demo] = {}
        for mode in ("Baseline", "Argus"):
            selected = [
                record for record in records if record["demo"] == demo and record["mode"] == mode
            ]
            aggregate[demo][mode] = {
                "route": sorted({record["route"] for record in selected}),
                "admitted_tools": sorted({tuple(record["admitted_tools"]) for record in selected}),
                "policy_setup": summary([record["policy_setup_ms"] for record in selected]),
                "preparation": summary([record["preparation_ms"] for record in selected]),
                "first_invocation": summary([record["first_invocation_ms"] for record in selected]),
                "steady_invocation": summary(
                    [sample for record in selected for sample in record["steady_invocation_ms"]]
                ),
            }

    relevant_diff = subprocess.run(
        [
            "git",
            "diff",
            "--binary",
            "--",
            "libs/langgraph/langgraph/pregel/main.py",
            "libs/prebuilt/langgraph/prebuilt/security/config.py",
            "libs/prebuilt/langgraph/prebuilt/security/object_policy.py",
            "libs/prebuilt/langgraph/prebuilt/security/inprocess.py",
            "libs/prebuilt/langgraph/prebuilt/security/language_route_verification.py",
            "libs/prebuilt/tests/security/test_language_route_verification.py",
            "libs/prebuilt/tests/security/test_object_policy.py",
            "libs/prebuilt/tests/security/test_runtime_mac.py",
            os.fspath(HERE.relative_to(ROOT)),
        ],
        cwd=ROOT,
        check=True,
        capture_output=True,
    ).stdout
    metadata = {
        "revision": command_output("git", "rev-parse", "HEAD"),
        "branch": command_output("git", "branch", "--show-current"),
        "relevant_diff_sha256": hashlib.sha256(relevant_diff).hexdigest(),
        "python": sys.version,
        "python_executable": os.fspath(python),
        "platform": platform.platform(),
        "machine": platform.machine(),
        "processor": platform.processor(),
        "cedar": command_output("bash", "-lc", "command -v cedar && cedar language-version"),
        "processes_per_cell": args.processes,
        "steady_repeats_per_process": args.repeats,
        "audit": False,
        "operator_policy": "forbid blocked principal",
        "principal": "alice with no roles/groups and a fresh session per invocation",
        "input": (
            "fixed-weather calls get_weather for San Francisco; parallel-weather "
            "additionally calls get_coolest_cities"
        ),
        "percentile": "nearest-rank p95",
    }
    (output_dir / "aggregate.json").write_text(
        json.dumps({"metadata": metadata, "results": aggregate}, indent=2, sort_keys=True) + "\n"
    )
    if commands:
        (output_dir / "commands.json").write_text(json.dumps(commands, indent=2) + "\n")
    (output_dir / "relevant.diff").write_bytes(relevant_diff)


if __name__ == "__main__":
    main()
