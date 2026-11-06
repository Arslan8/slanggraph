#!/usr/bin/env python3
"""Measure post-compilation runtime inside activated NoNo and APF boundaries."""

from __future__ import annotations

import argparse
import json
import math
import os
import platform
import statistics
import subprocess
import sys
from pathlib import Path

HERE = Path(__file__).resolve().parent
ROOT = HERE.parents[2]
WORKER = HERE / "comparator_worker.py"
NONO = ROOT / "eval/vendor/nono/target/release/nono"
OPEN_SHELL = ROOT / "eval/campaigns/remediation-v2/raw/openshell-setup/openshell"
APF_POLICY = (
    ROOT / "eval/campaigns/langgraph-demos-v3/permissive-comparators/apf-projected-policy.json"
)
APF_IMAGE = "slg-apf-apps:bd035dd06"
ENDPOINT = "http://127.0.0.1:18080"
READ_ONLY_CODE = (
    ROOT / "eval/.venv",
    ROOT / "eval/src",
    ROOT / "eval/apps/demos",
    ROOT / "libs",
)
PYTHON_RUNTIME = Path("/home/faculty/abk6349/.local/share/uv")


def percentile(values: list[float], fraction: float) -> float:
    ordered = sorted(values)
    return ordered[math.ceil(len(ordered) * fraction) - 1]


def describe(values: list[float]) -> dict[str, float | int]:
    return {
        "n": len(values),
        "mean_ms": statistics.mean(values),
        "median_ms": statistics.median(values),
        "p95_ms": percentile(values, 0.95),
        "min_ms": min(values),
        "max_ms": max(values),
    }


def parse_result(completed: subprocess.CompletedProcess[str]) -> dict:
    if completed.returncode != 0:
        raise RuntimeError(completed.stderr)
    lines = [line for line in completed.stdout.splitlines() if line.startswith("{")]
    if len(lines) != 1:
        raise RuntimeError(f"unexpected comparator output: {completed.stdout!r}")
    return json.loads(lines[0])


def nono_command(demo: str, repeats: int, work: Path) -> list[str]:
    return [
        os.fspath(NONO),
        "run",
        "--allow-cwd",
        "--allow",
        os.fspath(work),
        *[item for path in READ_ONLY_CODE for item in ("--read", os.fspath(path))],
        "--read",
        os.fspath(PYTHON_RUNTIME),
        "--read-file",
        os.fspath(WORKER),
        "--block-net",
        "--no-audit",
        "--no-rollback",
        "--silent",
        "--",
        os.fspath(ROOT / "eval/.venv/bin/python"),
        os.fspath(WORKER),
        "--demo",
        demo,
        "--repeats",
        str(repeats),
    ]


def openshell_prefix() -> list[str]:
    return [os.fspath(OPEN_SHELL), "--gateway-endpoint", ENDPOINT]


def create_apf(sandbox: str) -> None:
    subprocess.run(
        [*openshell_prefix(), "sandbox", "delete", sandbox],
        cwd=ROOT,
        capture_output=True,
        text=True,
        check=False,
    )
    completed = subprocess.run(
        [
            *openshell_prefix(),
            "sandbox",
            "create",
            "--name",
            sandbox,
            "--from",
            APF_IMAGE,
            "--policy",
            os.fspath(APF_POLICY),
            "--no-tty",
            "--detach",
            "--",
            "/data/langgraph/eval/.venv/bin/python",
            (
                "/data/langgraph/eval/campaigns/langgraph-demos-v3/"
                "permissive-comparators/model_relay.py"
            ),
            "--target-host",
            "host.openshell.internal",
            "--target-port",
            "11435",
            "--rewrite-authority",
            "127.0.0.1:11434",
            "host.openshell.internal:11435",
        ],
        cwd=ROOT,
        capture_output=True,
        text=True,
        check=False,
    )
    if completed.returncode != 0:
        raise RuntimeError(completed.stderr)
    subprocess.run(
        [
            *openshell_prefix(),
            "sandbox",
            "upload",
            "--no-git-ignore",
            sandbox,
            os.fspath(WORKER),
            "/workspace/comparator_worker.py",
        ],
        cwd=ROOT,
        check=True,
        capture_output=True,
        text=True,
    )


def delete_apf(sandbox: str) -> None:
    subprocess.run(
        [*openshell_prefix(), "sandbox", "delete", sandbox],
        cwd=ROOT,
        check=True,
        capture_output=True,
        text=True,
    )


def apf_command(sandbox: str, demo: str, repeats: int) -> list[str]:
    return [
        *openshell_prefix(),
        "sandbox",
        "exec",
        sandbox,
        "--no-tty",
        "--no-login-shell",
        "--timeout",
        "60",
        "--workdir",
        "/data/langgraph",
        "--",
        "/data/langgraph/eval/.venv/bin/python",
        "/workspace/comparator_worker.py",
        "--demo",
        demo,
        "--repeats",
        str(repeats),
    ]


def main() -> None:
    parser = argparse.ArgumentParser()
    parser.add_argument("--processes", type=int, default=30)
    parser.add_argument("--repeats", type=int, default=20)
    parser.add_argument("--output", type=Path, required=True)
    parser.add_argument("--aggregate-only", action="store_true")
    args = parser.parse_args()
    args.output = args.output.resolve()
    args.output.mkdir(parents=True, exist_ok=True)
    work = args.output / "nono-work"
    work.mkdir(exist_ok=True)
    sandbox = "arg-runtime-v1"
    records = []
    commands = []
    if not args.aggregate_only:
        create_apf(sandbox)
        try:
            for process_index in range(args.processes):
                mode_order = (
                    ("NoNo", "APF") if process_index % 2 == 0 else ("APF", "NoNo")
                )
                for demo in ("fixed-weather", "parallel-weather"):
                    for mode in mode_order:
                        command = (
                            nono_command(demo, args.repeats, work)
                            if mode == "NoNo"
                            else apf_command(sandbox, demo, args.repeats)
                        )
                        completed = subprocess.run(
                            command,
                            cwd=work if mode == "NoNo" else ROOT,
                            env={
                                **os.environ,
                                "TMPDIR": os.fspath(work),
                                "PYTHONDONTWRITEBYTECODE": "1",
                            }
                            if mode == "NoNo"
                            else None,
                            capture_output=True,
                            text=True,
                            timeout=90,
                            check=False,
                        )
                        result = parse_result(completed)
                        result.update({"mode": mode, "process_index": process_index})
                        records.append(result)
                        commands.append(command)
        finally:
            delete_apf(sandbox)
    else:
        records = json.loads((args.output / "trials.json").read_text())

    aggregate = {}
    for demo in ("fixed-weather", "parallel-weather"):
        aggregate[demo] = {}
        for mode in ("NoNo", "APF"):
            selected = [
                record for record in records if record["demo"] == demo and record["mode"] == mode
            ]
            aggregate[demo][mode] = {
                "first_invocation": describe(
                    [record["first_invocation_ms"] for record in selected]
                ),
                "runtime_invocation": describe(
                    [sample for record in selected for sample in record["runtime_samples_ms"]]
                ),
            }
    (args.output / "trials.json").write_text(json.dumps(records, indent=2, sort_keys=True) + "\n")
    metadata = {
        "revision": subprocess.run(
            ["git", "rev-parse", "HEAD"],
            cwd=ROOT,
            check=True,
            capture_output=True,
            text=True,
        ).stdout.strip(),
        "branch": subprocess.run(
            ["git", "branch", "--show-current"],
            cwd=ROOT,
            check=True,
            capture_output=True,
            text=True,
        ).stdout.strip(),
        "python": sys.version,
        "platform": platform.platform(),
        "processes_per_cell": args.processes,
        "runtime_repeats_per_process": args.repeats,
        "runtime_boundary": (
            "prepared graph after the first invocation; excludes comparator activation, "
            "sandbox creation, process startup, first invocation, and cleanup"
        ),
        "apf_image": APF_IMAGE,
        "apf_policy": os.fspath(APF_POLICY.relative_to(ROOT)),
        "nono_executable": os.fspath(NONO.relative_to(ROOT)),
    }
    (args.output / "aggregate.json").write_text(
        json.dumps({"metadata": metadata, "results": aggregate}, indent=2, sort_keys=True)
        + "\n"
    )
    if commands:
        (args.output / "commands.json").write_text(json.dumps(commands, indent=2) + "\n")


if __name__ == "__main__":
    main()
