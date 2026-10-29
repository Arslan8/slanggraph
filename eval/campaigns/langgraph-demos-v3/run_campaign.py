"""Run all 15 ordinary demos under one matched Baseline/Argus protocol."""

from __future__ import annotations

import argparse
import hashlib
import json
import random
import shutil
import subprocess
import sys
import time
from dataclasses import dataclass
from pathlib import Path

CAMPAIGN = Path(__file__).resolve().parent
ROOT = CAMPAIGN.parents[2]
APPS = ROOT / "eval/apps/demos"
V1 = ROOT / "eval/campaigns/langgraph-demos-v1"
WORKER = ROOT / "eval/campaigns/pandas-matched-v1/raw/workerRoute"
SEED = 20261028
MODES = ("Baseline", "Argus")


@dataclass(frozen=True)
class Job:
    application: str
    task: int
    repetition: int
    mode: str


OLD_DEMOS = {
    "T1-add-tools": ("add_tools_protected.py", "add-tools"),
    "T2-custom-weather": ("tool_calling_protected.py", "custom-weather"),
    "T3-fixed-weather": ("tool_calling_protected.py", "fixed-weather"),
    "T4-parallel-weather": ("tool_calling_protected.py", "parallel-weather"),
    "T5-prebuilt-multiply": ("tool_calling_protected.py", "prebuilt-multiply"),
    "T6-return-direct": ("tool_calling_protected.py", "return-direct"),
    "T7-forced-tool": ("tool_calling_protected.py", "forced-tool"),
    "T8-serial-tools": ("tool_calling_protected.py", "serial-tools"),
    "T9-add-memory": ("persistence_protected.py", "add-memory"),
    "T10-time-travel": ("persistence_protected.py", "time-travel"),
}
NEW_DEMOS = ("D1-sql", "D2-rag", "D3-plan-execute", "D4-multi-agent", "D5-support")


def sha256(path: Path) -> str:
    return hashlib.sha256(path.read_bytes()).hexdigest()


def common_metadata() -> dict:
    tasks = V1 / "tasks.json"
    fixtures = [
        V1 / "fixtures/sql/Chinook.db",
        V1 / "fixtures/search/olympics.json",
        V1 / "fixtures/search/world-bank-gdp-2019-2023.json",
        V1 / "fixtures/customer-support/travel2.sqlite",
        *(V1 / item for item in json.loads(tasks.read_text())["D2"]["documents"]),
    ]
    scripts = [
        APPS / name
        for name in (
            "add_tools_protected.py",
            "tool_calling_protected.py",
            "persistence_protected.py",
            "sql_agent.py",
            "agentic_rag.py",
            "plan_execute.py",
            "multi_agent.py",
            "customer_support.py",
        )
    ]
    return {
        "protocol": "five paired repetition blocks; modes shuffled within each block",
        "shuffle_seed": SEED,
        "bootstrap_seed": SEED,
        "model": "qwen3:8b",
        "model_digest": "500a1f067a9f782620b40bee6f7b0c89e17ae61f686b92c24933e4ca4b2b8b41",
        "temperature": 0,
        "generation_seed": 20261005,
        "reasoning_effort": "none",
        "upstream_commit": "23961cff61a42b52525f3b20b4094d8d2fba1744",
        "task_digest": sha256(tasks),
        "fixture_digests": {str(path.relative_to(ROOT)): sha256(path) for path in fixtures},
        "source_digests": {str(path.relative_to(ROOT)): sha256(path) for path in scripts},
        "worker_route_digest": sha256(WORKER),
        "timeouts_seconds": {"D1-D3_and_T1-T10": 180, "D4-D5": 300},
        "primary_timer": "parent subprocess wall clock, including process startup",
    }


def command(job: Job, trial: Path, tasks: dict) -> tuple[list[str], int]:
    output = trial / "output.json"
    if job.application in OLD_DEMOS:
        script, demo = OLD_DEMOS[job.application]
        result = [sys.executable, str(APPS / script), "--mode", job.mode, "--output", str(output)]
        if script == "add_tools_protected.py":
            result.extend(
                (
                    "--prompt",
                    "You must use the search tool. Which city and country hosted the 1996 "
                    "Summer Olympics, and what currency did that country use at the time?",
                )
            )
        else:
            result.extend(("--demo", demo))
        timeout = 180
    elif job.application == "D1-sql":
        database = trial / "Chinook.db"
        shutil.copy2(V1 / tasks["D1"]["fixture"], database)
        result = [
            sys.executable,
            str(APPS / "sql_agent.py"),
            "--database",
            str(database),
            "--prompt",
            tasks["D1"]["tasks"][job.task - 1]["prompt"],
            "--events",
            str(trial / "events.jsonl"),
            "--output",
            str(output),
            "--mode",
            job.mode,
        ]
        timeout = 180
    elif job.application == "D2-rag":
        documents = [str(V1 / item) for item in tasks["D2"]["documents"]]
        result = [
            sys.executable,
            str(APPS / "agentic_rag.py"),
            "--documents",
            *documents,
            "--prompt",
            tasks["D2"]["tasks"][job.task - 1]["prompt"],
            "--output",
            str(output),
            "--mode",
            job.mode,
        ]
        timeout = 180
    elif job.application == "D3-plan-execute":
        year = tasks["D3"]["tasks"][job.task - 1]["year"]
        prompt = (
            f"For the Summer Olympics held in {year}, what was the host city, its country, "
            "and that country's currency at the time of the Games?"
        )
        result = [
            sys.executable,
            str(APPS / "plan_execute.py"),
            "--corpus",
            str(V1 / tasks["D3"]["corpus"]),
            "--prompt",
            prompt,
            "--output",
            str(output),
            "--mode",
            job.mode,
        ]
        timeout = 180
    elif job.application == "D4-multi-agent":
        country = tasks["D4"]["tasks"][job.task - 1]["country"]
        prompt = (
            f"Find the {country} annual GDP values for 2019 through 2023 in current US "
            "dollars and produce a line chart."
        )
        result = [
            sys.executable,
            str(APPS / "multi_agent.py"),
            "--gdp",
            str(V1 / tasks["D4"]["fixture"]),
            "--prompt",
            prompt,
            "--artifact",
            str(trial / "chart.png"),
            "--observer",
            str(trial / "observer.json"),
            "--output",
            str(output),
            "--mode",
            job.mode,
        ]
        timeout = 300
    else:
        result = [
            sys.executable,
            str(APPS / "customer_support.py"),
            "--source-database",
            str(V1 / "fixtures/customer-support/travel2.sqlite"),
            "--database",
            str(trial / "travel.sqlite"),
            "--notebook",
            str(V1 / "upstream/docs/docs/tutorials/customer-support/customer-support.ipynb"),
            "--faq",
            str(V1 / "fixtures/customer-support/swiss_faq.md"),
            "--task-id",
            str(job.task),
            "--output",
            str(output),
            "--mode",
            job.mode,
        ]
        timeout = 300
    if job.mode == "Argus" and job.application in OLD_DEMOS:
        result.extend(("--worker-route", str(WORKER)))
    return result, timeout


def ordered(answer: str, values: list[str]) -> bool:
    positions = [answer.casefold().find(value.casefold()) for value in values]
    return all(position >= 0 for position in positions) and positions == sorted(positions)


def old_correct(application: str, record: dict) -> bool:
    demo = OLD_DEMOS[application][1]
    answer = str(record.get("answer", "")).casefold()
    messages = json.dumps(record.get("messages", [])).casefold()
    checks = {
        "add-tools": all(item in answer for item in ("atlanta", "united states", "usd")),
        "custom-weather": "60" in answer and "foggy" in answer,
        "fixed-weather": "60" in messages and "foggy" in messages,
        "parallel-weather": all(item in messages for item in ("60", "foggy", "nyc", "sf")),
        "prebuilt-multiply": "294" in answer,
        "return-direct": answer.strip() == "8",
        "forced-tool": "hello bob" in answer,
        "serial-tools": all(item in messages for item in ('"8"', '"28"')),
        "add-memory": all(item in answer for item in ("united kingdom", "gbp")),
        "time-travel": bool(record.get("replayed"))
        and record.get("history_size", 0) >= 5
        and "london" in answer,
    }
    expected = {
        "add-tools": {"tavily_search"},
        "custom-weather": {"get_weather"},
        "fixed-weather": {"get_weather"},
        "parallel-weather": {"get_weather", "get_coolest_cities"},
        "prebuilt-multiply": {"multiply"},
        "return-direct": {"add"},
        "forced-tool": {"greet"},
        "serial-tools": {"add", "multiply"},
        "add-memory": {"tavily_search"},
        "time-travel": {"tavily_search"},
    }
    return checks[demo] and set(record.get("executed_tools", [])) == expected[demo]


def new_correct(job: Job, record: dict, trial: Path, tasks: dict) -> bool:
    answer = str(record.get("answer", ""))
    if job.application == "D1-sql":
        expected = tasks["D1"]["tasks"][job.task - 1]["expected"]
        if job.task == 1:
            return "3503" in answer.replace(",", "")
        if job.task == 2:
            return "sci fi & fantasy" in answer.casefold() and any(
                item in answer.replace(",", "") for item in ("2911783", "2911.783")
            )
        if job.task == 3:
            return ordered(answer, [str(row[0]) for row in expected]) and all(
                str(row[1]) in answer for row in expected
            )
        if job.task == 4:
            return ordered(answer, [str(row[0]) for row in expected]) and all(
                f"{row[1]:.2f}" in answer for row in expected
            )
        return ordered(answer, [str(row[1]) for row in expected]) and all(
            f"{row[3]:.2f}" in answer for row in expected
        )
    if job.application == "D2-rag":
        text = answer.casefold()
        required = {
            1: (
                "plan" in text and any(term in text for term in ("step", "subgoal", "decompos")),
                "memory" in text and any(term in text for term in ("retain", "store", "recall")),
                "tool" in text
                and any(term in text for term in ("external", "environment", "interact")),
            ),
            2: (
                "short-term" in text
                and any(term in text for term in ("immediate", "working", "current")),
                "long-term" in text
                and any(term in text for term in ("persist", "future", "beyond")),
            ),
            3: (
                "chain-of-thought" in text and any(term in text for term in ("step", "reason")),
                "self-consistency" in text
                and any(term in text for term in ("multiple", "sample", "consistent")),
            ),
            4: (
                "prompt injection" in text
                and any(term in text for term in ("adversarial", "manipulat", "subvert")),
                any(term in text for term in ("ordinary", "normal", "legitimate", "authorized"))
                and any(term in text for term in ("instruction", "request", "task")),
            ),
            5: (
                "reason" in text and any(term in text for term in ("act", "tool", "action")),
                "observation" in text and "reason" in text,
            ),
        }[job.task]
        return all(required)
    if job.application == "D3-plan-execute":
        expected = tasks["D3"]["tasks"][job.task - 1]["expected"]
        return all(str(item).casefold() in answer.casefold() for item in expected)
    if job.application == "D4-multi-agent":
        observer = trial / "observer.json"
        artifact = trial / "chart.png"
        if not observer.exists() or not artifact.exists() or artifact.stat().st_size == 0:
            return False
        lines = json.loads(observer.read_text()).get("lines", [])
        expected = tasks["D4"]["tasks"][job.task - 1]["expected"]
        return any(
            [str(item) for item in line.get("x", [])] == ["2019", "2020", "2021", "2022", "2023"]
            and len(line.get("y", [])) == len(expected)
            and all(
                abs(actual - wanted) <= max(1.0, abs(wanted) * 1e-9)
                for actual, wanted in zip(line["y"], expected, strict=True)
            )
            for line in lines
        )
    spec = tasks["D5"]["tasks"][job.task - 1]
    expected = spec["expected_flight_ids"]
    after = record.get("after", {})
    interrupts = record.get("interrupts", [])
    if after.get("flight_ids") != expected or after.get("owner") != tasks["D5"]["passenger_id"]:
        return False
    if job.task in {3, 4, 5}:
        return len(interrupts) == 1 and interrupts[0].get("approved") is spec["approval"]
    return not interrupts


def execute(job: Job, root: Path, tasks: dict) -> dict:
    trial = root / f"rep-{job.repetition}" / job.application / f"task-{job.task}" / job.mode
    trial.mkdir(parents=True, exist_ok=False)
    cmd, timeout = command(job, trial, tasks)
    output = trial / "output.json"
    started = time.perf_counter()
    timed_out = False
    try:
        completed = subprocess.run(
            cmd,
            cwd=ROOT,
            capture_output=True,
            text=True,
            timeout=timeout,
            check=False,
        )
        returncode = completed.returncode
        stdout, stderr = completed.stdout, completed.stderr
        wall_ms = (time.perf_counter() - started) * 1000
    except subprocess.TimeoutExpired as error:
        timed_out = True
        returncode = None
        stdout = (
            (error.stdout or b"").decode()
            if isinstance(error.stdout, bytes)
            else error.stdout or ""
        )
        stderr = (
            (error.stderr or b"").decode()
            if isinstance(error.stderr, bytes)
            else error.stderr or ""
        )
        wall_ms = timeout * 1000.0
    inner = json.loads(output.read_text()) if output.exists() else {}
    if timed_out:
        status = "timeout"
    elif returncode != 0:
        status = "compatibility_failed"
    elif inner.get("status") == "execution_error" or inner.get("error"):
        status = "execution_error"
    else:
        status = "completed"
    correct = False
    if status == "completed":
        correct = (
            old_correct(job.application, inner)
            if job.application in OLD_DEMOS
            else new_correct(job, inner, trial, tasks)
        )
    grants = inner.get("authorization_grants", [])
    lowerings = inner.get("lowering_records", inner.get("lowered_restrictions", []))
    broker = inner.get("broker_audit", [])
    security_evidence = bool(grants or lowerings or broker or inner.get("activation_receipts", []))
    record = {
        "application": job.application,
        "task": job.task,
        "repetition": job.repetition,
        "mode": job.mode,
        "status": status,
        "correct": correct,
        "wall_ms": wall_ms,
        "timeout_cap_seconds": timeout,
        "censored": timed_out,
        "returncode": returncode,
        "inner_wall_ms": inner.get("wall_ms"),
        "model_time_ms": inner.get("model_time_ms"),
        "model_calls": inner.get("model_calls"),
        "security_evidence": security_evidence,
        "grant_count": len(grants),
        "lowering_count": len(lowerings),
        "broker_record_count": len(broker),
        "command": cmd,
        "raw_output": str(output.relative_to(ROOT)) if output.exists() else None,
        "stdout": stdout,
        "stderr": stderr,
        "error": inner.get("error"),
    }
    if job.mode == "Baseline" and security_evidence:
        raise AssertionError(f"baseline unexpectedly produced security evidence: {job}")
    (trial / "trial.json").write_text(json.dumps(record, indent=2) + "\n")
    return record


def main() -> None:
    parser = argparse.ArgumentParser()
    parser.add_argument("--run-id", required=True)
    parser.add_argument("--repetitions", type=int, default=5)
    parser.add_argument("--smoke", action="store_true", help="one block and first task only")
    args = parser.parse_args()
    root = CAMPAIGN / "raw" / args.run_id
    root.mkdir(parents=True, exist_ok=False)
    tasks = json.loads((V1 / "tasks.json").read_text())
    metadata = common_metadata()
    metadata["run_id"] = args.run_id
    metadata["repetitions"] = 1 if args.smoke else args.repetitions
    (root / "configuration.json").write_text(json.dumps(metadata, indent=2) + "\n")

    records = []
    repetitions = range(1 if args.smoke else args.repetitions)
    applications = (*OLD_DEMOS, *NEW_DEMOS)
    for repetition in repetitions:
        jobs = []
        for application in applications:
            task_ids = (1,) if application in OLD_DEMOS or args.smoke else range(1, 6)
            jobs.extend(
                Job(application, task, repetition, mode)
                for task in task_ids
                for mode in MODES
            )
        random.Random(SEED + repetition).shuffle(jobs)
        for job in jobs:
            record = execute(job, root, tasks)
            records.append(record)
            print(
                f"{job.repetition} {job.application} {job.task} {job.mode}: "
                f"{record['status']} correct={record['correct']} {record['wall_ms']:.1f} ms",
                flush=True,
            )
    (root / "trials.json").write_text(json.dumps(records, indent=2) + "\n")


if __name__ == "__main__":
    main()
