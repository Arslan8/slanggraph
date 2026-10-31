"""Recompute baseline completeness and frozen application oracles from raw output."""

from __future__ import annotations

import argparse
import hashlib
import importlib.util
import json
import math
import statistics
import sys
from collections import Counter, defaultdict
from pathlib import Path

ROOT = Path(__file__).resolve().parents[2]


def load(name, path):
    spec = importlib.util.spec_from_file_location(name, path)
    module = importlib.util.module_from_spec(spec)
    sys.modules[name] = module
    spec.loader.exec_module(module)
    return module


def sha(path):
    return hashlib.sha256(path.read_bytes()).hexdigest()


def verify(folder):
    config = json.loads((folder / "configuration.json").read_text())
    before = json.loads((folder / "source-before.json").read_text())
    after = json.loads((folder / "source-after.json").read_text())
    issues = []
    if not before or before != after:
        issues.append("source drift")
    for name, digest in before.items():
        path = folder / "sources" / digest
        if not path.is_file() or sha(path) != digest:
            issues.append(f"source archive missing or changed: {name}")
    for copy, original in (
        ("demo_campaign.py", "eval/campaigns/langgraph-demos-v3/run_campaign.py"),
        ("application_campaign.py", "eval/remaining/application_campaign.py"),
        ("pandas-manifest.json", "eval/apps/pandas/policy/manifest-v22-full.json"),
    ):
        if sha(folder / "harness" / copy) != before[original]:
            issues.append(f"oracle/configuration copy changed: {copy}")
    demos = load("verify_demo_oracles", folder / "harness/demo_campaign.py")
    pandas = load("verify_pandas_oracles", folder / "harness/application_campaign.py")
    tasks_digest = before["eval/campaigns/langgraph-demos-v1/tasks.json"]
    tasks = json.loads((folder / "sources" / tasks_digest).read_text())
    observations = [json.loads(line) for line in (folder / "trials.jsonl").read_text().splitlines()]
    expected = []
    for repeat in range(config["repetitions"]):
        if config["only"] != "pandas":
            expected.extend(
                (app, task, repeat)
                for app in (*demos.OLD_DEMOS, *demos.NEW_DEMOS)
                for task in ((1,) if app in demos.OLD_DEMOS or config["pilot"] else range(1, 6))
            )
        if config["only"] != "demos":
            selected = [pandas.TASKS[5]] if config["pilot"] else pandas.TASKS
            expected.extend(("Pandas", task[0], repeat) for task in selected)
    actual = [
        (row["application"], row.get("task", row.get("case_id")), row["repetition"])
        for row in observations
    ]
    if Counter(expected) != Counter(actual):
        issues.append("missing/duplicate/extra observations")
    if not config["pilot"] and config["repetitions"] != 5:
        issues.append("full campaign requires five repetitions")
    tags = json.loads((folder / "models.json").read_text())
    if config[
        "model_digest"
    ] != "500a1f067a9f782620b40bee6f7b0c89e17ae61f686b92c24933e4ca4b2b8b41" or not any(
        row["name"] == "qwen3:8b" and row["digest"] == config["model_digest"]
        for row in tags["models"]
    ):
        issues.append("model identity mismatch")
    results = defaultdict(list)
    pandas_tasks = {case: (prompt, wanted) for case, prompt, wanted in pandas.TASKS}
    for row in observations:
        app, repeat = row["application"], row["repetition"]
        key = f"{app}/{row.get('task', row.get('case_id'))}/{repeat}"
        if row["mode"] != "Baseline" or row["security_evidence"]:
            issues.append(f"{key}: protected execution mixed into baseline")
        if not math.isfinite(row["wall_ms"]) or row["wall_ms"] <= 0:
            issues.append(f"{key}: invalid timing")
        if app == "Pandas":
            case = row["case_id"]
            trial = folder / "pandas" / f"rep-{repeat}" / case
            output = trial / "output.json"
            value = json.loads(output.read_text()) if output.exists() else {}
            matched = pandas.oracle(value, pandas_tasks[case][1], case == "monthly_chart")
            evidence = trial / "baseline-security-evidence.json"
            proof = json.loads(evidence.read_text()) if evidence.exists() else None
            correct = (
                row["status"] == "completed"
                and row["returncode"] == 0
                and matched
                and proof is not None
                and not any(proof.values())
            )
            if any(
                (trial / name).exists()
                for name in ("security.sqlite", "activation-receipts.json", "closed-inventory.json")
            ):
                issues.append(f"{key}: baseline security artifacts present")
        else:
            trial = folder / "demos" / f"rep-{repeat}" / app / f"task-{row['task']}" / "Baseline"
            output = trial / "output.json"
            value = json.loads(output.read_text()) if output.exists() else {}
            job = demos.Job(app, row["task"], repeat, "Baseline")
            correct = (
                row["status"] == "completed"
                and row["returncode"] == 0
                and (
                    demos.old_correct(app, value)
                    if app in demos.OLD_DEMOS
                    else demos.new_correct(job, value, trial, tasks)
                )
            )
            if any(
                value.get(field)
                for field in (
                    "authorization_grants",
                    "activation_receipts",
                    "lowering_records",
                    "broker_audit",
                )
            ):
                issues.append(f"{key}: raw security evidence in baseline")
        if bool(correct) != row["correct"]:
            issues.append(f"{key}: correctness disagrees with raw output")
        if json.loads((trial / "trial.json").read_text()) != row:
            issues.append(f"{key}: trial record mismatch")
        results[app].append((row, bool(correct)))
    summary = {}
    for app, values in sorted(results.items()):
        summary[app] = dict(
            attempted=len(values),
            correct=sum(correct for _, correct in values),
            statuses=dict(Counter(row["status"] for row, _ in values)),
            mean_wall_ms=statistics.fmean(
                row.get("analysis_wall_ms", row["wall_ms"]) for row, _ in values
            ),
        )
    return dict(
        evidence_valid=not issues,
        issues=issues,
        attempted=len(observations),
        correct=sum(value["correct"] for value in summary.values()),
        applications=summary,
        baseline_only=True,
        protected_application_parity=False,
        cross_os_speedup_claim=False,
    )


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("folder", type=Path)
    args = parser.parse_args()
    try:
        report = verify(args.folder.resolve())
    except (OSError, ValueError, KeyError, TypeError, IndexError) as exc:
        report = dict(
            evidence_valid=False, issues=[f"incomplete evidence: {type(exc).__name__}: {exc}"]
        )
    (args.folder / "verification.json").write_text(
        json.dumps(report, sort_keys=True, indent=2) + "\n"
    )
    print(json.dumps(report, sort_keys=True))
    raise SystemExit(0 if report["evidence_valid"] else 1)


if __name__ == "__main__":
    main()
