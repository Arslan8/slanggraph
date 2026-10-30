"""Validate the matched Baseline/slangGraph Pandas campaign artifact."""

from __future__ import annotations

import argparse
import hashlib
import importlib.util
import json
from collections import Counter
from pathlib import Path

ROOT = Path(__file__).resolve().parents[3]


def _campaign():
    spec = importlib.util.spec_from_file_location(
        "trusted_pandas_campaign", ROOT / "eval/remaining/application_campaign.py"
    )
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


def _sha(path: Path) -> str:
    return hashlib.sha256(path.read_bytes()).hexdigest()


def validate(raw: Path) -> dict:
    trusted = _campaign()
    plan = json.loads((raw / "plan.json").read_text())
    preflight = json.loads((raw / "preflight.json").read_text())
    rows = [json.loads(line) for line in (raw / "trials.jsonl").read_text().splitlines()]
    issues: list[str] = []
    tasks = {case: (expected, case == "monthly_chart") for case, _, expected in trusted.TASKS}
    expected_keys = {
        (case, mode, repeat)
        for case in tasks
        for mode in ("Baseline", "slangGraph")
        for repeat in range(5)
    }
    keys = [(row["case_id"], row["mode"], row["repeat"]) for row in rows]
    if len(keys) != 100 or set(keys) != expected_keys:
        issues.append("Missing, duplicated, or unexpected task/condition/repetition rows")
    if plan["conditions"] != ["Baseline", "slangGraph"] or plan["repetitions"] != 5:
        issues.append("Plan does not identify the required matched 5x10x2 campaign")
    if plan["tasks"] != [list(task) for task in trusted.TASKS]:
        issues.append("Plan tasks differ from the trusted frozen task list")
    if preflight["common_settings_sha256"] != plan["common_settings_sha256"]:
        issues.append("Plan/preflight common-settings digests differ")
    for name, digest in plan["sources"].items():
        source = raw / "harness" / name
        if not source.is_file() or _sha(source) != digest:
            issues.append(f"Frozen harness source differs: {name}")

    successes = Counter()
    failures = Counter()
    timeout_count = 0
    for row in rows:
        run_id = row["run_id"]
        trial = raw / run_id
        mode = row["mode"]
        case = row["case_id"]
        expected, chart = tasks[case]
        output_path = trial / "output.json"
        output = json.loads(output_path.read_text()) if output_path.is_file() else {}
        oracle_match = trusted.oracle(output, expected, chart)
        if oracle_match != row["output_matches_oracle"]:
            issues.append(f"Recorded oracle result differs: {run_id}")
        legitimate = row["status"] == "completed" and oracle_match
        if legitimate != row["legitimate_result"]:
            issues.append(f"Recorded legitimate result differs: {run_id}")
        (successes if legitimate else failures)[(mode, case)] += 1
        timeout_count += row["status"] == "timeout"
        if row["fixture_sha256"] != plan["dataset"]["sha256"]:
            issues.append(f"Fixture digest differs: {run_id}")
        if row["common_settings_sha256"] != plan["common_settings_sha256"]:
            issues.append(f"Common-settings digest differs: {run_id}")
        if row["model"] != plan["model"]:
            issues.append(f"Model settings differ: {run_id}")
        if not row["source_hashes_unchanged_before_after"]:
            issues.append(f"Framework source identity changed: {run_id}")
        request = json.loads((trial / "request.json").read_text())
        events = [json.loads(line) for line in (trial / "events.jsonl").read_text().splitlines()]
        if mode == "Baseline":
            if request["configuration"] != "Baseline" or request["lean_worker"] is not None:
                issues.append(f"Baseline request enabled a protected configuration: {run_id}")
            forbidden = (
                "security.sqlite",
                "activation-receipts.json",
                "closed-inventory.json",
                "lowered-restrictions.json",
                "principal.cedar",
                "operator.cedar",
            )
            if any((trial / name).exists() for name in forbidden):
                issues.append(f"Baseline produced security activation evidence: {run_id}")
            evidence = row.get("baseline_security_evidence") or {}
            if not evidence or any(evidence.values()):
                issues.append(f"Baseline negative-control evidence differs: {run_id}")
            if any(
                event.get("kind") in {"dataset_authorize", "dispatch_result", "lifecycle_selection"}
                for event in events
            ):
                issues.append(f"Baseline contains a protected enforcement event: {run_id}")
        else:
            if request["configuration"] != "C-full-lean":
                issues.append(f"slangGraph request is not C-full-lean: {run_id}")
            required = (
                "security.sqlite",
                "activation-receipts.json",
                "closed-inventory.json",
                "principal.cedar",
                "operator.cedar",
            )
            if any(not (trial / name).is_file() for name in required):
                issues.append(f"Protected evidence is incomplete: {run_id}")
            receipts = trial / "activation-receipts.json"
            if row["computation_calls"] and (
                not receipts.is_file() or not json.loads(receipts.read_text())
            ):
                issues.append(f"Protected computation lacks activation receipt: {run_id}")
            if not any(event.get("kind") == "dataset_authorize" for event in events):
                issues.append(f"Protected dataset authorization is missing: {run_id}")

    if timeout_count:
        issues.append(f"Unexpected timeouts in completed artifact: {timeout_count}")
    expected_failures = Counter({("slangGraph", "monthly_mean"): 5})
    if failures != expected_failures:
        issues.append(f"Failure set differs: {dict(failures)}")
    if sum(successes.values()) != 95:
        issues.append(f"Expected 95 legitimate results, got {sum(successes.values())}")
    return {
        "passed": not issues,
        "trials": len(rows),
        "expected_trials": 100,
        "successes": {f"{mode}/{case}": count for (mode, case), count in successes.items()},
        "failures": {f"{mode}/{case}": count for (mode, case), count in failures.items()},
        "timeouts": timeout_count,
        "issues": issues,
        "checks": [
            "task/repetition pairing",
            "trusted task list and oracle replay",
            "common settings, model, fixture, and source identities",
            "Baseline negative security evidence",
            "slangGraph admission, policy, audit, and activation evidence",
            "retained protected non-finite refusals",
        ],
    }


if __name__ == "__main__":
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("raw", type=Path)
    parser.add_argument("--output", type=Path)
    arguments = parser.parse_args()
    result = validate(arguments.raw)
    rendered = json.dumps(result, indent=2) + "\n"
    if arguments.output:
        arguments.output.write_text(rendered)
    print(rendered, end="")
    raise SystemExit(0 if result["passed"] else 1)
