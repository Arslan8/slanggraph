"""Verify a complete macOS Pandas C-full-lean cohort without changing its oracle."""

from __future__ import annotations

import argparse
import ast
import hashlib
import importlib.util
import json
from collections import Counter
from pathlib import Path

ROOT = Path(__file__).resolve().parents[2]
MANIFEST = ROOT / "eval/campaigns/macos-resubmission-v1/macos-pandas-runtime-manifest.json"


def sha(path: Path) -> str:
    return hashlib.sha256(path.read_bytes()).hexdigest()


def load_oracle(path: Path):
    spec = importlib.util.spec_from_file_location("frozen_pandas_oracle", path)
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


def named_node(tree: ast.Module, name: str):
    for node in tree.body:
        if isinstance(node, (ast.FunctionDef, ast.AsyncFunctionDef)) and node.name == name:
            return node
        if isinstance(node, ast.Assign) and any(
            isinstance(target, ast.Name) and target.id == name for target in node.targets
        ):
            return node
    raise ValueError(f"missing frozen definition: {name}")


def verify(folder: Path) -> dict:
    issues = []
    plan = json.loads((folder / "plan.json").read_text())
    frozen_oracle = folder / "harness/application_campaign.py"
    trusted_oracle = ROOT / "eval/remaining/application_campaign.py"
    frozen_ast = ast.parse(frozen_oracle.read_text())
    current_ast = ast.parse(trusted_oracle.read_text())
    for name in ("TASKS", "ROWS", "oracle"):
        if ast.dump(named_node(frozen_ast, name)) != ast.dump(named_node(current_ast, name)):
            issues.append(f"frozen {name} differs from trusted source")
    trusted = load_oracle(trusted_oracle)
    if plan["conditions"] != ["C-full-lean"] or plan["repetitions"] != 5 or plan["pilot"]:
        issues.append("not the complete pinned C-full-lean cohort")
    if plan["tasks"] != [list(task) for task in trusted.TASKS]:
        issues.append("task definitions changed")
    if plan["fixture"] != trusted.ROWS:
        issues.append("fixture changed")
    if plan["manifest_sha256"] != sha(MANIFEST):
        issues.append("runtime manifest changed")
    for name, digest in plan["sources"].items():
        if sha(folder / "harness" / name) != digest:
            issues.append(f"harness source changed: {name}")
    framework = json.loads((folder / "framework-sources.json").read_text())
    if (
        plan["framework_sources_sha256"]
        != hashlib.sha256(json.dumps(framework, sort_keys=True).encode()).hexdigest()
    ):
        issues.append("framework inventory digest changed")
    for name, digest in framework.items():
        if (
            sha(folder / "framework" / name) != digest
            or sha(folder / "framework-source-blobs" / digest) != digest
        ):
            issues.append(f"framework source changed: {name}")
    rows = [json.loads(line) for line in (folder / "trials.jsonl").read_text().splitlines()]
    expected = {
        (case, repeat) for case, _, _ in trusted.TASKS for repeat in range(plan["repetitions"])
    }
    actual = [(row["case_id"], row["repeat"]) for row in rows]
    if len(actual) != len(expected) or set(actual) != expected:
        issues.append("missing, duplicate, or extra trials")
    tasks = {case: target for case, _, target in trusted.TASKS}
    correct = Counter()
    status = Counter()
    activated = 0
    for row in rows:
        case, repeat = row["case_id"], row["repeat"]
        if case not in tasks:
            continue
        trial = folder / f"{case}-C-full-lean-{repeat}"
        if row["run_id"] != trial.name:
            issues.append(f"trial identity changed: {case}/{repeat}")
            continue
        if row["model"] != plan["model"] or row["mode"] != "C-full-lean":
            issues.append(f"model or mode changed: {trial.name}")
        before = json.loads((trial / "framework-sources-before.json").read_text())
        after = json.loads((trial / "framework-sources-after.json").read_text())
        if before != framework or after != framework or row["framework_sources"] != framework:
            issues.append(f"source drift: {trial.name}")
        output = (
            json.loads((trial / "output.json").read_text())
            if (trial / "output.json").exists()
            else {}
        )
        matches = trusted.oracle(output, tasks[case], case == "monthly_chart")
        if matches != row["output_matches_oracle"]:
            issues.append(f"oracle record differs: {trial.name}")
        if row["status"] == "completed" and row["exit_status"] == 0 and matches:
            correct[case] += 1
        status[row["status"]] += 1
        events = [json.loads(line) for line in (trial / "events.jsonl").read_text().splitlines()]
        if not any(
            e.get("kind") == "dataset_read" and e.get("sha256") == plan["dataset"]["sha256"]
            for e in events
        ):
            issues.append(f"pinned dataset read missing: {trial.name}")
        receipts_path = trial / "activation-receipts.json"
        receipts = json.loads(receipts_path.read_text()) if receipts_path.exists() else []
        if row["status"] == "completed" and not receipts:
            issues.append(f"activation evidence missing: {trial.name}")
        if any(
            receipt.get("mode") != "enforced" or not receipt.get("evidence") for receipt in receipts
        ):
            issues.append(f"unenforced receipt: {trial.name}")
        activated += len(receipts)
        if row["status"] == "completed" and not (trial / "security.sqlite").is_file():
            issues.append(f"audit database missing: {trial.name}")
    return {
        "evidence_valid": not issues,
        "complete": len(actual) == len(expected) and set(actual) == expected,
        "trials": len(rows),
        "correct": sum(correct.values()),
        "correct_by_case": dict(correct),
        "status": dict(status),
        "activated_receipts": activated,
        "issues": issues,
        "scope": "macOS-only complete Pandas cohort; no performance or cross-host claim",
    }


def main() -> None:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("folder", type=Path)
    args = parser.parse_args()
    try:
        result = verify(args.folder.resolve())
    except (OSError, ValueError, KeyError, TypeError) as error:
        result = {"evidence_valid": False, "issues": [str(error)]}
    print(json.dumps(result, indent=2, sort_keys=True))
    raise SystemExit(0 if result["evidence_valid"] else 1)


if __name__ == "__main__":
    main()
