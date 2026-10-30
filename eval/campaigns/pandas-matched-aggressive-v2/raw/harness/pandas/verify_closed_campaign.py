"""Recompute C-closed cohort acceptance from preserved outputs and identities.

Mirrors `eval/remaining/verify_pandas_campaign.py` for the single C-closed
condition and adds closed-route checks per trial: the recorded inventory covers
all four graphs with the pinned declarations and only admitted kinds, the
dataset was read once through `dataset_read` with the pinned digest, the Lean
selection is the cohort's captured binary, and every trial that computed has
activation receipts. Utility is judged by the trusted unchanged oracle imported
from `eval/remaining/application_campaign.py`, never by recorded flags.

    python eval/apps/pandas/verify_closed_campaign.py COHORT [--expect-repetitions 5]

Writes `verification.json` into COHORT only if it does not exist.
"""

import argparse
import ast
import hashlib
import importlib.util
import inspect
import json
from collections import Counter
from pathlib import Path

ROOT = Path(__file__).resolve().parents[3]
MODE = "C-closed"
GRAPHS = ("pandas_data_analyst", "data_wrangling_agent", "data_visualization_agent")
ROUTE_SOURCES = (
    "libs/prebuilt/langgraph/prebuilt/security/_linux_worker.py",
    "libs/prebuilt/langgraph/prebuilt/security/admission.py",
    "libs/prebuilt/langgraph/prebuilt/security/config.py",
    "libs/prebuilt/langgraph/prebuilt/security/dataset_operation.py",
    "libs/prebuilt/langgraph/prebuilt/security/enforcement.py",
    "libs/prebuilt/langgraph/prebuilt/security/host_boundary.py",
    "libs/prebuilt/langgraph/prebuilt/security/landlock.py",
    "libs/prebuilt/langgraph/prebuilt/security/lean_grant.py",
    "libs/prebuilt/langgraph/prebuilt/security/lean_lifecycle.py",
    "libs/prebuilt/langgraph/prebuilt/security/linux.py",
    "libs/prebuilt/langgraph/prebuilt/security/placement.py",
)
REQUIRED_HARNESS = {
    "application_campaign.py",
    "pandas/backend_closed.py",
    "pandas/closed_campaign.py",
    "pandas/integration_closed.py",
    "pandas/sandbox_codec.py",
    "pandas/worker.py",
    "pandas/workflow_contract.py",
}


def _trusted_campaign():
    spec = importlib.util.spec_from_file_location(
        "trusted_application_campaign", ROOT / "eval/remaining/application_campaign.py"
    )
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


def _sha(path: Path) -> str:
    return hashlib.sha256(path.read_bytes()).hexdigest()


def _trial_checks(trial: Path, plan: dict, row: dict, issues: list) -> None:
    run_id = row["run_id"]
    inventory_path = trial / "closed-inventory.json"
    if not inventory_path.is_file():
        issues.append(f"Closed inventory missing: {run_id}")
    else:
        recorded = {g["graph"]: g["descriptors"] for g in json.loads(inventory_path.read_text())}
        if set(recorded) != {*GRAPHS, "compute_dispatch"}:
            issues.append(f"Closed inventory graph set differs: {run_id}")
        for graph in GRAPHS:
            declared = plan["trusted_declarations"][graph]
            descriptors = recorded.get(graph, [])
            nodes = sorted(d["name"] for d in descriptors if d["kind"] == "trusted_application")
            branches = sorted(
                d["name"] for d in descriptors if d["kind"] == "trusted_application_branch"
            )
            if (
                nodes != sorted(declared["nodes"])
                or branches != sorted(declared["branches"])
                or len(descriptors) != len(nodes) + len(branches)
                or any(len(d["identity"]) != 64 for d in descriptors)
            ):
                issues.append(f"Closed inventory differs from declarations: {run_id}/{graph}")
        dispatch = recorded.get("compute_dispatch", [])
        if [d["name"] for d in dispatch] != ["dispatch"] or any(
            d["kind"].startswith("trusted_application") for d in dispatch
        ):
            issues.append(f"Compute dispatch inventory differs: {run_id}")
    events_path = trial / "events.jsonl"
    events = (
        [json.loads(line) for line in events_path.read_text().splitlines()]
        if events_path.is_file()
        else []
    )
    reads = [e for e in events if e.get("kind") == "dataset_read"]
    grants = [e for e in events if e.get("kind") == "dataset_authorize"]
    if (
        len(reads) != 1
        or reads[0]["sha256"] != plan["dataset"]["sha256"]
        or [g["verdict"] for g in grants] != ["allow"]
    ):
        issues.append(f"dataset_read evidence differs: {run_id}")
    request = json.loads((trial / "request.json").read_text())
    fixture = Path(request["dataset"]["path"])
    if not fixture.is_file() or _sha(fixture) != plan["dataset"]["sha256"]:
        issues.append(f"Trial fixture differs from pin: {run_id}")
    if request["lean_worker"] != plan["lean_worker"] or request.get(
        "state_normalization"
    ) != plan.get("state_normalization"):
        issues.append(f"Trial request differs from plan: {run_id}")
    selection = trial / "lifecycle-selection.json"
    if not selection.is_file() or json.loads(selection.read_text()) != plan["lean_worker"]:
        issues.append(f"Lean selection record differs: {run_id}")
    computations = sum(e.get("kind") == "computation" for e in events)
    if computations != row["computation_calls"]:
        issues.append(f"Recorded computation count differs: {run_id}")
    receipts = trial / "activation-receipts.json"
    if computations and (not receipts.is_file() or not json.loads(receipts.read_text())):
        issues.append(f"Computation without activation receipts: {run_id}")


def verify(folder: Path, expect_repetitions: int) -> dict:
    trusted = _trusted_campaign()
    plan = json.loads((folder / "plan.json").read_text())
    frozen = ast.parse((folder / "harness/application_campaign.py").read_text())
    functions = [n for n in frozen.body if isinstance(n, ast.FunctionDef) and n.name == "oracle"]
    issues = []
    if not (
        len(functions) == 1
        and ast.dump(functions[0]) == ast.dump(ast.parse(inspect.getsource(trusted.oracle)).body[0])
    ):
        issues.append("Frozen oracle differs from the trusted unchanged utility oracle")
    if plan["conditions"] != [MODE] or plan["repetitions"] != expect_repetitions:
        issues.append("Plan conditions or repetitions differ from the expected cohort")
    if plan["tasks"] != [list(task) for task in trusted.TASKS]:
        issues.append("Plan task set differs from the frozen oracle")
    if not REQUIRED_HARNESS.issubset(plan["sources"]):
        issues.append("Required harness source identities are missing")
    for name, digest in plan["sources"].items():
        source = folder / "harness" / name
        if not source.is_file() or _sha(source) != digest:
            issues.append(f"Harness source identity mismatch: {name}")
    worker = folder / "workerRoute"
    if (
        not worker.is_file()
        or _sha(worker) != plan["lean_worker"]["sha256"]
        or plan["lean_worker"]["binary"] != str(worker.resolve())
    ):
        issues.append("Captured Lean worker differs from its pin")
    framework = json.loads((folder / "framework-sources.json").read_text())
    source_sha256 = {name: framework.get(name) for name in ROUTE_SOURCES}
    if None in source_sha256.values():
        issues.append("Route source identities are missing")
    actual = {
        str(p.relative_to(folder / "framework")) for p in (folder / "framework").rglob("*.py")
    }
    if actual != set(framework):
        issues.append("Framework inventory differs from the retained source tree")
    for name, digest in framework.items():
        blob = folder / "framework-source-blobs" / digest
        source = folder / "framework" / name
        if (
            not blob.is_file()
            or _sha(blob) != digest
            or not source.is_file()
            or _sha(source) != digest
        ):
            issues.append(f"Framework source identity mismatch: {name}")
    rows = [json.loads(line) for line in (folder / "trials.jsonl").read_text().splitlines()]
    tasks = {case: (expected, case == "monthly_chart") for case, _, expected in trusted.TASKS}
    expected_keys = {(case, MODE, r) for case in tasks for r in range(expect_repetitions)}
    keys = [(row["case_id"], row["mode"], row["repeat"]) for row in rows]
    if len(keys) != len(expected_keys) or set(keys) != expected_keys:
        issues.append("Missing, duplicate or unexpected trials")
    passed = Counter()
    by_task = Counter()
    failures = []
    for row in rows:
        case, repeat = row["case_id"], row["repeat"]
        trial = folder / row["run_id"]
        if row["run_id"] != f"{case}-{MODE}-{repeat}" or case not in tasks:
            issues.append(f"Trial identity mismatch: {row['run_id']}")
            continue
        expected, chart = tasks[case]
        output = (
            json.loads((trial / "output.json").read_text())
            if (trial / "output.json").exists()
            else {}
        )
        match = trusted.oracle(output, expected, chart)
        if row["status"] == "completed" and row["exit_status"] == 0 and match:
            passed[MODE] += 1
            by_task[case] += 1
        else:
            failures.append(row["run_id"])
        if row["output_matches_oracle"] != match:
            issues.append(f"Recorded oracle result differs: {row['run_id']}")
        before = json.loads((trial / "framework-sources-before.json").read_text())
        after = json.loads((trial / "framework-sources-after.json").read_text())
        if before != framework or after != framework or row["framework_sources"] != framework:
            issues.append(f"Per-trial framework identity differs: {row['run_id']}")
        if row["model"] != plan["model"]:
            issues.append(f"Model configuration differs: {row['run_id']}")
        _trial_checks(trial, plan, row, issues)
    return {
        "passed": not issues and not failures,
        "trials": len(rows),
        "expected_trials": len(expected_keys),
        "passes_by_configuration": dict(passed),
        "passes_by_task": {case: by_task[case] for case in tasks},
        "failures": failures,
        "issues": issues,
        "source_sha256": source_sha256,
        "scope": (
            "Frozen pandas utility cohort for C-closed only; closed-admission inventory, "
            "dataset_read and compute-route evidence checked per trial; no security or "
            "performance completeness claim"
        ),
    }


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("folder", type=Path)
    parser.add_argument("--expect-repetitions", type=int, default=5)
    args = parser.parse_args()
    report = verify(args.folder.resolve(), args.expect_repetitions)
    with (args.folder / "verification.json").open("x") as stream:
        stream.write(json.dumps(report, indent=2) + "\n")
    print(json.dumps({k: report[k] for k in ("passed", "trials", "passes_by_configuration")}))
    raise SystemExit(0 if report["passed"] else 1)


if __name__ == "__main__":
    main()
