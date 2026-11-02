"""Recompute macOS campaign completeness, utility oracles, and native Lean traces."""

from __future__ import annotations

import argparse
import gzip
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


def native_journals(trial, checker, checker_digest):
    receipts, traces, lowerings = [], [], []
    for path in sorted(trial.glob("native-execution-*.json")):
        data = json.loads(path.read_text())
        receipts.extend(data["activation_receipts"])
        traces.extend(data["lifecycle_records"])
        lowerings.extend(data["lowering_records"])
    if len(receipts) != len(traces):
        raise ValueError("native receipt/lifecycle count mismatch")
    nonces = [item["nonce"] for item in receipts]
    if len(nonces) != len(set(nonces)):
        raise ValueError("duplicate native receipt nonce")
    by_nonce = {item["nonce"]: item for item in receipts}
    for trace in traces:
        if (
            trace["phase"] != "ready"
            or trace["cleanup_confirmed"] is not True
            or trace["object_route"] is not True
            or trace["checker_sha256"] != checker_digest
        ):
            raise ValueError("native lifecycle scope/identity mismatch")
        binding, certificate = trace["binding"], trace["certificate"]
        receipt = by_nonce[binding["nonce"]]
        if receipt["mode"] != "enforced" or not receipt["evidence"]:
            raise ValueError("native receipt is unenforced")
        for public, field in (
            ("nonce", "nonce"),
            ("context_digest", "context"),
            ("plan_digest", "plan"),
            ("host_digest", "host"),
            ("artifact_digest", "artifact"),
        ):
            if receipt[public] != binding[field]:
                raise ValueError(f"native receipt binding mismatch: {field}")
        if not any(
            item["object_grant_digest"] == receipt["grant_digest"]
            and item["native_grant_digest"] == binding["grant"]
            for item in lowerings
        ):
            raise ValueError("object/native grant correspondence missing")
        if any(
            rule["domain"] == "resource_limit" and rule["selector"] == "cpu_ms"
            for rule in certificate["grant"]["rules"]
        ):
            raise ValueError("unqualified CPU ceiling was certified")
        checker.require(
            binding, trace["events"], "ready", certificate=certificate, object_route=True
        )
    return len(traces)


def verify(folder):
    config = json.loads((folder / "configuration.json").read_text())
    mode = config.get("mode", "Baseline")
    if mode not in {"Baseline", "Argus"}:
        raise ValueError("unknown treatment")
    before = json.loads((folder / "source-before.json").read_text())
    after = json.loads((folder / "source-after.json").read_text())
    issues = []
    checker, checker_digest = None, None
    if mode == "Argus":
        from langgraph.prebuilt.security.lean_lifecycle import LeanLifecycleChecker

        host = json.loads((folder / "macos-host-configuration.json").read_text())
        checker_digest = host["lean"]["sha256"]
        checker = LeanLifecycleChecker(
            str(folder / "libargus_worker_route.dylib"),
            checker_digest,
            str(folder / "libleanshared.dylib"),
            host["lean"]["native_runtime_sha256"],
        )
        if sha(folder / "macos-launcher") != host["launcher"]["launcher_digest"]:
            issues.append("native launcher identity mismatch")
    if not before or before != after:
        issues.append("source drift")
    for name, digest in before.items():
        path = folder / "sources" / digest
        if not path.is_file() or sha(path) != digest:
            if (
                name == "eval/campaigns/langgraph-demos-v1/fixtures/customer-support/travel2.sqlite"
                and digest == "7646259e80230dc9bd92914466e13874bba82f461473d6a66552e819898eb66b"
            ):
                compressed = folder / "sources" / before.get(name + ".gz", "missing")
                if compressed.is_file():
                    with gzip.open(compressed, "rb") as stream:
                        data = stream.read(114442241)
                    if len(data) == 114442240 and hashlib.sha256(data).hexdigest() == digest:
                        continue
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
        if row["mode"] != mode or (mode == "Baseline" and row["security_evidence"]):
            issues.append(f"{key}: treatment mismatch")
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
                and (
                    (proof is not None and not any(proof.values()))
                    if mode == "Baseline"
                    else bool(json.loads((trial / "activation-receipts.json").read_text()))
                    if (trial / "activation-receipts.json").is_file()
                    else False
                )
            )
            if mode == "Baseline" and any(
                (trial / name).exists()
                for name in ("security.sqlite", "activation-receipts.json", "closed-inventory.json")
            ):
                issues.append(f"{key}: baseline security artifacts present")
        else:
            trial = folder / "demos" / f"rep-{repeat}" / app / f"task-{row['task']}" / mode
            output = trial / "output.json"
            value = json.loads(output.read_text()) if output.exists() else {}
            job = demos.Job(app, row["task"], repeat, mode)
            correct = (
                row["status"] == "completed"
                and row["returncode"] == 0
                and (
                    demos.old_correct(app, value)
                    if app in demos.OLD_DEMOS
                    else demos.new_correct(job, value, trial, tasks)
                )
            )
            if mode == "Baseline" and any(
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
        calls = 0
        if mode == "Argus":
            try:
                if app == "Pandas":
                    evidence_folder = (
                        folder / "native-evidence" / "pandas" / f"rep-{repeat}" / row["case_id"]
                    )
                else:
                    evidence_folder = (
                        folder
                        / "native-evidence"
                        / "demos"
                        / f"rep-{repeat}"
                        / app
                        / f"task-{row['task']}"
                        / mode
                    )
                calls = native_journals(evidence_folder, checker, checker_digest)
                public_receipts = value.get("activation_receipts", [])
                if app == "Pandas" and (trial / "activation-receipts.json").is_file():
                    public_receipts = json.loads((trial / "activation-receipts.json").read_text())
                if public_receipts and not calls:
                    raise ValueError("native lifecycle evidence missing for delivered results")
            except (ValueError, KeyError, TypeError, PermissionError) as exc:
                issues.append(f"{key}: invalid native evidence: {exc}")
        results[app].append((row, bool(correct), calls))
    summary = {}
    for app, values in sorted(results.items()):
        summary[app] = dict(
            attempted=len(values),
            correct=sum(correct for _, correct, _ in values),
            successful_protected_calls=sum(calls for _, _, calls in values),
            trials_with_successful_protected_calls=sum(calls > 0 for _, _, calls in values),
            statuses=dict(Counter(row["status"] for row, _, _ in values)),
            mean_wall_ms=statistics.fmean(
                row.get("analysis_wall_ms", row["wall_ms"]) for row, _, _ in values
            ),
        )
    return dict(
        evidence_valid=not issues,
        issues=issues,
        attempted=len(observations),
        correct=sum(value["correct"] for value in summary.values()),
        applications=summary,
        baseline_only=mode == "Baseline",
        protected_application_evaluation=mode == "Argus",
        successful_protected_calls=sum(
            value["successful_protected_calls"] for value in summary.values()
        ),
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
