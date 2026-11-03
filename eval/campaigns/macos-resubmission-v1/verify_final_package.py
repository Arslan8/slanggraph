"""Verify committed checksums and core macOS acceptance counts."""

from __future__ import annotations

import argparse
import csv
import gzip
import hashlib
import json
import tarfile
from pathlib import Path

HERE = Path(__file__).resolve().parent


def verify(folder: Path) -> dict:
    issues = []
    checked = 0
    for line in (folder / "SHA256SUMS").read_text().splitlines():
        if not line:
            continue
        digest, name = line.split("  ", 1)
        path = folder / name
        if path.resolve().parent != folder.resolve() or not path.is_file():
            issues.append(f"missing or escaped artifact: {name}")
            continue
        if hashlib.sha256(path.read_bytes()).hexdigest() != digest:
            issues.append(f"artifact digest differs: {name}")
        checked += 1
    acceptance = json.loads((folder / "acceptance.json").read_text())
    for name in (
        "cross-host-common-verification.json",
        "common-source-equivalence.json",
        "common-cpu-verification.json",
        "security-verification.json",
        "advanced-verification.json",
        "filesystem-identity-finding.json",
        "cancellation-witness-verification.json",
        "pandas-verification.json",
        "application-regressions.json",
    ):
        report = json.loads((folder / name).read_text())
        if report.get("evidence_valid", report.get("passed")) is not True:
            issues.append(f"invalid report: {name}")
    common = json.loads((folder / "cross-host-common-verification.json").read_text())
    if common["distinct_common_cases"] != 45 or common["selected_trials_per_host"] != 450:
        issues.append("common matrix count differs")
    mapping = json.loads((folder / "cross-host-common-cases.json").read_text())
    with (folder / "cross-host-common-cases.csv").open(newline="") as source:
        csv_rows = list(csv.DictReader(source))
    if [row["macos_case_id"] for row in mapping["rows"]] != [
        row["macos_case_id"] for row in csv_rows
    ]:
        issues.append("CSV and JSON case mapping differ")
    for name, expected in (
        ("security-trials.jsonl.gz", 580),
        ("common-cpu-trials.jsonl.gz", 10),
        ("advanced-trials.jsonl.gz", 126),
        ("before-fix-aliases.jsonl.gz", 6),
        ("per-process-trials.jsonl.gz", 2),
        ("cancellation-witness-trials.jsonl.gz", 6),
        ("pandas-trials.jsonl.gz", 50),
        ("app-baseline-trials.jsonl.gz", 175),
        ("app-argus-trials.jsonl.gz", 175),
    ):
        with gzip.open(folder / name, "rt") as source:
            count = sum(1 for _ in source)
        if count != expected:
            issues.append(f"raw trial count differs: {name}: {count}")
    with gzip.open(folder / "common-cpu-trials.jsonl.gz", "rt") as source:
        cpu_rows = [json.loads(line) for line in source]
    for repeat in range(5):
        control = next(
            row
            for row in cpu_rows
            if row["repetition"] == repeat and row["condition"] == "Unprotected"
        )
        protected = next(
            row for row in cpu_rows if row["repetition"] == repeat and row["condition"] == "Argus"
        )
        if control["before"]["records"]["bob"] == control["after"]["records"]["bob"]:
            issues.append(f"CPU control did not change Bob: {repeat}")
        lowerings = [
            item
            for dispatcher in protected["evidence"]["dispatchers"]
            for item in dispatcher["lowering"]
        ]
        if not any(
            item.get("decision") == "unsupported" and item.get("tool_released") is False
            for item in lowerings
        ):
            issues.append(f"CPU requirement did not refuse before execution: {repeat}")
    for condition in ("baseline", "argus"):
        name = f"app-{condition}-verification.json"
        report = json.loads((folder / name).read_text())
        if report.get("evidence_valid") is not True or report.get("attempted") != 175:
            issues.append(f"incomplete application cohort: {name}")
        if acceptance.get("application_correctness", {}).get(f"{condition}_correct") != report.get(
            "correct"
        ):
            issues.append(f"acceptance correctness differs: {name}")
        with tarfile.open(folder / f"app-{condition}-outputs.tar.gz", "r:gz") as bundle:
            names = bundle.getnames()
        if len([name for name in names if name.endswith("/trial.json")]) != 175:
            issues.append(f"portable trial outputs incomplete: {condition}")
    if json.loads((folder / "app-baseline-sources.json").read_text()) != json.loads(
        (folder / "app-argus-sources.json").read_text()
    ):
        issues.append("application cohort source inventories differ")
    if acceptance.get("application_correctness", {}).get("pandas_correct") != 50:
        issues.append("Pandas final cohort count differs")
    return {"evidence_valid": not issues, "checked_artifacts": checked, "issues": issues}


if __name__ == "__main__":
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("folder", type=Path, nargs="?", default=HERE)
    args = parser.parse_args()
    result = verify(args.folder)
    print(json.dumps(result, indent=2, sort_keys=True))
    raise SystemExit(0 if result["evidence_valid"] else 1)
