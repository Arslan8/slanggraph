"""Verify 45 behavior-matched cases and five macOS pairs per case."""

from __future__ import annotations

import gzip
import json
import subprocess
import sys
from collections import Counter
from pathlib import Path

ROOT = Path(__file__).resolve().parents[2]
CAMPAIGN = ROOT / "eval/campaigns/macos-resubmission-v1"
sys.path.insert(0, str(Path(__file__).resolve().parent))
from build_macos_cross_host_mapping import LINUX, LINUX_ROOT, build  # noqa: E402


def portable(path: Path) -> list[dict]:
    with gzip.open(path, "rt") as source:
        return [json.loads(line) for line in source]


def git_portable(name: str) -> list[dict]:
    data = subprocess.check_output(["git", "show", f"{LINUX}:{LINUX_ROOT}/{name}"], cwd=ROOT)
    return [json.loads(line) for line in gzip.decompress(data).splitlines()]


def verify() -> dict:
    recorded = json.loads((CAMPAIGN / "cross-host-common-cases.json").read_text())
    generated = build()
    issues = []
    if recorded != generated:
        issues.append("mapping differs from pinned source and macOS evidence")
    mac_main = portable(CAMPAIGN / "security-trials.jsonl.gz")
    mac_cpu = portable(CAMPAIGN / "common-cpu-trials.jsonl.gz")
    linux_main = git_portable("main-trials.jsonl.gz")
    linux_sessions = git_portable("session-trials.jsonl.gz")
    linux_cpu = git_portable("per-process-cpu-trials.jsonl.gz")
    mac_classified = {
        (item["case"], item["repetition"]): item
        for item in json.loads((CAMPAIGN / "security-verification.json").read_text())["classified"]
    }
    mac_classified.update(
        {
            (item["case"], item["repetition"]): item
            for item in json.loads((CAMPAIGN / "common-cpu-verification.json").read_text())[
                "classified"
            ]
        }
    )
    observed = Counter()
    for row in recorded["rows"]:
        case = row["macos_case_id"]
        mac = mac_cpu if case == "required_per_process_cpu" else mac_main
        linux = (
            linux_cpu
            if case == "required_per_process_cpu"
            else linux_sessions
            if case.startswith("session_")
            else linux_main
        )
        for repeat in range(5):
            for condition in ("Unprotected", "Argus"):
                mac_hits = [
                    item
                    for item in mac
                    if (item["case"], item["repetition"], item["condition"])
                    == (case, repeat, condition)
                ]
                linux_hits = [
                    item
                    for item in linux
                    if (item["case"], item["repetition"], item["condition"])
                    == (case, repeat, condition)
                ]
                if len(mac_hits) != 1 or len(linux_hits) != 1:
                    issues.append(f"{case}/{repeat}/{condition}: missing or duplicate evidence")
                else:
                    observed[condition] += 1
            classification = mac_classified.get((case, repeat))
            if classification is None or classification["control_effect"] is not True:
                issues.append(f"{case}/{repeat}: unprotected effect not demonstrated")
            elif row["macos_outcome_five_repetitions"].get(classification["category"], 0) < 1:
                issues.append(f"{case}/{repeat}: protected classification differs")
    return {
        "evidence_valid": not issues,
        "linux_revision": LINUX,
        "distinct_common_cases": len(recorded["rows"]),
        "macos_paired_repetitions": 5,
        "selected_trials_per_host": sum(observed.values()),
        "selected_macos_conditions": dict(observed),
        "protected_outcomes": dict(
            Counter(
                category
                for row in recorded["rows"]
                for category, count in row["macos_outcome_five_repetitions"].items()
                for _ in range(count)
            )
        ),
        "issues": issues,
    }


if __name__ == "__main__":
    result = verify()
    print(json.dumps(result, indent=2, sort_keys=True))
    raise SystemExit(0 if result["evidence_valid"] else 1)
