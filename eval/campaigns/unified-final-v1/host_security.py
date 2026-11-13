"""Adapter from the frozen cross-host attack harness to unified records."""

from __future__ import annotations

import json
import os
import subprocess
import sys
from pathlib import Path
from typing import Any

from campaign import HERE, ROOT, append_jsonl, load_config

UPSTREAM = ROOT / "eval/campaigns/cross-host-security-v2"
CHECKER = ROOT / "proofs/worker-route/.lake/build/lib/libargus_worker_route.so"


def _manifest(result: Path) -> dict[str, Any]:
    path = result / "host_cases.json"
    return json.loads(path.read_text() if path.exists() else (HERE / "host_cases.json").read_text())


def _cases(result: Path, backend: str) -> list[str]:
    return [case["id"] for case in _manifest(result)["cases"] if case.get(backend) is True]


def _verified(run: Path) -> dict[str, Any]:
    completed = subprocess.run(
        [sys.executable, str(UPSTREAM / "verify.py"), str(run)],
        cwd=UPSTREAM,
        capture_output=True,
        text=True,
        check=False,
    )
    if completed.returncode:
        raise RuntimeError(
            f"host-security evidence verification failed: {completed.stderr or completed.stdout}"
        )
    result = json.loads(completed.stdout)
    if result.get("evidence_valid") is not True:
        raise RuntimeError(f"host-security evidence invalid: {result}")
    return result


def _records(
    result: Path,
    backend: str,
    verification: dict[str, Any],
) -> list[dict[str, Any]]:
    prepared = json.loads((result / "prepared.json").read_text())
    obligations = {case["id"]: case["obligation"] for case in _manifest(result)["cases"]}
    rows = []
    for item in verification["classified"]:
        category = item["category"]
        allowed = item["allowed_success"] is not None
        outcome = (
            "allowed"
            if category == "Enforced" and allowed
            else "prevented"
            if category == "Enforced"
            else "rejected"
            if category == "Rejected before execution"
            else "failed"
            if category == "Failed"
            else "inconclusive"
        )
        rows.append(
            {
                "schema_version": 1,
                "campaign_id": prepared["campaign_id"],
                "config_id": prepared["config_id"],
                "build_id": prepared["build_id"],
                "backend": backend,
                "case": item["case"],
                "repetition": item["repetition"],
                "applicable": True,
                "outcome": outcome,
                "oracle_passed": category in {"Enforced", "Rejected before execution"},
                "source_category": category,
                "positive_control_passed": item["control_effect"],
                "excluded_from_prevention_counts": category == "Inconclusive",
                "obligation": obligations[item["case"]],
                "reason": item["reason"],
                "protected_entered": item["protected_entered"],
                "protected_forbidden_effect": item["protected_forbidden_effect"],
                "allowed_success": item["allowed_success"],
                "source_evidence": "cross-host-security-v2",
            }
        )
    return rows


def collect_linux(result: Path) -> dict[str, Any]:
    """Run and verify every Linux-applicable case five times."""
    config = load_config(result / "configuration.json")
    output = result / "host-security" / "linux"
    cases = _cases(result, "linux")
    command = [
        sys.executable,
        str(UPSTREAM / "run.py"),
        "--output",
        str(output),
        "--repetitions",
        str(config["evaluations"][1]["repetitions_per_case"]),
        "--jobs",
        "3",
        "--cases",
        *cases,
    ]
    environment = {**os.environ, "ARGUS_LIFECYCLE_CHECKER": str(CHECKER)}
    completed = subprocess.run(command, cwd=UPSTREAM, env=environment, check=False)
    if completed.returncode:
        raise RuntimeError(f"Linux host-security harness exited {completed.returncode}")
    verification = _verified(output)
    rows = _records(result, "linux", verification)
    append_jsonl(result / "host-security.jsonl", rows)
    return {
        "backend": "linux",
        "cases": len(cases),
        "records": len(rows),
        "categories": verification["categories"],
        "passed": verification["evidence_valid"],
    }
