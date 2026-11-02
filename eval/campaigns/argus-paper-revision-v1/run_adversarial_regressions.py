"""Run the implementation-boundary regressions used by the revision ledger."""

from __future__ import annotations

import argparse
import hashlib
import json
import re
import subprocess
import sys
import time
from pathlib import Path

ROOT = Path(__file__).resolve().parents[3]
PROJECT = ROOT / "libs/prebuilt"
GROUPS = {
    "authorization_to_resource": (
        ["tests/security/test_mediation.py", "-k", "rebinding_after_authorization"],
        "mutated request/principal bindings require a fresh decision",
    ),
    "filesystem_identity": (
        [
            "tests/security/test_linux_resource_resolution.py",
            "tests/security/test_language_file_binding.py",
            "-k",
            "ancestor_replaced or hard_link_alias or symlink_swap or postpin or initial_alias",
        ],
        "legacy positive witness reads the replacement; descriptor route refuses or "
        "retains the pinned object",
    ),
    "worker_startup": (
        [
            "tests/security/test_object_broker.py",
            "-k",
            "no_direct_socket or import_time_effect or no_grant_means_no_broker_authority",
        ],
        "live listener/import effect and broker authority are independently observed",
    ),
    "child_processes": (
        [
            "tests/security/test_native_async_lifetime.py",
            "-k",
            "direct_landlock_without_cgroup_forbids_descendant_creation",
        ],
        "fork/thread controls reach creation without the filter; protected workers "
        "cannot create descendants",
    ),
    "controller_guardian": (
        [
            "tests/security/test_native_async_lifetime.py",
            "-k",
            "repeated_cancellation_waits_for_child_exit and Landlock",
        ],
        "cancellation is repeated and worker lifetime is checked independently",
    ),
    "reused_contexts": (
        [
            "tests/security/test_verification_contextvars.py",
            "-k",
            "restored_value_does_not_inherit_replacement_grant",
        ],
        "restored context is a positive carrier but cannot retain replacement authority",
    ),
    "parallel_execution": (
        [
            "tests/security/test_tool_node_security.py",
            "tests/security/test_concurrency.py",
            "-k",
            "parallel_tool_dispatch_records_one_identity_transfer or thousand_parallel",
        ],
        "two ToolNode modes plus 1,000 sync and 1,000 async calls check identity uniqueness",
    ),
    "admission_framework": (
        [
            "tests/security/test_admission.py",
            "tests/security/test_checkpoint_placement.py",
            "-k",
            "unsupported_node_bodies_refuse or recheck_refuses_replaced or "
            "tampered_checkpoint or replayed_checkpoint",
        ],
        "allowed framework shapes execute; modified bodies/artifacts and invalid "
        "history refuse before use",
    ),
}


def digest(path: Path) -> str:
    return hashlib.sha256(path.read_bytes()).hexdigest()


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--output", type=Path, required=True)
    args = parser.parse_args()
    args.output.mkdir(parents=True, exist_ok=False)
    records = []
    for name, (selection, control) in GROUPS.items():
        command = [sys.executable, "-m", "pytest", "-q", *selection]
        started = time.time_ns()
        result = subprocess.run(
            command,
            cwd=PROJECT,
            check=False,
            text=True,
            stdout=subprocess.PIPE,
            stderr=subprocess.STDOUT,
        )
        log = args.output / f"{name}.log"
        log.write_text(result.stdout)
        matches = re.findall(r"(\d+) passed", result.stdout)
        records.append(
            {
                "boundary": name,
                "control_and_oracle": control,
                "command": command,
                "started_ns": started,
                "ended_ns": time.time_ns(),
                "returncode": result.returncode,
                "passed": int(matches[-1]) if matches else 0,
                "log": log.name,
                "log_sha256": digest(log),
            }
        )
        print(f"{name}: returncode={result.returncode} passed={records[-1]['passed']}")
    summary = {
        "schema": 1,
        "distinct_investigations": sum(item["passed"] for item in records),
        "scheduling_trials": 2000,
        "all_passed": all(item["returncode"] == 0 for item in records),
        "groups": records,
    }
    (args.output / "summary.json").write_text(json.dumps(summary, indent=2) + "\n")
    return 0 if summary["all_passed"] else 1


if __name__ == "__main__":
    raise SystemExit(main())
