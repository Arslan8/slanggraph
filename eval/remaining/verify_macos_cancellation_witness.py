"""Check the three independent cancellation lifecycle witnesses."""

from __future__ import annotations

import argparse
import json
from pathlib import Path


def verify(root: Path) -> dict:
    rows = []
    issues = []
    for seed in range(3):
        pair = root / f"pending_cancellation-{seed}"
        control = json.loads((pair / "Unprotected/result.json").read_text())
        protected = json.loads((pair / "Argus/result.json").read_text())
        outcome = protected["outcome"]
        record_events = [
            item
            for item in protected["after"]["events"]
            if item["resource"] == "record" and item["operation"] == "read"
        ]
        startup = [item for item in protected["evidence"]["startup"] if not item.get("preflight")]
        checks = {
            "control_read_alice": control["markers"]["alice"] in json.dumps(control["outcome"]),
            "resource_read_logged": len(record_events) == 1
            and record_events[0]["selector"] == "notes/alice",
            "bob_unchanged": protected["before"]["records"]["bob"]
            == protected["after"]["records"]["bob"],
            "cancellation_observed": outcome.get("cancelled") is True,
            "authorized_operation_completed": outcome.get("resource_invocation_finished") is True,
            "graph_result_not_released": outcome.get("graph_result_released") is False,
            "internal_result_accepted": outcome.get("internal_result_accepted") is True,
            "worker_terminated": outcome.get("worker_terminated") is True,
            "guardian_terminated": outcome.get("guardian_terminated") is True,
            "native_identity_recorded": len(startup) == 1
            and startup[0].get("worker_start") is not None
            and startup[0].get("guardian_start") is not None,
        }
        issues.extend(f"seed {seed}: {name}" for name, passed in checks.items() if not passed)
        rows.append({"seed": seed, "checks": checks, "outcome": outcome})
    return {
        "evidence_valid": not issues,
        "distinct_cases": 1,
        "paired_repetitions": len(rows),
        "classification": "qualified: authorized operation completed during cancellation",
        "rows": rows,
        "issues": issues,
    }


def main() -> None:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("folder", type=Path)
    args = parser.parse_args()
    result = verify(args.folder)
    print(json.dumps(result, indent=2, sort_keys=True))
    raise SystemExit(0 if result["evidence_valid"] else 1)


if __name__ == "__main__":
    main()
