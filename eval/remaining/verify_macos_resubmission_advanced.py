"""Check supplemental macOS attack/control pairs against retained resource state."""

from __future__ import annotations

import argparse
import json
import sqlite3
import sys
from collections import Counter
from pathlib import Path

CAMPAIGN = Path(__file__).resolve().parents[1] / "campaigns/macos-resubmission-v1"
sys.path.insert(0, str(CAMPAIGN))
from advanced import CASES  # noqa: E402


def visible(outcome: dict, marker: str) -> bool:
    text = json.dumps(outcome)
    return marker in text or marker.encode().hex() in text.lower()


def message(result: dict) -> str:
    outcome = result["outcome"]
    return str(outcome.get("message", {}).get("content", outcome.get("reason", "")))


def sqlite_rows(path: Path) -> dict:
    with sqlite3.connect(path.as_uri() + "?mode=ro&immutable=1", uri=True) as connection:
        return dict(connection.execute("SELECT key,value FROM records"))


def check_sources(folder: Path, row: dict) -> None:
    for stage in ("before", "after"):
        if sqlite_rows(folder / f"database-{stage}.sqlite") != row[stage]["records"]:
            raise ValueError(f"SQLite snapshot mismatch: {folder}/{stage}")
    target = row["target"]
    if Path(target["path"]).read_bytes().hex() != target["bytes"]:
        raise ValueError(f"target bytes changed: {folder}")
    events = folder / "resource-events.jsonl"
    retained = (
        [json.loads(line) for line in events.read_text().splitlines()] if events.exists() else []
    )
    if retained[: len(row["after"]["events"])] != row["after"]["events"]:
        raise ValueError(f"resource event log differs: {folder}")


def classify(control: dict, protected: dict) -> tuple[str, str]:
    case = protected["case"]
    private = protected["markers"]["private"]
    bob = protected["markers"]["bob"]
    credential = protected["markers"]["credential"]
    if protected["before"]["records"]["bob"] != protected["after"]["records"]["bob"]:
        return "Failed", "Bob's SQLite row changed"
    if any(visible(protected["outcome"], value) for value in (private, bob, credential)):
        return "Failed", "private marker appeared in protected response"
    if case.startswith("race_") or case == "private_alias":
        if not visible(control["outcome"], control["markers"]["private"]):
            return "Inconclusive", "unprotected alias did not read the private inode"
        if "required_authority_removed" not in message(protected):
            return "Failed", "object-identity refusal missing"
        if protected["evidence"]["resource_invocations"]:
            return "Failed", "worker reached mediator after refusal"
        return "Enforced", "private inode read in control; protected release refused"
    if case == "inherited_fd":
        if not visible(control["outcome"], control["markers"]["private"]):
            return "Inconclusive", "inherited-FD control could not read marker"
        return (
            ("Enforced", "worker inherited no private descriptor")
            if "Bad file descriptor" in message(protected)
            else ("Failed", "descriptor refusal missing")
        )
    if case == "inherited_env":
        if not visible(control["outcome"], control["markers"]["credential"]):
            return "Inconclusive", "environment control lacked credential"
        return (
            ("Enforced", "credential absent from worker environment")
            if '"read": null' in message(protected)
            else ("Failed", "credential environment result differs")
        )
    if case == "startup_inventory":
        try:
            inventory = json.loads(message(protected))
            control_inventory = json.loads(control["outcome"]["stdout"])
        except ValueError:
            return "Failed", "worker startup inventory unavailable"
        if (
            "ARGUS_TEST_CREDENTIAL" not in control_inventory.get("environment_names", [])
            or len(control_inventory.get("fds", [])) <= 3
        ):
            return "Inconclusive", "startup control lacked injected authority"
        if inventory.get("fds") != [0, 1, 2, 3] or inventory.get("environment_names") != []:
            return "Failed", "unexpected worker startup authority"
        return "Enforced", "bounded descriptor and environment inventory"
    if case == "mach_inventory":
        return "Inconclusive", "Mach names retained; right semantics need separate validation"
    if case in {"signal_controller", "signal_guardian"}:
        if not control["evidence"]["signals"]:
            return "Inconclusive", "unprotected signal was not observed"
        if protected["evidence"]["signals"] or "PermissionError" not in message(protected):
            return "Failed", "protected signal was not refused"
        return "Enforced", "signal blocked with independent controller observation"
    if case == "debug_controller":
        return "Inconclusive", "task_for_pid failed in both conditions"
    if case in {"child_channel", "import_side_effect"}:
        if control["before"]["records"]["bob"] == control["after"]["records"]["bob"]:
            return "Inconclusive", "unprotected control did not change Bob"
        return "Enforced", "Bob unchanged in protected SQLite copy"
    if case in {"artifact_changed", "direct_node", "nested_entry"}:
        if not visible(control["outcome"], control["markers"]["alice"]):
            return "Inconclusive", "unprotected body did not read Alice"
        expected = (
            "artifact_changed" if case == "artifact_changed" else "admission:unsupported_node_body"
        )
        return (
            ("Enforced", "admission refused before resource effect")
            if expected in str(protected["outcome"])
            else ("Failed", "admission refusal missing")
        )
    if case == "parallel_confusion":
        responses = protected["outcome"].get("results", [])
        invocations = [
            row
            for row in protected["evidence"]["resource_invocations"]
            if row["line"]["class_name"] == "record"
        ]
        if len(responses) != 8 or not invocations:
            return "Inconclusive", "parallel batch incomplete"
        if any(
            row["line"]["selector"] != "notes/alice" or row["context"]["principal_id"] != "alice"
            for row in invocations
        ):
            return "Failed", "mediator confused selector or principal"
        return "Enforced", "eight calls; mediator records only Alice's bound selector"
    if case == "pending_cancellation":
        if not protected["outcome"].get("cancelled"):
            return "Failed", "graph cancellation not observed"
        return (
            "Inconclusive",
            "mediator completed; graph worker completion not independently verified",
        )
    if case in {"suspended_worker", "suspended_guardian"}:
        if not visible(protected["outcome"], protected["markers"]["alice"]):
            return "Failed", "Alice read failed after controlled suspension"
        return "Qualified", "SIGSTOP/SIGCONT completed; this is not host sleep/wake"
    if case == "optional_permission":
        grants = protected["evidence"].get("grants", [])
        if not grants or any(line["selector"] == "notes/bob" for line in grants[0]["lines"]):
            return "Failed", "optional Bob permission survived authorization"
        return "Qualified", "Cedar omitted want; no lowerer tightening observed"
    return "Inconclusive", "no classifier for case"


def verify(root: Path, repetitions: int) -> dict:
    results = []
    issues = []
    for seed in range(repetitions):
        for case in CASES:
            pair = []
            for mode in ("Unprotected", "Argus"):
                folder = root / f"{case}-{seed}" / mode
                row = json.loads((folder / "result.json").read_text())
                if (row["case"], row["seed"], row["condition"]) != (case, seed, mode):
                    raise ValueError(f"trial identity mismatch: {folder}")
                check_sources(folder, row)
                pair.append(row)
            category, reason = classify(*pair)
            results.append(dict(case=case, seed=seed, category=category, reason=reason))
            if category == "Failed":
                issues.append(f"{case}/{seed}: {reason}")
    return dict(
        evidence_valid=not issues,
        distinct_cases=len(CASES),
        paired_trials=len(results),
        categories=dict(Counter(item["category"] for item in results)),
        results=results,
        issues=issues,
    )


def main() -> None:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("folder", type=Path)
    parser.add_argument("--repetitions", type=int, default=3)
    args = parser.parse_args()
    try:
        result = verify(args.folder.resolve(), args.repetitions)
    except (OSError, ValueError, KeyError, TypeError) as error:
        result = {"evidence_valid": False, "issues": [str(error)]}
    print(json.dumps(result, indent=2, sort_keys=True))
    raise SystemExit(0 if result["evidence_valid"] else 1)


if __name__ == "__main__":
    main()
