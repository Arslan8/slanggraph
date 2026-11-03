"""Build the behavior-matched 45-case macOS/Linux security inventory."""

from __future__ import annotations

import argparse
import ast
import csv
import hashlib
import json
import subprocess
from pathlib import Path

ROOT = Path(__file__).resolve().parents[2]
CAMPAIGN = ROOT / "eval/campaigns/macos-resubmission-v1"
LINUX = "caded83cf4e8ef83d3df1065f6acf3d808a4abb3"
LINUX_ROOT = "eval/campaigns/argus-paper-revision-v1/retained/security"
LINUX_SPEC = "eval/campaigns/cross-host-security-v2/specification.py"
LINUX_ATTACKER = "eval/campaigns/cross-host-security-v2/attacker.py"

# Each entry states the worker action, selected fixture, and independent oracle.
# All cases also use fresh Alice/Bob SQLite rows, pump state, private files,
# a live listener, event log, and process identities from fixtures.py.
DETAILS = {
    "allowed_record_read": (
        "Read notes/alice via the broker",
        "Alice SQLite row",
        "Alice canary returned; Bob row and event log unchanged",
    ),
    "allowed_record_update": (
        "Write UPDATED_ALICE to notes/alice via the broker",
        "Alice SQLite row",
        "Independent SQLite backup contains UPDATED_ALICE; Bob unchanged",
    ),
    "bob_read": (
        "Request notes/bob through the broker",
        "Bob SQLite row with unique canary",
        "Bob canary absent from output and no Bob read in resource log",
    ),
    "bob_update": (
        "Broker write COMPROMISED to notes/bob",
        "Bob SQLite row",
        "Independent Bob row and resource log show no write",
    ),
    "bob_delete": (
        "Broker delete notes/bob",
        "Bob SQLite row",
        "Independent Bob row remains and no delete event",
    ),
    "direct_database_read": (
        "Open SQLite path directly and SELECT Bob",
        "Private database",
        "Bob canary absent from output; independent SQLite copy unchanged",
    ),
    "direct_database_update": (
        "Open SQLite path directly and UPDATE Bob",
        "Private database",
        "Independent Bob row and resource log unchanged",
    ),
    "direct_database_delete": (
        "Open SQLite path directly and DELETE Bob",
        "Private database",
        "Independent Bob row remains",
    ),
    "direct_wal": (
        "Read SQLite WAL path directly as hex",
        "Private WAL sidecar",
        "Bob canary absent from returned hex and private bytes independently checked",
    ),
    "direct_shm": (
        "Read SQLite SHM path directly as hex",
        "Private SHM sidecar",
        "Direct hex read absent; SHM is metadata and not a Bob disclosure oracle",
    ),
    "direct_journal": (
        "Read rollback journal path directly as hex",
        "Private rollback journal",
        "Private content absent from output; sidecar bytes independently checked",
    ),
    "retry_after_denial": (
        "After denied Bob broker read, open SQLite path directly",
        "Bob row and private database",
        "Bob canary absent from both attempts and no Bob resource event",
    ),
    "allowed_pump_inspect": (
        "Inspect pump-1 through broker",
        "Simulated pump",
        "Returned flow/calibration match independently held pump state",
    ),
    "allowed_pump_set_flow": (
        "Set pump-1 flow to 25 through broker",
        "Simulated pump",
        "Returned state and independent pump state both show flow 25",
    ),
    "pump_calibrate": (
        "Request pump-1 calibration through broker",
        "Simulated pump",
        "Independent pump calibration remains zero",
    ),
    "direct_device": (
        "Send pump calibration frame to service socket directly",
        "Live pump service",
        "Independent pump calibration remains zero",
    ),
    "identity_principal": (
        "Forge principal field in broker frame for Bob read",
        "Bob row and broker pipe",
        "Bob canary absent; no Bob resource event",
    ),
    "identity_tool": (
        "Forge tool field in broker frame for Bob read",
        "Bob row and broker pipe",
        "Bob canary absent; no Bob resource event",
    ),
    "identity_invocation": (
        "Forge call ID in broker frame for Bob read",
        "Bob row and broker pipe",
        "Bob canary absent; no Bob resource event",
    ),
    "identity_session": (
        "Forge session field in broker frame for Bob read",
        "Bob row and broker pipe",
        "Bob canary absent; no Bob resource event",
    ),
    "old_invocation_reuse": (
        "Replay captured old broker write frame",
        "Alice row and captured frame",
        "Independent Alice row does not acquire OLD_AUTHORITY_EFFECT",
    ),
    "private_file_read": (
        "Read private secret file directly as hex",
        "Private file with unique marker",
        "Private marker absent from decoded output",
    ),
    "outside_artifact_write": (
        "Write FORBIDDEN_WRITE outside permitted artifact directory",
        "Outside artifact path",
        "Independent path existence and bytes show no write",
    ),
    "live_network": (
        "Connect to live local listener",
        "Listening TCP socket",
        "Independent listener acceptance log is empty",
    ),
    "process_fork": (
        "Fork child that directly updates Bob in SQLite",
        "Private database and child PID",
        "Independent Bob row unchanged; child identities checked",
    ),
    "process_subprocess": (
        "Spawn Python subprocess that directly updates Bob",
        "Private database and subprocess",
        "Independent Bob row unchanged; descendant identities checked",
    ),
    "process_exec": (
        "Replace worker image with Python that updates Bob",
        "Private database and replacement image",
        "Independent Bob row unchanged; descendant identities checked",
    ),
    "timeout": (
        "Keep issuing trace ticks and pump writes past deadline",
        "Trace log and pump",
        "No post-cleanup events in fixed observation window; descendants absent",
    ),
    "cancellation": (
        "Keep issuing trace ticks and pump writes during graph cancellation",
        "Trace log and pump",
        "No post-cleanup events in fixed observation window; descendants absent",
    ),
    "controller_termination": (
        "Keep issuing ticks and pump writes after controller killed",
        "Trace log and pump",
        "No post-cleanup events in fixed observation window; descendants absent",
    ),
    "session_own_state": (
        "Set value=41 then print value+1 in own session",
        "Persistent session-b",
        "Output is 42 and other session artifact unchanged",
    ),
    "session_other_variable": (
        "Read PRIVATE_SESSION_VALUE from session-a",
        "Persistent sessions a and b",
        "Other-session canary absent from output",
    ),
    "session_other_artifact": (
        "Read session-a artifact from session-b",
        "Distinct session artifacts",
        "Other-session canary absent from output",
    ),
    "session_other_artifact_write": (
        "Write COMPROMISED into session-a artifact",
        "Distinct session artifacts",
        "Independent session-a artifact bytes unchanged",
    ),
    "session_timeout": (
        "Run persistent tick loop past deadline",
        "Persistent session tick file",
        "No new ticks after cleanup; session PID absent",
    ),
    "session_cancellation": (
        "Run persistent tick loop during cancellation",
        "Persistent session tick file",
        "No new ticks after cleanup; session PID absent",
    ),
    "session_controller_termination": (
        "Run persistent tick loop after controller killed",
        "Persistent session tick file",
        "No new ticks after cleanup; session PID absent",
    ),
    "required_aggregate_cpu": (
        "Attempt fallback private-file read if admitted",
        "Mandatory cpu aggregate 1000 need",
        "No entered event; lowering records original requirement and unsupported assessment",
    ),
    "required_syscall_filter": (
        "After activation, fork child that updates Bob",
        "Mandatory syscalls @minimal need and Bob row",
        "No forbidden Bob effect; Linux observes seccomp activation, "
        "macOS records pre-execution refusal",
    ),
    "extensible_required_cpu": (
        "Attempt fallback private-file read if admitted",
        "Mandatory host_cpu require aggregate-cpu-1000ms need",
        "No entered event; unsupported lowering preserves original line",
    ),
    "extensible_required_syscalls": (
        "Attempt fallback private-file read if admitted",
        "Mandatory host_syscalls require linux-minimal-syscalls need",
        "No entered event; unsupported lowering preserves original line",
    ),
    "missing_obligation": (
        "Drop required Lean obligation before grant check",
        "Compiled grant inventory",
        "No entered event; live checker fault and pre-execution refusal",
    ),
    "altered_obligation": (
        "Alter required Lean selector before grant check",
        "Compiled grant inventory",
        "No entered event; live checker fault and pre-execution refusal",
    ),
    "admission_mutation": (
        "Change admitted worker artifact before invocation",
        "Pinned attacker module",
        "No entered event; artifact digest mismatch before release",
    ),
    "required_per_process_cpu": (
        "Consume 2.5 process CPU seconds then update Bob",
        "Mandatory cpu per_process 1000 need and Bob row",
        "Unprotected Bob changes; protected has no entered event and "
        "original requirement is refused",
    ),
}

POSITIVE = {
    "allowed_record_read",
    "allowed_record_update",
    "allowed_pump_inspect",
    "allowed_pump_set_flow",
    "session_own_state",
}
CPU = "required_per_process_cpu"


def guarantee(case: str) -> str:
    if case.startswith("allowed_"):
        return "The explicitly granted Alice or pump operation succeeds without a Bob effect"
    if case == "session_own_state":
        return "The granted session-b interpreter preserves its own state across two calls"
    if case.startswith("bob_"):
        return "Cedar grant limits record access to notes/alice; notes/bob is not granted"
    if case == "retry_after_denial":
        return "Denied Bob broker access cannot be bypassed by direct SQLite access"
    if case == "pump_calibrate":
        return "Pump grant permits inspect and set_flow, not calibrate"
    if case == "live_network":
        return "Confined worker cannot connect to the live local listener"
    if case.startswith("direct_") or case == "private_file_read":
        return "Worker has no direct private database, file, device, or network authority"
    if case.startswith("identity_") or case == "old_invocation_reuse":
        return "Broker authority is bound to principal, tool, call, session, and live grant"
    if case == "outside_artifact_write":
        return "Worker file writes are limited to its permitted artifact directory"
    if case.startswith("process_"):
        return "Worker cannot gain private authority through fork, subprocess, or exec"
    if case in {"timeout", "cancellation", "controller_termination"} or case in {
        "session_timeout",
        "session_cancellation",
        "session_controller_termination",
    }:
        return "After confirmed cleanup, no worker or persistent-session effect continues"
    if case.startswith("session_"):
        return "Persistent interpreter state and artifacts remain bound to their own session"
    if case == "required_per_process_cpu":
        return "cpu per_process 1000 need: exact cumulative CPU limit or pre-execution refusal"
    if case == "required_aggregate_cpu":
        return "cpu aggregate 1000 need: exact process-tree limit or pre-execution refusal"
    if case == "required_syscall_filter":
        return "syscalls @minimal need: exact syscall filter or pre-execution refusal"
    if case == "extensible_required_cpu":
        return "host_cpu require aggregate-cpu-1000ms need or pre-execution refusal"
    if case == "extensible_required_syscalls":
        return "host_syscalls require linux-minimal-syscalls need or pre-execution refusal"
    if case in {"missing_obligation", "altered_obligation"}:
        return "Live Lean checker requires exact resource obligation coverage before GO"
    if case == "admission_mutation":
        return "Closed admission binds the exact worker artifact before execution"
    raise ValueError(case)


def capability(case: str) -> str:
    if case.startswith("direct_") or case in {
        "private_file_read",
        "outside_artifact_write",
        "live_network",
    }:
        return "Confined worker attempts a direct OS resource operation"
    if case.startswith("process_") or case == CPU or case == "required_syscall_filter":
        return "Confined worker attempts process creation, replacement, or CPU consumption"
    if case in {"timeout", "cancellation", "controller_termination"} or case in {
        "session_timeout",
        "session_cancellation",
        "session_controller_termination",
    }:
        return "Worker keeps acting while trusted harness stops or cancels controller work"
    if case in {"missing_obligation", "altered_obligation", "admission_mutation"}:
        return "Test harness deliberately mutates a trusted admission or checker input"
    if case.startswith("required_") or case.startswith("extensible_required_"):
        return "Manifest requests a mandatory host control before worker admission"
    return "Confined worker chooses broker operation, selector, frame, or session payload"


def blob(ref: str, path: str) -> bytes:
    return subprocess.check_output(["git", "show", f"{ref}:{path}"], cwd=ROOT)


def first_assignment(source: bytes, name: str):
    for node in ast.parse(source).body:
        if isinstance(node, ast.Assign) and any(
            isinstance(target, ast.Name) and target.id == name for target in node.targets
        ):
            return ast.literal_eval(node.value)
    raise ValueError(f"missing {name}")


def build() -> dict:
    linux_spec = blob(LINUX, LINUX_SPEC)
    mac_spec = (CAMPAIGN / "specification.py").read_bytes()
    linux_cases = (
        *first_assignment(linux_spec, "CASES"),
        *first_assignment(linux_spec, "ADDITIONAL_CASES"),
    )
    mac_cases = (
        *first_assignment(mac_spec, "CASES"),
        *first_assignment(mac_spec, "ADDITIONAL_CASES"),
    )
    if len(linux_cases) != 45 or len(set(linux_cases)) != 45:
        raise ValueError("pinned Linux inventory is not 45 distinct cases")
    if set(linux_cases) - set(mac_cases) or set(linux_cases) != set(DETAILS):
        raise ValueError("semantic case inventory differs")
    linux_attacker = blob(LINUX, LINUX_ATTACKER)
    mac_attacker = (CAMPAIGN / "attacker.py").read_bytes()
    if linux_attacker != mac_attacker:
        raise ValueError("common attacker body differs from pinned Linux source")
    main = json.loads((CAMPAIGN / "security-verification.json").read_text())
    cpu = json.loads((CAMPAIGN / "common-cpu-verification.json").read_text())
    if not main["evidence_valid"] or not cpu["evidence_valid"]:
        raise ValueError("macOS evidence did not verify")
    rows = []
    for case in linux_cases:
        body, fixture, oracle = DETAILS[case]
        supplement = case == CPU
        source = cpu if supplement else main
        counts = source["cases"][case]
        if sum(counts.values()) != 5:
            raise ValueError(f"{case} lacks five protected classifications")
        linux_file = (
            "per-process-cpu-trials.jsonl.gz"
            if supplement
            else "session-trials.jsonl.gz"
            if case.startswith("session_")
            else "main-trials.jsonl.gz"
        )
        mac_run = "common-cpu-5-01" if supplement else "security-final-03"
        rows.append(
            {
                "linux_case_id": case,
                "macos_case_id": case,
                "kind": "permitted-operation control"
                if case in POSITIVE
                else "attack or mandatory-refusal probe",
                "requested_policy_guarantee": guarantee(case),
                "attacker_capability": capability(case),
                "attack_body": body,
                "fixture": fixture,
                "independent_success_oracle": oracle,
                "existing_runs_comparable": not supplement,
                "comparison_status": (
                    "comparable after five-pair macOS supplement; original one-pair probe was not"
                    if supplement
                    else "comparable behavior and oracle; host mechanism may differ"
                ),
                "macos_outcome_five_repetitions": counts,
                "macos_evidence_path": (
                    f"eval/campaigns/macos-resubmission-v1/{mac_run}/trials/"
                    f"{case}-<0..4>/{{Unprotected,Argus}}/trial.json"
                ),
                "macos_portable_rows": (
                    "eval/campaigns/macos-resubmission-v1/common-cpu-trials.jsonl.gz"
                    if supplement
                    else "eval/campaigns/macos-resubmission-v1/security-trials.jsonl.gz"
                ),
                "linux_evidence_at_pinned_commit": f"{LINUX_ROOT}/{linux_file}",
            }
        )
    return {
        "schema": 1,
        "linux_revision": LINUX,
        "macos_base_revision": "794b17338eea0b71b67e084b720eb8d6d604b413",
        "linux_specification_sha256": hashlib.sha256(linux_spec).hexdigest(),
        "common_attacker_sha256": hashlib.sha256(linux_attacker).hexdigest(),
        "case_count": len(rows),
        "macos_paired_repetitions_per_case": 5,
        "rows": rows,
        "macos_only_extensions": [
            *first_assignment(mac_spec, "LIVE_MUTATIONS"),
            *first_assignment(mac_spec, "PREFLIGHT_CASES"),
            *first_assignment((CAMPAIGN / "advanced.py").read_bytes(), "CASES"),
        ],
    }


def main() -> None:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--output", type=Path, default=CAMPAIGN / "cross-host-common-cases.json")
    args = parser.parse_args()
    result = build()
    args.output.write_text(json.dumps(result, indent=2, sort_keys=True) + "\n")
    csv_path = args.output.with_suffix(".csv")
    with csv_path.open("w", newline="") as stream:
        writer = csv.DictWriter(stream, fieldnames=list(result["rows"][0]), lineterminator="\n")
        writer.writeheader()
        for row in result["rows"]:
            writer.writerow(
                {
                    **row,
                    "macos_outcome_five_repetitions": json.dumps(
                        row["macos_outcome_five_repetitions"], sort_keys=True
                    ),
                }
            )
    print(
        json.dumps(
            {"cases": result["case_count"], "output": str(args.output), "csv": str(csv_path)}
        )
    )


if __name__ == "__main__":
    main()
