"""Recompute native macOS campaign coverage, oracles, binding, audit and statistics.

No stored passed/valid flag is an oracle. This checks recorded observations;
it does not prove their provenance or reproduce native enforcement off-host.
"""

from __future__ import annotations

import argparse
import hashlib
import json
import math
import os
import sqlite3
import statistics
import xml.etree.ElementTree as ET
from collections import Counter
from pathlib import Path

DOMAINS = (
    "filesystem",
    "network",
    "process",
    "ipc",
    "service",
    "credential",
    "runtime",
    "delegation",
    "resource_limit",
)
UTILITY = {"left": 17, "right": 24, "sum": 41, "equal": False}
ATTACKS = (
    "allowed_exact",
    "denied_exact",
    "alias_allowed",
    "alias_denied",
    "symlink_escape",
    "hardlink_inside",
    "hardlink_outside",
    "write",
    "fork",
    "raw_fork",
    "spawn",
    "exec",
    "network",
    "signal",
    "descriptors",
    "cpu",
    "wall",
    "policy_forbid",
    "wrong_principal",
    "artifact_changed",
    "unsupported_minimal",
    "nonfinite_frame",
    "receipt_grant",
    "receipt_context",
    "receipt_nonce",
    "receipt_coverage",
)
PREGO = {
    "policy_forbid",
    "wrong_principal",
    "artifact_changed",
    "unsupported_minimal",
    "receipt_grant",
    "receipt_context",
    "receipt_nonce",
    "receipt_coverage",
}
ALLOWS = {"allowed_exact": "17", "alias_allowed": "17", "hardlink_inside": "PRIVATE_CANARY"}


def digest(value):
    return hashlib.sha256(
        json.dumps(value, ensure_ascii=False, sort_keys=True, separators=(",", ":")).encode()
    ).hexdigest()


def rows(path):
    return [json.loads(line) for line in path.read_text().splitlines()]


def interval(values):
    if not values:
        return {"mean": None, "ci95": [None, None], "sessions": 0}
    mean = statistics.fmean(values)
    half = 2.776445 * statistics.stdev(values) / math.sqrt(5) if len(values) == 5 else None
    return {
        "mean": mean,
        "ci95": [mean - half, mean + half] if half is not None else [None, None],
        "sessions": len(values),
    }


def check_binding(row, issues, key):
    try:
        grant, plan, receipt = row["grant"], row["plan"], row["receipt"]
        if grant["call_id"] != row["call_id"] or grant["principal_id"] != "alice":
            issues.append(f"{key}: invocation identity")
        payload = {
            field: grant[field]
            for field in (
                "principal_id",
                "session_id",
                "tool_name",
                "artifact_digest",
                "call_id",
                "normalized_intent_digest",
                "policy_digest",
            )
        }
        payload["rules"] = sorted(grant["rules"], key=lambda rule: rule["rule_id"])
        payload.update(
            {
                field: grant[field]
                for field in ("deployment_digest", "runtime_digest")
                if grant[field]
            }
        )
        if (
            digest(payload) != row["grant_digest"]
            or receipt["grant_digest"] != row["grant_digest"]
            or plan["grant_digest"] != row["grant_digest"]
        ):
            issues.append(f"{key}: grant digest binding")
        if (
            receipt["plan_digest"] != row["plan_digest"]
            or receipt["artifact_digest"] != grant["artifact_digest"]
        ):
            issues.append(f"{key}: plan/artifact binding")
        expected = {f"rule:{rule['rule_id']}:operate" for rule in grant["rules"]} | {
            f"domain:{domain}:deny_complement" for domain in DOMAINS
        }
        assignments = plan["assignments"]
        ids = [assignment["obligation_id"] for assignment in assignments]
        if (
            len(ids) != len(set(ids))
            or set(ids) != expected
            or any(
                assignment["support"] not in {"exact", "tightened"} for assignment in assignments
            )
        ):
            issues.append(f"{key}: obligation assignments")
        if set(receipt["activated_obligations"]) != expected or len(
            receipt["activated_obligations"]
        ) != len(expected):
            issues.append(f"{key}: activated obligation coverage")
        if (
            plan["mode"] != "enforced"
            or receipt["mode"] != "enforced"
            or plan["waived_obligations"]
        ):
            issues.append(f"{key}: degraded or waived")
        if len(plan["adapter_plans"]) != 1 or len(receipt["evidence"]) != 1:
            issues.append(f"{key}: native evidence ownership")
        native, evidence = plan["adapter_plans"][0], receipt["evidence"][0]
        if (
            set(native["obligation_ids"]) != expected
            or set(evidence["obligation_ids"]) != expected
            or evidence["adapter_id"] != native["adapter_id"]
            or evidence["native_plan_digest"] != native["native_plan_digest"]
            or digest(native["payload"]) != native["native_plan_digest"]
        ):
            issues.append(f"{key}: native plan/evidence binding")
        if (
            evidence["nonce"] != receipt["nonce"]
            or evidence["context_digest"] != receipt["context_digest"]
        ):
            issues.append(f"{key}: context/nonce binding")
        if (
            digest(row["context"]) != receipt["context_digest"]
            or str(row["worker_pid"]) not in row["context"]["process_identity"]
        ):
            issues.append(f"{key}: worker context")
        if not row["receipt_validated"]:
            issues.append(f"{key}: live signature validation failed")
    except (KeyError, TypeError, IndexError) as exc:
        issues.append(f"{key}: missing receipt structure: {exc}")


def useful(row, issues, key):
    if row.get("status") != "success" or row.get("value") != UTILITY:
        issues.append(f"{key}: useful control failed")
    if (
        not row.get("cleanup_confirmed")
        or not row.get("worker_absent")
        or row.get("recovery_records") != 0
        or row.get("unresolved") != 0
    ):
        issues.append(f"{key}: cleanup incomplete")
    check_binding(row, issues, key)


def verify_attack(row, issues):
    case = row["case"]
    key = f"attack/{case}/{row['repeat']}"
    useful(row["control"], issues, key + "/control")
    trial, direct = row["trial"], row["direct_control"]
    if row.get("fixture_after") != {"left": "17", "right": "24", "secret": "PRIVATE_CANARY"}:
        issues.append(f"{key}: unauthorized fixture change")
    if case in PREGO:
        expected = {
            "wrong_principal": "macos:principal_profile_mismatch",
            "artifact_changed": "macos:artifact_changed",
        }.get(case)
        error = trial.get("error", {})
        if (
            trial.get("status") != "refusal"
            or error.get("type") != "HostExecutionDenied"
            or trial.get("go_ns")
        ):
            issues.append(f"{key}: pre-GO refusal missing")
        elif expected and error["reason"] != expected:
            issues.append(f"{key}: wrong refusal stage")
        elif case == "unsupported_minimal" and "adapter_rule_unsupported:" not in error["reason"]:
            issues.append(f"{key}: unsupported confused with activation failure")
        elif case.startswith("receipt_") and error["reason"] != "macos:activation_receipt_invalid":
            issues.append(f"{key}: evidence fault not rejected by validator")
        elif case == "policy_forbid" and not error["reason"].startswith(
            "macos:required_authority_removed:"
        ):
            issues.append(f"{key}: policy denial confused with worker failure")
        if "worker_pid" in trial and (
            not trial.get("cleanup_confirmed")
            or not trial.get("worker_absent")
            or trial.get("recovery_records") != 0
        ):
            issues.append(f"{key}: pre-GO worker cleanup missing")
        return
    check_binding(trial, issues, key)
    if case != "nonfinite_frame":
        if case == "exec":
            if direct != {"exec_returncode": 0}:
                issues.append(f"{key}: exec positive control failed")
        elif (
            not isinstance(direct, dict)
            or direct.get("attempted") is not True
            or direct.get("blocked") is not False
            or direct.get("useful") != UTILITY
        ):
            issues.append(f"{key}: unconfined effect control failed")
    if (
        not trial.get("receipt_validated")
        or not trial.get("cleanup_confirmed")
        or not trial.get("worker_absent")
        or trial.get("recovery_records") != 0
    ):
        issues.append(f"{key}: activation/cleanup evidence missing")
    if case in {"cpu", "wall", "nonfinite_frame"}:
        if (
            trial.get("status") != "execution_error"
            or trial.get("termination_confirmed") is not True
        ):
            issues.append(f"{key}: post-activation failure not contained")
        status = trial.get("wait_status")
        if case in {"cpu", "wall"}:
            if (
                type(status) is not int
                or not os.WIFSIGNALED(status)
                or os.WTERMSIG(status) not in {9, 24}
            ):
                issues.append(f"{key}: kernel/guardian termination not observed")
            elapsed = trial["phases"]["execution_ms"]
            if case == "cpu" and not 700 <= elapsed < 4000:
                issues.append(f"{key}: CPU ceiling not distinguished from wall deadline")
            if case == "wall" and not 70 <= elapsed < 1000:
                issues.append(f"{key}: wall deadline not witnessed")
        elif trial.get("protocol_error") != "ValueError":
            issues.append(f"{key}: malformed response not witnessed")
        return
    if trial.get("status") != "success":
        issues.append(f"{key}: worker error is not a witnessed denial")
        return
    value = trial.get("value", {})
    if value.get("useful") != UTILITY or value.get("attempted") is not True:
        issues.append(f"{key}: useful work or effect attempt missing")
    if case in ALLOWS:
        if value.get("blocked") is not False or value.get("effect") != ALLOWS[case]:
            issues.append(f"{key}: authorized path semantics failed")
    elif case == "descriptors":
        effect = value.get("effect", {})
        if (
            effect.get("errno") != 24
            or not 1 <= effect.get("opened", 1000) < 64
            or direct.get("effect") != {"opened": 100, "errno": None}
        ):
            issues.append(f"{key}: descriptor ceiling/control failed")
    elif value.get("blocked") is not True or value.get("errno") not in {1, 13}:
        issues.append(f"{key}: no witnessed permission denial")
    if case == "network" and row["network_effect"]:
        issues.append(f"{key}: protected network connection reached listener")


def check_audit(records, protected, issues, key):
    previous = ""
    if len(records) != len(protected):
        issues.append(f"{key}: audit count")
    for record, trial in zip(records, protected, strict=False):
        payload = {
            field: record[field]
            for field in (
                "args_hash",
                "call_index",
                "module",
                "prev_hash",
                "reason",
                "stage",
                "tool_name",
                "user_id",
                "verdict",
            )
        }
        if record.get("session_id"):
            payload["session_id"] = record["session_id"]
        if record.get("outcome") is not None:
            payload["outcome"] = record["outcome"]
        if record["prev_hash"] != previous or digest(payload) != record["hash"]:
            issues.append(f"{key}: audit chain")
        previous = record["hash"]
        if not record["reason"].startswith("activation_receipt:") or json.loads(
            record["reason"].split(":", 1)[1]
        ) != trial.get("receipt"):
            issues.append(f"{key}: audit receipt correspondence")
        if record["call_index"] != trial["index"] or record["session_id"] != trial.get(
            "grant", {}
        ).get("session_id"):
            issues.append(f"{key}: audit invocation binding")


def verify(folder):
    issues = []
    config = json.loads((folder / "plan.json").read_text())
    if not config["pilot"] and (config["sessions"], config["warmups"], config["measured"]) != (
        5,
        10,
        20,
    ):
        issues.append("full campaign denominator changed")
    if config["attacks"] != list(ATTACKS):
        issues.append("attack census changed")
    before = json.loads((folder / "source-before.json").read_text())
    after = json.loads((folder / "source-after.json").read_text())
    if not before or before != after:
        issues.append("source drift during campaign")
    for name, value in before.items():
        archived = folder / "sources" / value
        if not archived.is_file() or hashlib.sha256(archived.read_bytes()).hexdigest() != value:
            issues.append(f"missing or altered source archive: {name}")
    gates = json.loads((folder / "gates.json").read_text())
    junit = ET.parse(folder / "gates.xml").getroot()
    cases = list(junit.iter("testcase"))
    if (
        gates["returncode"] != 0
        or not cases
        or list(junit.iter("failure"))
        or list(junit.iter("error"))
    ):
        issues.append("test gates failed or missing")
    executed = [case for case in cases if case.find("skipped") is None]
    if sum("test_macos_execution" in case.get("classname", "") for case in executed) != 40:
        issues.append("native adapter test gate did not execute all 40 cases")
    oracle_prefixes = (
        "test_valid_synthetic_binding",
        "test_receipt_digest_fault",
        "test_obligation_and_native_faults",
        "test_denial_requires_positive_controls",
        "test_missing_archive",
        "test_confidence_interval",
    )
    if sum(case.get("name", "").startswith(oracle_prefixes) for case in executed) < 20:
        issues.append("independent oracle test gate incomplete")
    process_rows = rows(folder / "session-processes.jsonl")
    if [(item["session"], item["returncode"]) for item in process_rows] != [
        (number, 0) for number in range(config["sessions"])
    ]:
        issues.append("session execution matrix failed")
    means, baselines, first_use, setups, phase_means = [], [], [], [], {}
    controller_pids = []
    for number in range(config["sessions"]):
        directory = folder / f"session-{number}"
        observations = rows(directory / "trials.jsonl")
        setup = [row for row in observations if row["kind"] == "setup"]
        if (
            len(setup) != 1
            or setup[0].get("closed_admission") is not False
            or setup[0].get("lean") is not None
            or setup[0].get("cedar") is not None
        ):
            issues.append(f"session/{number}: setup/scope mismatch")
        controller_pids.append(setup[0]["pid"])
        setups.append(setup[0]["executor_setup_ms"])
        calls = [row for row in observations if row["kind"] == "call"]
        phases = ["first_use"] + ["warmup"] * config["warmups"] + ["measured"] * config["measured"]
        expected = Counter(
            (route, phase, index)
            for index, phase in enumerate(phases)
            for route in ("macos-native-typed-audited-pilot", "direct-primitive")
        )
        actual = Counter((row["route"], row["phase"], row["index"]) for row in calls)
        if actual != expected:
            issues.append(f"session/{number}: missing/duplicate/extra timing observations")
        protected = [row for row in calls if row["route"] == "macos-native-typed-audited-pilot"]
        for row in calls:
            key = f"session/{number}/{row['index']}/{row['route']}"
            if not math.isfinite(row["elapsed_ms"]) or row["elapsed_ms"] <= 0:
                issues.append(f"{key}: invalid elapsed time")
            if row.get("value") != UTILITY:
                issues.append(f"{key}: output oracle failed")
            if row["route"] == "direct-primitive":
                continue
            useful(row, issues, key)
            values = [*row["phases"].values(), row["framework_residual_ms"]]
            if (
                any(not math.isfinite(value) or value < -0.1 for value in values)
                or abs(sum(values) - row["elapsed_ms"]) > 0.01
            ):
                issues.append(f"{key}: additive phase ledger overlaps or loses time")
            if row["call_id"] != f"session-{number}-call-{row['index']}":
                issues.append(f"{key}: call binding")
        measured = [row for row in protected if row["phase"] == "measured"]
        baseline = [
            row
            for row in calls
            if row["route"] == "direct-primitive" and row["phase"] == "measured"
        ]
        means.append(statistics.fmean(row["elapsed_ms"] for row in measured))
        baselines.append(statistics.fmean(row["elapsed_ms"] for row in baseline))
        first_use.append(
            next(row["elapsed_ms"] for row in protected if row["phase"] == "first_use")
        )
        for phase in measured[0]["phases"]:
            phase_means.setdefault(phase, []).append(
                statistics.fmean(row["phases"][phase] for row in measured)
            )
        phase_means.setdefault("framework_residual_ms", []).append(
            statistics.fmean(row["framework_residual_ms"] for row in measured)
        )
        audit = json.loads((directory / "audit-records.json").read_text())
        check_audit(audit, protected, issues, f"session/{number}")
        with sqlite3.connect(f"file:{directory / 'audit.sqlite'}?mode=ro", uri=True) as database:
            stored = database.execute("SELECT hash FROM audit_records ORDER BY sequence").fetchall()
        if [value[0] for value in stored] != [record["hash"] for record in audit]:
            issues.append(f"session/{number}: SQLite and exported audit disagree")
    if len(set(controller_pids)) != len(controller_pids):
        issues.append("fresh controller sessions not demonstrated")
    attacks = rows(folder / "attacks/trials.jsonl")
    if Counter((row["case"], row["repeat"]) for row in attacks) != Counter(
        (case, number) for case in ATTACKS for number in range(config["sessions"])
    ):
        issues.append("attack matrix missing/duplicated/unexpected")
    for row in attacks:
        verify_attack(row, issues)
    census = json.loads((folder / "lowering-census.json").read_text())
    complement = [row for row in census if row["obligation"]["kind"] == "deny_complement"]
    if Counter(row["obligation"]["domain"] for row in complement) != Counter(DOMAINS):
        issues.append("lowering census lacks nine domain complements")
    expected_census = {
        "read": "exact",
        "cpu": "exact",
        "descriptors": "exact",
        "wall": "exact",
        **{
            name: "unsupported"
            for name in (
                "write",
                "syscalls",
                "memory",
                "network",
                "fractional_cpu",
                "delegation",
                "service",
                "exclusion",
            )
        },
    }
    if Counter(
        row["obligation"]["rule_id"]
        for row in census
        if row["obligation"]["kind"] != "deny_complement"
    ) != Counter(expected_census.keys()):
        issues.append("lowering census rule matrix changed")
    for row in census:
        expected = expected_census.get(row["obligation"]["rule_id"], "exact")
        if (
            row["assessment"]["support"] != expected
            or row["assessment"]["obligation_id"] != row["obligation"]["obligation_id"]
        ):
            issues.append("lowering census classification mismatch")
    attack_results = []
    for row in attacks:
        failures = []
        verify_attack(row, failures)
        attack_results.append(
            {
                "case": row["case"],
                "repeat": row["repeat"],
                "passed": not failures,
                "issues": failures,
            }
        )
    ratios = [protected / baseline for protected, baseline in zip(means, baselines, strict=True)]
    return {
        "passed": not issues,
        "issues": issues,
        "scope": config["scope"],
        "system_complete": False,
        "lean_validated": False,
        "cross_host_validated": False,
        "sessions": len(means),
        "measured_calls": len(means) * config["measured"],
        "attack_observations": len(attacks),
        "attack_passed": sum(row["passed"] for row in attack_results),
        "attack_results": attack_results,
        "statistics": {
            "elapsed_ms": interval(means),
            "first_use_ms": interval(first_use),
            "executor_setup_ms": interval(setups),
            "baseline_ms": interval(baselines),
            "added_ms": interval([a - b for a, b in zip(means, baselines, strict=True)]),
            "primitive_relative_multiple": interval(ratios),
            "phases_ms": {name: interval(values) for name, values in phase_means.items()},
        },
        "test_gates": {"passed": len(executed), "skipped": len(cases) - len(executed)},
        "native_census": dict(Counter(row["assessment"]["support"] for row in census)),
    }


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("folder", type=Path)
    args = parser.parse_args()
    try:
        report = verify(args.folder.resolve())
    except (
        OSError,
        ValueError,
        KeyError,
        TypeError,
        IndexError,
        statistics.StatisticsError,
    ) as exc:
        report = {
            "passed": False,
            "issues": [f"incomplete/malformed evidence: {type(exc).__name__}: {exc}"],
            "system_complete": False,
        }
    (args.folder / "verification.json").write_text(
        json.dumps(report, sort_keys=True, indent=2) + "\n"
    )
    print(json.dumps(report, sort_keys=True))
    raise SystemExit(0 if report["passed"] else 1)


if __name__ == "__main__":
    main()
