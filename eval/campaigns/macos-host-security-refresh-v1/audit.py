"""Audit the shared 45-case macOS run and emit case-level portable results."""

from __future__ import annotations

import argparse
import csv
import hashlib
import json
import sys
from collections import Counter
from pathlib import Path

HERE = Path(__file__).resolve().parent
ROOT = HERE.parents[2]
CROSS = ROOT / "eval/campaigns/cross-host-security-v2"
UNIFIED = ROOT / "eval/campaigns/unified-final-v1"
REFERENCE = "30bb18375c36ee9634ed9b7d7af04c8e21546a96"
HOST_REQUIRED = {
    "required_per_process_cpu": ("cpu per_process 1000 need", "cpu", "per_process", "1000"),
    "required_aggregate_cpu": ("cpu aggregate 1000 need", "cpu", "aggregate", "1000"),
    "required_syscall_filter": ("syscalls @minimal need", "syscalls", "filter", "@minimal"),
    "extensible_required_cpu": (
        "host_cpu require aggregate-cpu-1000ms need",
        "host_cpu",
        "require",
        "aggregate-cpu-1000ms",
    ),
    "extensible_required_syscalls": (
        "host_syscalls require linux-minimal-syscalls need",
        "host_syscalls",
        "require",
        "linux-minimal-syscalls",
    ),
}

sys.path[:0] = [str(CROSS), str(UNIFIED)]
import host  # noqa: E402
import verify  # noqa: E402
from macos_student import applicable_cases  # noqa: E402
from specification import ALLOWED, manifest  # noqa: E402


def digest(path: Path) -> str:
    return hashlib.sha256(path.read_bytes()).hexdigest()


def relative(path: Path) -> str:
    return str(path.relative_to(ROOT))


def refusal_witness(case: str, protected: dict, issues: list[str], label: str) -> dict:
    expected_line, expected_class, expected_operation, expected_selector = HOST_REQUIRED[case]
    _, profile = manifest(case, "macos")
    if expected_line not in profile.splitlines():
        issues.append(f"{label}: original mandatory requirement differs")
    dispatchers = (protected.get("evidence") or {}).get("dispatchers", [])
    grants = [grant for item in dispatchers for grant in item.get("authorization_grants", [])]
    lines = [line for grant in grants for line in grant.get("lines", [])]
    matched = [
        line
        for line in lines
        if (line["class_name"], line["operation"], line["selector"], line["requirement"])
        == (expected_class, expected_operation, expected_selector, "need")
    ]
    if len(matched) != 1 or matched[0].get("enforcer") != "kernel":
        issues.append(f"{label}: mandatory kernel grant line missing or changed")
    expected_id = matched[0]["line_id"] if matched else None
    lowerings = [item for dispatcher in dispatchers for item in dispatcher.get("lowering", [])]
    receipts = [item for dispatcher in dispatchers for item in dispatcher.get("receipts", [])]
    if receipts or verify.entered(protected):
        issues.append(f"{label}: worker received a mandatory unsupported operation")
    if case.startswith("extensible_"):
        reason = str((protected.get("outcome") or {}).get("result"))
        if "macos_object:unsupported_filesystem_authority" not in reason:
            issues.append(f"{label}: attributable native grant refusal missing")
        # The process-tree sampler also observes Cedar admission helpers. The
        # recorded exception is raised by _compile_grant before _run/_spawn;
        # receipts and trusted worker-entry events are the release witnesses.
        release = False if not receipts and not verify.entered(protected) else None
    else:
        refusals = [item for item in lowerings if item.get("decision") == "unsupported"]
        if not any(
            item.get("tool_released") is False
            and any(
                obligation.get("waivable") is False and obligation.get("rule_id") == expected_id
                for obligation in item.get("unsupported_obligations", [])
            )
            for item in refusals
        ):
            issues.append(f"{label}: lowerer did not retain the non-waivable refusal")
        reason = "; ".join(str(item.get("reason")) for item in refusals)
        release = (
            False
            if refusals and all(item.get("tool_released") is False for item in refusals)
            else None
        )
    return {
        "original_requirement": expected_line,
        "grant_line_id": matched[0]["line_id"] if matched else None,
        "refusal_reason": reason,
        "tool_released": release,
        "activation_receipts": len(receipts),
        "observed_controller_descendants": [
            item["pid"]
            for item in protected["observed_processes"]
            if item["pid"] != protected["controller"]["pid"]
        ],
    }


def audit(run: Path, verification: Path, repetitions: int) -> dict:
    host.bootstrap()
    checked = json.loads(verification.read_text())
    config = json.loads((run / "configuration.json").read_text())
    request = json.loads(run.with_name(run.name + "-request.json").read_text())
    manifest_data = json.loads((UNIFIED / "host_cases.json").read_text())
    cases = applicable_cases(manifest_data)
    rows = [json.loads(line) for line in (run / "trials.jsonl").read_text().splitlines()]
    indexed = {(row["case"], row["repetition"], row["condition"]): row for row in rows}
    classified = {(row["case"], row["repetition"]): row for row in checked.get("classified", [])}
    issues = []
    if not checked.get("evidence_valid") or checked.get("distinct_cases") != 45:
        issues.append("independent security verifier did not pass all 45 cases")
    if config["cases"] != cases or request["cases"] != cases:
        issues.append("runner case order differs from the shared manifest")
    if config["repetitions"] != repetitions or request["repetitions"] != repetitions:
        issues.append("runner repetition count differs")
    if config["host"] != "macos" or request["macos_version"] != "26.7.2":
        issues.append("macOS host identity differs")
    if config["revisions"]["linux_reference"] != REFERENCE:
        issues.append("Linux reference revision differs")
    if (run / "native-configuration.json").read_bytes() != (
        HERE / "native-configuration.json"
    ).read_bytes():
        issues.append("runner did not copy the frozen native configuration")
    if list(run.glob("harness-error-*.json")):
        issues.append("harness errors present")
    if len(rows) != 45 * repetitions * 2 or len(indexed) != len(rows):
        issues.append("missing or duplicate trial rows")
    if json.loads((run / "source-before.json").read_text()) != json.loads(
        (run / "source-after.json").read_text()
    ):
        issues.append("source changed during execution")
    case_rows = []
    categories = Counter()
    for case in manifest_data["cases"]:
        case_id = case["id"]
        controls = []
        protected_outcomes = []
        oracles = []
        refusals = []
        for repeat in range(repetitions):
            label = f"{case_id}/{repeat}"
            control = indexed.get((case_id, repeat, "Unprotected"))
            protected = indexed.get((case_id, repeat, "Argus"))
            if control is None or protected is None:
                issues.append(f"{label}: paired trial missing")
                continue
            control_effect = (
                verify.allowed(control) if case_id in ALLOWED else verify.forbidden(control)
            )
            finding = classified.get((case_id, repeat))
            if not control_effect or finding is None or finding["control_effect"] is not True:
                issues.append(f"{label}: unprotected positive control ineffective")
            protected_effect = (
                verify.allowed(protected) if case_id in ALLOWED else verify.forbidden(protected)
            )
            if finding is None:
                category = "Inconclusive"
                reason = "independent classification missing"
            elif finding["category"] == "Enforced":
                category = (
                    "Authorized control succeeded"
                    if case_id in ALLOWED
                    else "Forbidden effect prevented"
                )
                reason = finding["reason"]
            elif finding["category"] == "Rejected before execution":
                category, reason = "Rejected before execution", finding["reason"]
            elif finding["category"] == "Failed" and case_id not in ALLOWED and protected_effect:
                category, reason = "Forbidden effect occurred", finding["reason"]
            else:
                category, reason = "Inconclusive", finding["reason"]
            categories[category] += 1
            if category in {"Inconclusive", "Forbidden effect occurred"}:
                issues.append(f"{label}: {category}: {reason}")
            if case_id in HOST_REQUIRED:
                refusals.append(refusal_witness(case_id, protected, issues, label))
                if category != "Rejected before execution":
                    issues.append(f"{label}: mandatory host requirement not refused")
            if case_id == "direct_shm":
                for condition, trial in (("Unprotected", control), ("Argus", protected)):
                    target = trial["task"]["target"]
                    marker = trial["fixture"]["shm_canary"]
                    if not trial["fixture"]["files"][target]["contains_shm_canary"]:
                        issues.append(
                            f"{label}/{condition}: separate SHM canary absent from fixture"
                        )
                    if verify.visible(verify.attacker_output(trial), marker) != (
                        condition == "Unprotected"
                    ):
                        issues.append(f"{label}/{condition}: SHM canary observation differs")
            control_path = run / "trials" / f"{case_id}-{repeat}" / "Unprotected"
            protected_path = run / "trials" / f"{case_id}-{repeat}" / "Argus"
            controls.append({"repetition": repeat, "effect_observed": control_effect})
            protected_outcomes.append(
                {
                    "repetition": repeat,
                    "category": category,
                    "reason": reason,
                    "worker_entered": verify.entered(protected),
                    "forbidden_effect": protected_effect if case_id not in ALLOWED else None,
                    "evidence_path": relative(protected_path / "trial.json"),
                }
            )
            oracles.append(
                {
                    "repetition": repeat,
                    "control_trial": relative(control_path / "trial.json"),
                    "protected_trial": relative(protected_path / "trial.json"),
                    "resource_events": relative(protected_path / "resource-events.jsonl")
                    if (protected_path / "resource-events.jsonl").exists()
                    else None,
                    "database_before": relative(protected_path / "database-before.sqlite"),
                    "database_after": relative(protected_path / "database-after.sqlite"),
                    "control_effect_observed": control_effect,
                    "protected_effect_observed": protected_effect,
                    "shm_fixture_sha256": control["fixture"]["files"][control["task"]["target"]][
                        "sha256"
                    ]
                    if case_id == "direct_shm"
                    else None,
                }
            )
        case_rows.append(
            {
                "case_id": case_id,
                "requested_guarantee": case["obligation"],
                "kind": case["kind"],
                "positive_controls": controls,
                "protected_outcomes": protected_outcomes,
                "independent_oracle_evidence": oracles,
                "host_capability_refusals": refusals,
            }
        )
    allowed_success = sum(
        item["case_id"] in ALLOWED
        and all(
            result["category"] == "Authorized control succeeded"
            for result in item["protected_outcomes"]
        )
        for item in case_rows
    )
    if allowed_success != len(ALLOWED):
        issues.append("authorized controls did not all succeed")
    first_allowed = indexed.get(("allowed_record_read", 0, "Argus"))
    native = (first_allowed.get("evidence") or {}).get("dispatchers", []) if first_allowed else []
    if not any(
        item["type"] == "MacOSObjectDispatcher"
        and item["receipts"]
        and item["lifecycle"]
        and item["broker_audit"]
        for item in native
    ):
        issues.append("native MacOSObjectDispatcher/Lean/mediator route not witnessed")
    return {
        "schema": 1,
        "evidence_valid": not issues,
        "issues": issues,
        "linux_reference_revision": REFERENCE,
        "macos_checkout_revision": config["revisions"]["macOS_checkout"],
        "macos_version": request["macos_version"],
        "native_configuration_sha256": digest(HERE / "native-configuration.json"),
        "shared_manifest_sha256": digest(UNIFIED / "host_cases.json"),
        "attacker_sha256": digest(CROSS / "attacker.py"),
        "fixture_sha256": digest(CROSS / "fixtures.py"),
        "distinct_cases": len(case_rows),
        "repetitions_per_case": repetitions,
        "paired_trials": len(rows) // 2,
        "categories_by_observation": dict(categories),
        "authorized_control_cases": allowed_success,
        "native_success_certificates_replayed": checked.get("native_success_certificates_replayed"),
        "rows": case_rows,
    }


def main() -> None:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("run", type=Path)
    parser.add_argument("verification", type=Path)
    parser.add_argument("--repetitions", type=int, choices=(1, 5), required=True)
    parser.add_argument("--prefix", type=Path, required=True)
    args = parser.parse_args()
    report = audit(args.run.resolve(), args.verification.resolve(), args.repetitions)
    args.prefix.with_suffix(".json").write_text(json.dumps(report, indent=2, sort_keys=True) + "\n")
    with args.prefix.with_suffix(".csv").open("w", newline="") as stream:
        writer = csv.DictWriter(
            stream,
            fieldnames=(
                "case_id",
                "requested_guarantee",
                "kind",
                "positive_control_outcomes",
                "protected_outcomes",
                "independent_oracle_evidence",
                "host_capability_refusal",
            ),
            lineterminator="\n",
        )
        writer.writeheader()
        for row in report["rows"]:
            writer.writerow(
                {
                    "case_id": row["case_id"],
                    "requested_guarantee": row["requested_guarantee"],
                    "kind": row["kind"],
                    "positive_control_outcomes": json.dumps(
                        row["positive_controls"], sort_keys=True
                    ),
                    "protected_outcomes": json.dumps(row["protected_outcomes"], sort_keys=True),
                    "independent_oracle_evidence": json.dumps(
                        row["independent_oracle_evidence"], sort_keys=True
                    ),
                    "host_capability_refusal": json.dumps(
                        row["host_capability_refusals"], sort_keys=True
                    ),
                }
            )
    print(
        json.dumps(
            {
                "evidence_valid": report["evidence_valid"],
                "distinct_cases": report["distinct_cases"],
                "categories": report["categories_by_observation"],
                "issues": report["issues"],
            },
            indent=2,
        )
    )
    raise SystemExit(0 if report["evidence_valid"] else 1)


if __name__ == "__main__":
    main()
