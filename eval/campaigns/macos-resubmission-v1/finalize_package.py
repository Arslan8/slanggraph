"""Write the final summary and checksum index after both demo cohorts verify."""

from __future__ import annotations

import hashlib
import json
from pathlib import Path

HERE = Path(__file__).resolve().parent


def read(name: str) -> dict:
    return json.loads((HERE / name).read_text())


def require(report: dict, label: str) -> None:
    if report.get("evidence_valid", report.get("passed")) is not True:
        raise ValueError(f"invalid evidence: {label}")


def main() -> None:
    main_security = read("security-verification.json")
    advanced = read("advanced-verification.json")
    common = read("cross-host-common-verification.json")
    cpu = read("common-cpu-verification.json")
    vulnerability = read("filesystem-identity-finding.json")
    cancellation = read("cancellation-witness-verification.json")
    baseline = read("app-baseline-verification.json")
    argus = read("app-argus-verification.json")
    pandas = read("pandas-verification.json")
    regressions = read("application-regressions.json")
    equivalence = read("common-source-equivalence.json")
    for name, report in (
        ("security", main_security),
        ("advanced", advanced),
        ("common", common),
        ("cpu", cpu),
        ("filesystem identity", vulnerability),
        ("cancellation", cancellation),
        ("baseline", baseline),
        ("argus", argus),
        ("pandas", pandas),
        ("regressions", regressions),
        ("source equivalence", equivalence),
    ):
        require(report, name)
    if baseline["attempted"] != 175 or argus["attempted"] != 175:
        raise ValueError("demo correctness cohorts are incomplete")
    if pandas["trials"] != 50 or pandas["correct"] != 50:
        raise ValueError("final Pandas cohort differs")
    if common["distinct_common_cases"] != 45 or common["selected_trials_per_host"] != 450:
        raise ValueError("common security matrix differs")
    app_base = read("app-baseline-configuration.json")
    app_argus = read("app-argus-configuration.json")
    if (
        app_base["framework_revision"] != app_argus["framework_revision"]
        or app_base["model_digest"] != app_argus["model_digest"]
        or app_base["upstream_revision"] != app_argus["upstream_revision"]
        or app_base["packages"] != app_argus["packages"]
    ):
        raise ValueError("application cohort revision, model, upstream, or package pins differ")
    if read("app-baseline-sources.json") != read("app-argus-sources.json"):
        raise ValueError("application cohort source inventories differ")
    report = {
        "schema": 2,
        "scope": (
            "macOS security and application correctness; no Linux execution or overhead benchmark"
        ),
        "source_revisions": {
            "linux_inventory": common["linux_revision"],
            "macos_committed_base": "794b17338eea0b71b67e084b720eb8d6d604b413",
            "application_framework": app_base["framework_revision"],
            "application_upstream": app_base["upstream_revision"],
            "main_security_source_inventory": hashlib.sha256(
                (HERE / "security-sources.json").read_bytes()
            ).hexdigest(),
            "cpu_source_inventory": hashlib.sha256(
                (HERE / "common-cpu-sources.json").read_bytes()
            ).hexdigest(),
        },
        "pins": {
            "model": "qwen3:8b",
            "model_digest": app_base["model_digest"],
            "ollama": app_base["ollama"],
            "python": app_base["python"],
            "dependency_inventory": (
                "app-baseline-configuration.json and app-argus-configuration.json"
            ),
            "native_configuration": (
                "security-native-configuration.json and app-argus-host-configuration.json"
            ),
        },
        "common_security": {
            "distinct_cases": 45,
            "paired_repetitions_per_case": 5,
            "selected_macos_trials": 450,
            "permitted_control_cases": 5,
            "enforced_permitted_observations": 25,
            "enforced_attack_observations": 160,
            "pre_execution_refusals": 40,
            "all_controls_effective": True,
            "comparison": "behavior and oracle matched; host support decisions differ",
        },
        "macos_security_extensions": {
            "main_distinct_cases": main_security["distinct_cases"],
            "main_total_trials": main_security["total_trials"],
            "supplemental_distinct_cases": advanced["distinct_cases"],
            "supplemental_paired_repetitions": advanced["paired_trials"],
            "supplemental_categories": advanced["categories"],
            "before_fix_private_disclosures": vulnerability["before_fix_protected_disclosures"],
            "after_fix_direct_file_refusals": vulnerability["after_fix_pre_execution_refusals"],
            "legitimate_mediated_reads": vulnerability["legitimate_mediated_reads"],
            "cancellation_witness_pairs": cancellation["paired_repetitions"],
        },
        "application_correctness": {
            "baseline_attempted": baseline["attempted"],
            "baseline_correct": baseline["correct"],
            "argus_attempted": argus["attempted"],
            "argus_correct": argus["correct"],
            "baseline_by_application": baseline["applications"],
            "argus_by_application": argus["applications"],
            "pandas_attempted": pandas["trials"],
            "pandas_correct": pandas["correct"],
            "missing_value_and_infinity_regression": regressions,
        },
        "remaining_qualifications": [
            "Nine original supplemental observations are inconclusive and nine qualified; "
            "see SUPPLEMENTAL_DISPOSITIONS.md.",
            "Debugging failed in both conditions; trusted-controller compromise is outside "
            "the worker threat model.",
            "Controlled process suspension does not prove historical sleep/wake causality.",
            "Historical checkpoint time travel requires an authenticated branch/restore "
            "transition not implemented by the linear-integrity policy.",
            "Full raw SQLite backups, model outputs, and frozen execution copies remain in "
            "ignored local run directories; compact committed rows do not provide "
            "full offline replay.",
            "No new cross-host equivalence claim is made without Linux owner agreement "
            "on this revision.",
        ],
        "local_raw_runs": {
            "main_security": "security-final-03",
            "before_fix": "advanced-run-01",
            "after_fix": "advanced-run-02",
            "common_cpu": "common-cpu-5-01",
            "cancellation": "cancellation-witness-01",
            "pandas": "pandas-argus-rerun-11",
            "baseline_demos": "app-baseline-final-03",
            "argus_demos": "app-argus-final-02",
        },
    }
    (HERE / "acceptance.json").write_text(json.dumps(report, indent=2, sort_keys=True) + "\n")
    files = sorted(
        path
        for path in HERE.iterdir()
        if path.is_file()
        and path.name != "SHA256SUMS"
        and path.suffix in {".md", ".json", ".gz", ".csv", ".py"}
    )
    (HERE / "SHA256SUMS").write_text(
        "".join(f"{hashlib.sha256(path.read_bytes()).hexdigest()}  {path.name}\n" for path in files)
    )
    print(
        json.dumps(
            {"files": len(files), "baseline": baseline["correct"], "argus": argus["correct"]}
        )
    )


if __name__ == "__main__":
    main()
