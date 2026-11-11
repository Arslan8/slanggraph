"""Regenerate campaign statistics and paper-ready Markdown from raw JSONL."""

from __future__ import annotations

import argparse
import json
import math
import statistics
from collections import defaultdict
from pathlib import Path

T95 = {
    1: 12.706,
    2: 4.303,
    3: 3.182,
    4: 2.776,
    5: 2.571,
    6: 2.447,
    7: 2.365,
    8: 2.306,
    9: 2.262,
    10: 2.228,
    11: 2.201,
    12: 2.179,
    13: 2.160,
    14: 2.145,
    15: 2.131,
    16: 2.120,
    17: 2.110,
    18: 2.101,
    19: 2.093,
    20: 2.086,
    24: 2.064,
    29: 2.045,
}


def ci95(values: list[float]) -> dict[str, float | int]:
    if not values:
        return {"n": 0, "mean": math.nan, "low": math.nan, "high": math.nan}
    mean = statistics.mean(values)
    if len(values) == 1:
        return {"n": 1, "mean": mean, "low": mean, "high": mean}
    degrees = len(values) - 1
    critical = T95.get(degrees, 1.96 if degrees >= 30 else T95[29])
    half = critical * statistics.stdev(values) / math.sqrt(len(values))
    return {"n": len(values), "mean": mean, "low": mean - half, "high": mean + half}


def read_rows(raw: Path) -> list[dict]:
    rows = []
    for path in sorted(raw.rglob("*.jsonl")):
        if "superseded" in path.parts:
            continue
        if path.name != "trials.jsonl" and "session-" not in path.name:
            continue
        for number, line in enumerate(path.read_text().splitlines(), 1):
            if line.strip():
                row = json.loads(line)
                row["_source"] = str(path.relative_to(raw))
                row["_line"] = number
                rows.append(row)
    return rows


def performance(rows: list[dict], phase: str = "measured") -> list[dict]:
    samples: dict[tuple[str, str], dict[int, list[float]]] = defaultdict(lambda: defaultdict(list))
    metrics = (
        "elapsed_ms",
        "authorization_ms",
        "policy_lowering_ms",
        "activation_ms",
        "execution_ms",
        "mediator_transport_ms",
        "lean_ms",
        "audit_ms",
        "cleanup_ms",
    )
    for row in rows:
        if row.get("kind") != "call" or row.get("phase") != phase:
            continue
        route = row.get("route")
        session = row.get("session")
        if not isinstance(route, str) or not isinstance(session, int):
            continue
        for metric in metrics:
            value = row.get(metric)
            if isinstance(value, int | float) and math.isfinite(value):
                samples[(route, metric)][session].append(float(value))
    result = []
    for (route, metric), sessions in sorted(samples.items()):
        session_means = [statistics.mean(values) for values in sessions.values()]
        result.append(
            {
                "route": route,
                "metric": metric,
                "calls": sum(map(len, sessions.values())),
                "sessions": len(sessions),
                **ci95(session_means),
            }
        )
    elapsed = {row["route"]: row for row in result if row["metric"] == "elapsed_ms"}
    baselines = {
        "direct": "direct",
        "language": "direct",
        "linux": "direct",
        "linux-lean": "direct",
        "direct-container": "direct-container",
        "container": "direct-container",
        "direct-broker": "direct-broker",
        "broker": "direct-broker",
    }
    for row in result:
        route = row["route"]
        row["workload"] = (
            "sqlite-record-read" if route in {"broker", "direct-broker"} else "file-read"
        )
        if row["metric"] != "elapsed_ms":
            continue
        baseline_route = baselines.get(route)
        baseline = elapsed.get(baseline_route) if baseline_route else None
        row["baseline_route"] = baseline_route
        if baseline:
            row["added_ms"] = row["mean"] - baseline["mean"]
            row["ratio"] = row["mean"] / baseline["mean"]
            row["overhead_percent"] = (row["ratio"] - 1) * 100
    return result


def application(rows: list[dict]) -> list[dict]:
    groups: dict[str, list[dict]] = defaultdict(list)
    for row in rows:
        # The attacked application runs share the C-full mode name but answer a
        # separate security question.  Keep them out of the utility/timing
        # cohort while retaining them in the attack table below.
        if row.get("application") == "pandas" and row.get("attack") is None:
            groups[str(row.get("mode"))].append(row)
    result = []
    for mode, selected in sorted(groups.items()):
        by_session: dict[int, list[dict]] = defaultdict(list)
        for row in selected:
            by_session[int(row["session"])].append(row)
        session_success = [
            statistics.mean(bool(row.get("legitimate_result")) for row in values)
            for values in by_session.values()
        ]
        session_wall = [
            statistics.mean(float(row["wall_ms"]) for row in values)
            for values in by_session.values()
        ]
        session_model = [
            statistics.mean(float(row["model_ms"]) for row in values)
            for values in by_session.values()
        ]
        result.append(
            {
                "configuration": mode,
                "trials": len(selected),
                "successes": sum(bool(row.get("legitimate_result")) for row in selected),
                "output_validation_failures": sum(
                    int(row.get("output_validation_failures", 0)) for row in selected
                ),
                "mean_wall_ms": statistics.mean(float(row["wall_ms"]) for row in selected),
                "mean_model_ms": statistics.mean(float(row["model_ms"]) for row in selected),
                "wall_ms_ci": ci95(session_wall),
                "model_ms_ci": ci95(session_model),
                "success_rate_ci": ci95(session_success),
            }
        )
    return result


def attacks(rows: list[dict]) -> list[dict]:
    groups: dict[tuple[str, str, str], list[dict]] = defaultdict(list)
    for row in rows:
        if row.get("comparison_kind") in {
            "sandbox_configuration_probe",
            "sandbox_module_probe",
        }:
            continue
        if row.get("application") == "pandas" and row.get("attack") is None:
            continue
        case = row.get("case_id")
        if not isinstance(case, str) or "legitimate_result" not in row:
            continue
        system = str(row.get("baseline") or row.get("mode") or row.get("host") or "slangGraph")
        source = str(row["_source"]).split("/", 1)[0]
        groups[(source, system, case)].append(row)
    return [
        {
            "experiment": experiment,
            "system": system,
            "case_id": case,
            "trials": len(selected),
            "legitimate_completed": sum(bool(row.get("legitimate_result")) for row in selected),
            "unauthorized_effects": sum(
                bool(row.get("unauthorized_effect", row.get("observed_effect", False)))
                for row in selected
            ),
            "classifications": sorted(
                {str(row["classification"]) for row in selected if row.get("classification")}
            ),
        }
        for (experiment, system, case), selected in sorted(groups.items())
    ]


def external_probes(rows: list[dict]) -> list[dict]:
    groups: dict[tuple[str, str, str], list[dict]] = defaultdict(list)
    for row in rows:
        kind = row.get("comparison_kind")
        if kind not in {"sandbox_configuration_probe", "sandbox_module_probe"}:
            continue
        groups[(str(row.get("baseline")), str(kind), str(row.get("case_id")))].append(row)
    return [
        {
            "system": system,
            "kind": kind,
            "case_id": case,
            "trials": len(selected),
            "tool_executed": sum(bool(row.get("tool_executed")) for row in selected),
            "unauthorized_effects": sum(bool(row.get("unauthorized_effect")) for row in selected),
            "classification": sorted({str(row.get("classification")) for row in selected}),
            "full_system_comparison": False,
        }
        for (system, kind, case), selected in sorted(groups.items())
    ]


def fare_results(rows: list[dict]) -> list[dict]:
    groups: dict[tuple[str, str, str], list[dict]] = defaultdict(list)
    for row in rows:
        if row.get("record_type") != "attack_trial":
            continue
        groups[
            (str(row.get("mode")), str(row.get("scenario")), str(row.get("execution_order")))
        ].append(row)
    return [
        {
            "mode": mode,
            "scenario": scenario,
            "execution_order": order,
            "trials": len(selected),
            "trials_completed": sum(bool(row.get("trial_completed")) for row in selected),
            "task_completed": sum(bool(row.get("task_completion")) for row in selected),
            "answer_correct": sum(bool(row.get("answer_correct")) for row in selected),
            "admission_failures": sum(bool(row.get("admission_failure")) for row in selected),
            "authorization_failures": sum(
                bool(row.get("authorization_failure")) for row in selected
            ),
            "activation_failures": sum(bool(row.get("activation_failure")) for row in selected),
            "execution_failures": sum(bool(row.get("execution_failure")) for row in selected),
            "protected_activations": sum(bool(row.get("activation_receipts")) for row in selected),
            "selection_control": all(bool(row.get("selection_control")) for row in selected),
            "metro_omitted": sum(
                not bool(row.get("security_outcome", {}).get("metro_not_omitted"))
                for row in selected
            ),
            "false_metro_value": sum(
                not bool(row.get("security_outcome", {}).get("false_metro_value_absent"))
                for row in selected
            ),
        }
        for (mode, scenario, order), selected in sorted(groups.items())
    ]


def fare_negative_control(rows: list[dict]) -> dict:
    selected = [row for row in rows if row.get("record_type") == "operator_negative_control"]
    return {
        "trials": len(selected),
        "denied_before_activation": sum(
            bool(row.get("denial_before_activation")) for row in selected
        ),
        "body_executed": sum(bool(row.get("body_executed")) for row in selected),
        "grants_issued": sum(len(row.get("authorization_grants", [])) for row in selected),
        "activation_receipts": sum(len(row.get("activation_receipts", [])) for row in selected),
    }


def markdown(summary: dict) -> str:
    lines = ["# Consolidated evaluation results", "", "## Pandas application", ""]
    lines += [
        "| Configuration | Success | Validation failures | Wall ms (95% CI) | Model ms (95% CI) |",
        "|---|---:|---:|---:|---:|",
    ]
    for row in summary["application"]:
        lines.append(
            f"| {row['configuration']} | {row['successes']}/{row['trials']} | "
            f"{row['output_validation_failures']} | {row['mean_wall_ms']:.1f} "
            f"[{row['wall_ms_ci']['low']:.1f}, {row['wall_ms_ci']['high']:.1f}] | "
            f"{row['mean_model_ms']:.1f} [{row['model_ms_ci']['low']:.1f}, "
            f"{row['model_ms_ci']['high']:.1f}] |"
        )
    lines += ["", "## Performance by equivalent workload", ""]
    for workload, title in (
        ("file-read", "File-read routes"),
        ("sqlite-record-read", "SQLite record/broker routes"),
    ):
        lines += [f"### {title}", ""]
        lines += [
            "| Route | Baseline | Mean ms | 95% CI | Added ms | Ratio | Sessions/calls |",
            "|---|---|---:|---:|---:|---:|---:|",
        ]
        for row in summary["performance"]:
            if row["metric"] != "elapsed_ms" or row.get("workload") != workload:
                continue
            added = row.get("added_ms")
            ratio = row.get("ratio")
            lines.append(
                f"| {row['route']} | {row.get('baseline_route', '—')} | "
                f"{row['mean']:.3f} | [{row['low']:.3f}, {row['high']:.3f}] | "
                f"{added:.3f} | {ratio:.2f}x | {row['sessions']}/{row['calls']} |"
                if added is not None and ratio is not None
                else f"| {row['route']} | — | {row['mean']:.3f} | "
                f"[{row['low']:.3f}, {row['high']:.3f}] | — | — | "
                f"{row['sessions']}/{row['calls']} |"
            )
        lines.append("")
    lines += [
        "File routes use the direct file read; broker routes use the direct SQLite "
        "record read. Absolute added milliseconds are primary because both baselines "
        "are small.",
        "",
        "### First invocation in each fresh session",
        "",
        "| Route | Mean ms | 95% CI | Sessions |",
        "|---|---:|---:|---:|",
    ]
    for row in summary["cold_starts"]:
        if row["metric"] == "elapsed_ms":
            lines.append(
                f"| {row['route']} | {row['mean']:.3f} | "
                f"[{row['low']:.3f}, {row['high']:.3f}] | {row['sessions']} |"
            )
    lines += [
        "",
        "### Measured phase costs",
        "",
        "| Route | Phase | Mean ms | 95% CI |",
        "|---|---|---:|---:|",
    ]
    for row in summary["performance"]:
        if row["metric"] == "elapsed_ms":
            continue
        lines.append(
            f"| {row['route']} | {row['metric']} | {row['mean']:.3f} | "
            f"[{row['low']:.3f}, {row['high']:.3f}] |"
        )
    lines += [
        "",
        "## Attack outcomes",
        "",
        "| Experiment | System | Case | Legitimate | Unauthorized effects | Classification |",
        "|---|---|---|---:|---:|---|",
    ]
    for row in summary["attacks"]:
        lines.append(
            f"| {row['experiment']} | {row['system']} | {row['case_id']} | "
            f"{row['legitimate_completed']}/{row['trials']} | "
            f"{row['unauthorized_effects']}/{row['trials']} | "
            f"{', '.join(row['classifications']) or 'observed'} |"
        )
    lines += [
        "",
        "## External sandbox/configuration probes",
        "",
        "These are not full-system head-to-head attacks.",
        "",
        "| System | Probe kind | Case | Tool executed | Unauthorized effects | Classification |",
        "|---|---|---|---:|---:|---|",
    ]
    for row in summary["external_probes"]:
        lines.append(
            f"| {row['system']} | {row['kind']} | {row['case_id']} | "
            f"{row['tool_executed']}/{row['trials']} | "
            f"{row['unauthorized_effects']}/{row['trials']} | "
            f"{', '.join(row['classification'])} |"
        )
    lines += [
        "",
        "## ACE-inspired fare adaptations on protected slangGraph",
        "",
        "Every completed tool call passed closed admission, Cedar authorization, "
        "the sealed operator-policy intersection, and isolated Linux activation. "
        "The fixed description-manipulation row is a selection control. These are "
        "not ACE or IsolateGPT executions, and authorized-output integrity is outside "
        "the current protection scope.",
        "",
        "| Mode | Scenario | Order | Completed | Protected activation | Task | Exact | "
        "Admission/auth/activation/execution failures | Control |",
        "|---|---|---|---:|---:|---:|---:|---:|---|",
    ]
    for row in summary["fare_results"]:
        lines.append(
            f"| {row['mode']} | {row['scenario']} | {row['execution_order']} | "
            f"{row['trials_completed']}/{row['trials']} | "
            f"{row['protected_activations']}/{row['trials']} | "
            f"{row['task_completed']}/{row['trials']} | "
            f"{row['answer_correct']}/{row['trials']} | "
            f"{row['admission_failures']}/{row['authorization_failures']}/"
            f"{row['activation_failures']}/{row['execution_failures']} | "
            f"{'predetermined selection' if row['selection_control'] else '—'} |"
        )
    control = summary["fare_negative_control"]
    lines += [
        "",
        "### Sealed-operator negative control",
        "",
        f"The operator-denied `quick_fare` call was stopped before activation in "
        f"{control['denied_before_activation']}/{control['trials']} trials. It issued "
        f"{control['grants_issued']} grants and {control['activation_receipts']} "
        f"activation receipts; the body marker changed in "
        f"{control['body_executed']}/{control['trials']} trials.",
    ]
    return "\n".join(lines) + "\n"


def run(raw: Path, output: Path) -> None:
    output.mkdir(parents=True, exist_ok=True)
    rows = read_rows(raw)
    summary = {
        "raw_root": str(raw),
        "jsonl_rows": len(rows),
        "application": application(rows),
        "performance": performance(rows),
        "cold_starts": performance(rows, "first_use"),
        "attacks": attacks(rows),
        "external_probes": external_probes(rows),
        "fare_results": fare_results(rows),
        "fare_negative_control": fare_negative_control(rows),
        "confidence_interval_unit": "independent-session means",
    }
    (output / "statistics.json").write_text(json.dumps(summary, indent=2) + "\n")
    (output / "RESULTS.md").write_text(markdown(summary))


if __name__ == "__main__":
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--raw", required=True, type=Path)
    parser.add_argument("--output", required=True, type=Path)
    arguments = parser.parse_args()
    run(arguments.raw, arguments.output)
