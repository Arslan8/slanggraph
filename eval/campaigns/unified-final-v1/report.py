"""Generate all four unified-final-v1 summaries from raw records."""

from __future__ import annotations

import argparse
import json
import math
import random
import statistics
from collections import Counter, defaultdict
from pathlib import Path
from typing import Any

from campaign import config_id, load_config, percentile, write_json
from validate import read_jsonl


def _ordered_percentile(ordered: list[float], probability: float) -> float:
    """Return a percentile for an already sorted non-empty sample."""
    if not ordered:
        return math.nan
    position = (len(ordered) - 1) * probability
    low = math.floor(position)
    high = math.ceil(position)
    if low == high:
        return ordered[low]
    return ordered[low] + (ordered[high] - ordered[low]) * (position - low)


def successful(record: dict[str, Any]) -> bool:
    return (
        record["phase"] == "measured"
        and record["outcome"] == "completed"
        and record["oracle_passed"] is True
    )


def _tuple(record: dict[str, Any]) -> tuple[Any, ...]:
    return record["workload"], record["task"], record["session"], record["repetition"]


def _ratio(records: list[dict[str, Any]], modes: list[str], baseline: str) -> dict[str, Any]:
    by_mode = {
        mode: {_tuple(row): row for row in records if row["mode"] == mode and successful(row)}
        for mode in modes
    }
    common = set.intersection(*(set(rows) for rows in by_mode.values())) if by_mode else set()
    sums = {mode: sum(by_mode[mode][key]["runtime_ns"] for key in common) for mode in modes}
    ratios = {mode: (sums[mode] / sums[baseline] if sums[baseline] else None) for mode in modes}
    return {
        "estimand": "ratio of summed post-preflight runtimes on the fixed common-success tuple set",
        "common_success_count": len(common),
        "common_success_tuples": [list(value) for value in sorted(common)],
        "sum_runtime_ns": sums,
        "ratio_to_baseline": ratios,
        "overhead_percent": {
            mode: (100 * (ratio - 1) if ratio is not None else None)
            for mode, ratio in ratios.items()
        },
    }


def _bootstrap(
    records: list[dict[str, Any]], modes: list[str], baseline: str, draws: int, seed: int
) -> dict[str, Any]:
    primary = _ratio(records, modes, baseline)
    common = {tuple(value) for value in primary["common_success_tuples"]}
    lookup = {(row["mode"], _tuple(row)): row["runtime_ns"] for row in records if successful(row)}
    sessions = sorted({key[2] for key in common})
    randomizer = random.Random(seed)
    samples: dict[str, list[float]] = {mode: [] for mode in modes if mode != baseline}
    if not sessions or not common:
        return {mode: {"available": False} for mode in samples}
    for _ in range(draws):
        selected = [randomizer.choice(sessions) for _ in sessions]
        keys = [key for session in selected for key in common if key[2] == session]
        baseline_sum = sum(lookup[(baseline, key)] for key in keys)
        if baseline_sum == 0:
            continue
        for mode in samples:
            samples[mode].append(sum(lookup[(mode, key)] for key in keys) / baseline_sum)
    return {
        mode: {
            "available": bool(values),
            "low": percentile(values, 0.025) if values else None,
            "high": percentile(values, 0.975) if values else None,
            "draws": draws,
            "seed": seed,
            "unit": "fresh session block",
            "limitation": "five sessions on one machine; requests within a session are clustered",
        }
        for mode, values in samples.items()
    }


def _raw_by_workload(records: list[dict[str, Any]], modes: list[str]) -> dict[str, Any]:
    grouped: dict[tuple[str, str], list[dict[str, Any]]] = defaultdict(list)
    for row in records:
        if row["phase"] == "measured" and row["mode"] in modes:
            grouped[(row["workload"], row["mode"])].append(row)
    output: dict[str, Any] = {}
    for (workload, mode), rows in sorted(grouped.items()):
        times = [row["runtime_ns"] / 1e6 for row in rows if successful(row)]
        output.setdefault(workload, {})[mode] = {
            "scheduled": len(rows),
            "completed_correct": sum(successful(row) for row in rows),
            "status_counts": dict(Counter(row["outcome"] for row in rows)),
            "successful_runtime_mean_ms": statistics.fmean(times) if times else None,
            "successful_runtime_median_ms": statistics.median(times) if times else None,
            "full_population_runtime_ms": [row["runtime_ns"] / 1e6 for row in rows],
        }
    return output


def _preflight(records: list[dict[str, Any]], modes: list[str]) -> dict[str, Any]:
    return {
        mode: {
            "observations": sum(row["mode"] == mode for row in records),
            "mean_ms": statistics.fmean(
                row["preflight_ns"] / 1e6 for row in records if row["mode"] == mode
            )
            if any(row["mode"] == mode for row in records)
            else None,
            "excluded_from_primary_runtime": True,
        }
        for mode in modes
    }


def summarize_macro(records: list[dict[str, Any]], config: dict[str, Any]) -> dict[str, Any]:
    rows = [row for row in records if row["evaluation"] == 1]
    modes = config["evaluations"][0]["modes"]
    primary = _ratio(rows, modes, "baseline")
    primary["ci95"] = _bootstrap(
        rows, modes, "baseline", config["performance"]["bootstrap_draws"], config["random_seed"] + 1
    )
    return {
        "evaluation": 1,
        "name": "Macrobenchmarks",
        "scheduled_measured": sum(row["phase"] == "measured" for row in rows),
        "full_population_correctness": {
            mode: {
                "correct": sum(successful(row) for row in rows if row["mode"] == mode),
                "scheduled": sum(row["phase"] == "measured" for row in rows if row["mode"] == mode),
            }
            for mode in modes
        },
        "primary": primary,
        "applications": _raw_by_workload(rows, modes),
        "preflight": _preflight(rows, modes),
    }


def summarize_host(records: list[dict[str, Any]]) -> dict[str, Any]:
    applicable = [row for row in records if row.get("applicable")]
    distinct = defaultdict(dict)
    for row in applicable:
        entry = distinct[row["backend"]].setdefault(
            row["case"],
            {
                "obligation": row["obligation"],
                "outcomes": [],
                "oracle": [],
                "positive_control": [],
                "excluded_from_prevention_counts": row.get(
                    "excluded_from_prevention_counts", False
                ),
            },
        )
        entry["outcomes"].append(row["outcome"])
        entry["oracle"].append(row["oracle_passed"])
        entry["positive_control"].append(row["positive_control_passed"])
    distinct_outcomes: dict[str, dict[str, int]] = {}
    for backend, cases in distinct.items():
        classifications = Counter()
        for entry in cases.values():
            outcomes = set(entry["outcomes"])
            classifications[next(iter(outcomes)) if len(outcomes) == 1 else "mixed"] += 1
        distinct_outcomes[backend] = dict(classifications)
    return {
        "evaluation": 2,
        "name": "Host security portability",
        "distinct_cases": {backend: len(cases) for backend, cases in distinct.items()},
        "distinct_outcomes": distinct_outcomes,
        "positive_control_cases": {
            backend: sum(all(entry["positive_control"]) for entry in cases.values())
            for backend, cases in distinct.items()
        },
        "repetitions_are_not_coverage": True,
        "backends": distinct,
        "marginal_protection": "computed from observed complete/ablation case outcomes only",
    }


def summarize_micro(
    records: list[dict[str, Any]], sustained: list[dict[str, Any]], config: dict[str, Any]
) -> dict[str, Any]:
    rows = [row for row in records if row["evaluation"] == 3 and row["phase"] == "measured"]
    grouped: dict[tuple[str, str], list[dict[str, Any]]] = defaultdict(list)
    for row in rows:
        grouped[(row["workload"], row["mode"])].append(row)
    latency = {}
    for (workload, mode), values in sorted(grouped.items()):
        times = [row["runtime_ns"] / 1e3 for row in values]
        latency.setdefault(workload, {})[mode] = {
            "samples": len(values),
            "sessions": len({row["session"] for row in values}),
            "mean_us": statistics.fmean(times) if times else None,
            "median_us": statistics.median(times) if times else None,
            "p95_us": percentile(times, 0.95),
            "failures": sum(not successful(row) for row in values),
            "raw_us": times,
        }
    sustained_summary = []
    for row in sustained:
        latencies = sorted(value / 1e3 for value in row["latency_ns"])
        queue_waits = sorted(value / 1e3 for value in row["queue_wait_ns"])
        sustained_summary.append(
            {
                "mode": row["mode"],
                "concurrency": row["concurrency"],
                "session": row["session"],
                "offered": row["offered"],
                "completed": row["completed"],
                "failed": row["failed"],
                "completions_per_second": row["completed"] / row["issue_seconds"],
                "p50_us": _ordered_percentile(latencies, 0.50),
                "p95_us": _ordered_percentile(latencies, 0.95),
                "p99_us": _ordered_percentile(latencies, 0.99),
                "queue_wait_mean_us": statistics.fmean(queue_waits) if queue_waits else None,
                "queue_wait_p95_us": _ordered_percentile(queue_waits, 0.95),
                "queue_wait_p99_us": _ordered_percentile(queue_waits, 0.99),
                "pool_misses": row["pool_misses"],
                "replenishments": row["replenishments"],
                "initial_ready": row["initial_ready"],
                "final_ready": row["final_ready"],
                "drain_ns": row["drain_ns"],
                "restoration_ns": row["restoration_ns"],
            }
        )
    sustained_by_condition: dict[str, Any] = {}
    condition_rows: dict[tuple[str, int], list[dict[str, Any]]] = defaultdict(list)
    for row in sustained_summary:
        condition_rows[(row["mode"], row["concurrency"])].append(row)
    for (mode, concurrency), values in sorted(condition_rows.items()):
        sustained_by_condition.setdefault(mode, {})[str(concurrency)] = {
            "sessions": len(values),
            "offered": sum(row["offered"] for row in values),
            "completed": sum(row["completed"] for row in values),
            "failed": sum(row["failed"] for row in values),
            "session_mean_completions_per_second": statistics.fmean(
                row["completions_per_second"] for row in values
            ),
            "session_mean_p50_us": statistics.fmean(row["p50_us"] for row in values),
            "session_mean_p95_us": statistics.fmean(row["p95_us"] for row in values),
            "session_mean_p99_us": statistics.fmean(row["p99_us"] for row in values),
            "session_mean_queue_wait_us": statistics.fmean(
                row["queue_wait_mean_us"] for row in values
            ),
            "pool_misses": sum(row["pool_misses"] for row in values),
            "replenishments": sum(row["replenishments"] for row in values),
            "mean_drain_ms": statistics.fmean(row["drain_ns"] / 1e6 for row in values),
            "mean_restoration_ms": statistics.fmean(row["restoration_ns"] / 1e6 for row in values),
            "inventory_restored_sessions": sum(
                row["initial_ready"] == row["final_ready"] for row in values
            ),
        }
    return {
        "evaluation": 3,
        "name": "Identical-workload language/host microbenchmarks",
        "latency": latency,
        "tail_warning": (
            "request-latency p95 is descriptive for 30 clustered samples; "
            "sustained runs provide higher-volume tails"
        ),
        "sustained": sustained_summary,
        "sustained_by_condition": sustained_by_condition,
    }


def summarize_pandas(
    records: list[dict[str, Any]],
    config: dict[str, Any],
    pandas_security: list[dict[str, Any]],
) -> dict[str, Any]:
    rows = [row for row in records if row["evaluation"] == 4]
    modes = config["evaluations"][3]["modes"]
    primary = _ratio(rows, modes, "baseline")
    primary["ci95"] = _bootstrap(
        rows, modes, "baseline", config["performance"]["bootstrap_draws"], config["random_seed"] + 4
    )
    controls = []
    for probe in pandas_security:
        evidence = probe.get("rows", [])
        row = evidence[-1] if evidence else {}
        observations = row.get("attack_observations", [])
        controls.append(
            {
                "attack": probe.get("attack"),
                "passed": (
                    probe.get("returncode") == 0
                    and row.get("status") == "completed"
                    and row.get("output_matches_oracle") is True
                    and bool(observations)
                    and all(observation.get("effect") is False for observation in observations)
                ),
                "observations": observations,
                "protected_resource_after": row.get("attack_resource_after"),
                "raw_evidence": probe.get("raw_evidence"),
            }
        )
    per_task: dict[str, Any] = {}
    for task in config["evaluations"][3]["tasks"]:
        task_rows = [row for row in rows if row["task"] == task]
        per_task[task] = _raw_by_workload(task_rows, modes).get("pandas", {})
    return {
        "evaluation": 4,
        "name": "Pandas case study",
        "primary": primary,
        "full_population_correctness": {
            mode: {
                "correct": sum(successful(row) for row in rows if row["mode"] == mode),
                "scheduled": sum(row["phase"] == "measured" for row in rows if row["mode"] == mode),
            }
            for mode in modes
        },
        "tasks": per_task,
        "preflight": _preflight(rows, modes),
        "resource_controls": controls,
        "separate_from_macrobenchmark": True,
    }


def generate_summary(result: Path) -> dict[str, Any]:
    config = load_config(result / "configuration.json")
    records = read_jsonl(result / "records.jsonl")
    security = read_jsonl(result / "host-security.jsonl")
    sustained = read_jsonl(result / "sustained.jsonl")
    pandas_security = (
        json.loads((result / "pandas-security.json").read_text())
        if (result / "pandas-security.json").exists()
        else []
    )
    validation = (
        json.loads((result / "supporting-validation.json").read_text())
        if (result / "supporting-validation.json").exists()
        else {}
    )
    policy_mapping = json.loads((result / "policy_mapping.json").read_text())
    return {
        "schema_version": 1,
        "campaign_id": config["campaign_id"],
        "config_id": config_id(config),
        "evaluations": [
            summarize_macro(records, config),
            summarize_host(security),
            summarize_micro(records, sustained, config),
            summarize_pandas(records, config, pandas_security),
        ],
        "supporting_validation": validation,
        "policy_comparison": policy_mapping["mappings"],
    }


def _markdown(summary: dict[str, Any]) -> str:
    evaluations = summary["evaluations"]
    lines = [
        "# Unified final campaign report",
        "",
        f"Campaign `{summary['campaign_id']}`; configuration `{summary['config_id']}`.",
        "",
    ]
    for evaluation in evaluations:
        lines.extend([f"## Evaluation {evaluation['evaluation']}: {evaluation['name']}", ""])
        if evaluation["evaluation"] in {1, 4}:
            primary = evaluation["primary"]
            correctness = evaluation["full_population_correctness"]
            lines.append(
                "The fixed common-success population contains "
                f"{primary['common_success_count']} tuples. Headline values are ratios "
                "of summed post-preflight runtimes, not equal-workload averages."
            )
            lines.extend(
                [
                    "",
                    "| Mode | Correct/scheduled | Sum runtime (ms) | Ratio | 95% CI | Overhead |",
                    "| --- | ---: | ---: | ---: | ---: | ---: |",
                ]
            )
            for mode, total in primary["sum_runtime_ns"].items():
                ratio = primary["ratio_to_baseline"][mode]
                overhead = primary["overhead_percent"][mode]
                population = correctness[mode]
                interval = primary["ci95"].get(mode)
                interval_text = (
                    f"[{interval['low']:.4f}, {interval['high']:.4f}]"
                    if interval and interval.get("available")
                    else "reference"
                )
                lines.append(
                    f"| {mode} | {population['correct']}/{population['scheduled']} | "
                    f"{total / 1e6:.3f} | {ratio:.4f} | {interval_text} | {overhead:.2f}% |"
                    if ratio is not None
                    else f"| {mode} | {population['correct']}/{population['scheduled']} | "
                    f"{total / 1e6:.3f} | n/a | n/a | n/a |"
                )
            scheduled = max(value["scheduled"] for value in correctness.values())
            lines.extend(
                [
                    "",
                    f"The common-success set contains {primary['common_success_count']} of "
                    f"{scheduled} scheduled tuple positions. Exact membership, per-application "
                    "status counts, raw full-population runtimes, and preflight measurements are "
                    "in `summary.json`.",
                ]
            )
            if evaluation["evaluation"] == 4:
                controls = evaluation["resource_controls"]
                lines.extend(
                    [
                        "",
                        "Pandas resource controls:",
                        "",
                        "| Attack | Outcome | Raw evidence |",
                        "| --- | --- | --- |",
                    ]
                )
                for control in controls:
                    outcome = "prevented" if control["passed"] else "failed"
                    lines.append(f"| {control['attack']} | {outcome} | {control['raw_evidence']} |")
        elif evaluation["evaluation"] == 2:
            lines.append(
                "This is a security-portability comparison. Distinct cases, "
                "applicability, positive controls, and effect oracles are reported "
                "separately from repetitions."
            )
            lines.extend(
                [
                    "",
                    "| Backend | Distinct cases | Prevented | Rejected before execution | "
                    "Allowed controls | Inconclusive | Positive controls |",
                    "| --- | ---: | ---: | ---: | ---: | ---: | ---: |",
                ]
            )
            for backend, total in evaluation["distinct_cases"].items():
                outcomes = evaluation["distinct_outcomes"][backend]
                lines.append(
                    f"| {backend} | {total} | {outcomes.get('prevented', 0)} | "
                    f"{outcomes.get('rejected', 0)} | {outcomes.get('allowed', 0)} | "
                    f"{outcomes.get('inconclusive', 0)} | "
                    f"{evaluation['positive_control_cases'][backend]}/{total} |"
                )
            lines.extend(
                [
                    "",
                    "Required-obligation rejections are reported separately from "
                    "effect-level prevention. The macOS manifest and runner are supplied "
                    "for the other student; no macOS outcomes are claimed here.",
                ]
            )
        else:
            lines.append(
                "Request latency uses 30 samples clustered within five sessions. "
                "Sustained results remain part of this evaluation and include drain "
                "and inventory-restoration endpoints."
            )
            lines.extend(
                [
                    "",
                    "Request latency:",
                    "",
                    "| Workload | Mode | Mean (us) | Median (us) | p95 (us) | Failures |",
                    "| --- | --- | ---: | ---: | ---: | ---: |",
                ]
            )
            for workload, modes in evaluation["latency"].items():
                for mode, values in modes.items():
                    lines.append(
                        f"| {workload} | {mode} | {values['mean_us']:.3f} | "
                        f"{values['median_us']:.3f} | {values['p95_us']:.3f} | "
                        f"{values['failures']} |"
                    )
            lines.extend(
                [
                    "",
                    "Sustained 32-byte read (means of five 60-second session results):",
                    "",
                    "| Mode | Concurrency | Completions/s | p50 (us) | p95 (us) | "
                    "p99 (us) | Failures | Pool misses | Replenishments |",
                    "| --- | ---: | ---: | ---: | ---: | ---: | ---: | ---: | ---: |",
                ]
            )
            for mode, concurrencies in evaluation["sustained_by_condition"].items():
                for concurrency, values in concurrencies.items():
                    lines.append(
                        f"| {mode} | {concurrency} | "
                        f"{values['session_mean_completions_per_second']:.2f} | "
                        f"{values['session_mean_p50_us']:.3f} | "
                        f"{values['session_mean_p95_us']:.3f} | "
                        f"{values['session_mean_p99_us']:.3f} | {values['failed']} | "
                        f"{values['pool_misses']} | {values['replenishments']} |"
                    )
        lines.append("")
    lines.extend(
        [
            "## Policy comparison",
            "",
            "| Scope | nono | APF/OpenShell | Omitted obligation |",
            "| --- | --- | --- | --- |",
        ]
    )
    for row in summary["policy_comparison"]:
        if row.get("nono_category") is None and row.get("apf_category") is None:
            continue
        lines.append(
            f"| {row['scope']} | {row['nono_category']} | {row['apf_category']} | "
            f"{row['omitted_obligation']} |"
        )
    lines.append("")
    fuzz = summary.get("supporting_validation", {}).get("fuzz", {})
    counts = fuzz.get("counts", {})
    lines.extend(
        [
            "## Supporting validation",
            "",
            f"Admission/interpreter fuzzing generated {counts.get('generated', 0)} programs "
            f"across {len(fuzz.get('seeds', []))} fixed seeds: "
            f"{counts.get('admitted', 0)} admitted, {counts.get('rejected', 0)} rejected, "
            f"{counts.get('timeouts', 0)} timeouts, {counts.get('crashes', 0)} crashes, "
            f"{counts.get('mismatches', 0)} mismatches, and "
            f"{counts.get('security_violations', 0)} security violations.",
            "",
        ]
    )
    lines.extend(
        [
            "## Limitations",
            "",
            "Performance intervals use five session blocks on one Linux machine. "
            "Request-latency tail quantiles are descriptive for 30 clustered samples; "
            "the sustained subtest supplies the higher-volume tails. APF/OpenShell and "
            "nono are best-available reduced-enforcement comparisons, not equivalent-policy "
            "rankings. macOS was not executed locally.",
            "",
        ]
    )
    return "\n".join(lines)


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("result", type=Path)
    args = parser.parse_args()
    summary = generate_summary(args.result)
    write_json(args.result / "summary.json", summary)
    (args.result / "REPORT.md").write_text(_markdown(summary), encoding="utf-8")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
