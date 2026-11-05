"""Regenerate statistics, table, and normalized-overhead graph from raw trials."""

from __future__ import annotations

import argparse
import json
import math
import random
import statistics
from pathlib import Path

import matplotlib.pyplot as plt

CAMPAIGN = Path(__file__).resolve().parent
SEED = 20261028
RESAMPLES = 10_000
MODES = ("Baseline", "Argus")


def percentile(values: list[float], fraction: float) -> float:
    ordered = sorted(values)
    position = (len(ordered) - 1) * fraction
    lower = math.floor(position)
    upper = math.ceil(position)
    if lower == upper:
        return ordered[lower]
    return ordered[lower] + (ordered[upper] - ordered[lower]) * (position - lower)


def timing_samples(records: list[dict], repetitions: list[int]) -> dict[str, list[float]]:
    samples = {mode: [] for mode in MODES}
    for repetition in repetitions:
        selected = [item for item in records if item["repetition"] == repetition]
        by_pair: dict[tuple[str, int, int], dict[str, dict]] = {}
        for record in selected:
            key = (record["application"], record["repetition"], record["task"])
            by_pair.setdefault(key, {})[record["mode"]] = record
        for pair in by_pair.values():
            if set(pair) != set(MODES):
                continue
            if not all(
                item["status"] == "completed"
                and item["correct"]
                and item.get("invocation_ms") is not None
                for item in pair.values()
            ):
                continue
            for mode in MODES:
                samples[mode].append(pair[mode]["invocation_ms"])
    return samples


def ratio_for(records: list[dict], repetitions: list[int]) -> float:
    samples = timing_samples(records, repetitions)
    return statistics.fmean(samples["Argus"]) / statistics.fmean(samples["Baseline"])


def mean_or_none(values) -> float | None:
    selected = list(values)
    return statistics.fmean(selected) if selected else None


def summarize_mode(records: list[dict]) -> dict:
    model_times = [item["model_time_ms"] for item in records if item["model_time_ms"] is not None]
    return {
        "attempts": len(records),
        "completed": sum(item["status"] == "completed" for item in records),
        "correct": sum(item["correct"] for item in records),
        "timeouts": sum(item["status"] == "timeout" for item in records),
        "compatibility_failures": sum(item["status"] == "compatibility_failed" for item in records),
        "execution_errors": sum(item["status"] == "execution_error" for item in records),
        "mean_process_wall_ms": statistics.fmean(item["process_wall_ms"] for item in records),
        "mean_preparation_ms": mean_or_none(
            item["preparation_ms"] for item in records if item.get("preparation_ms") is not None
        ),
        "mean_model_ms": statistics.fmean(model_times) if model_times else None,
        "model_calls": sum(item["model_calls"] or 0 for item in records),
        "security_evidence_trials": sum(item["security_evidence"] for item in records),
    }


def main() -> None:
    parser = argparse.ArgumentParser()
    parser.add_argument("--run-id", required=True)
    parser.add_argument(
        "--output-dir",
        type=Path,
        help="Write generated outputs here instead of the campaign directory.",
    )
    args = parser.parse_args()
    output = args.output_dir or CAMPAIGN
    output.mkdir(parents=True, exist_ok=True)
    raw = CAMPAIGN / "raw" / args.run_id
    records = json.loads((raw / "trials.json").read_text())
    applications = sorted({item["application"] for item in records})
    repetitions = sorted({item["repetition"] for item in records})
    rng = random.Random(SEED)
    resampled_blocks = [[rng.choice(repetitions) for _ in repetitions] for _ in range(RESAMPLES)]

    results = {}
    included = []
    for application in applications:
        selected = [item for item in records if item["application"] == application]
        modes = {
            mode: summarize_mode([item for item in selected if item["mode"] == mode])
            for mode in MODES
        }
        population_paired = len(
            {item["task"] for item in selected if item["mode"] == "Baseline"}
        ) == len({item["task"] for item in selected if item["mode"] == "Argus"}) and all(
            modes[mode]["attempts"] > 0 for mode in MODES
        )
        samples = timing_samples(selected, repetitions)
        matched_pairs = len(samples["Baseline"])
        for mode in MODES:
            modes[mode]["matched_mean_invocation_ms"] = (
                statistics.fmean(samples[mode]) if samples[mode] else None
            )
        application_result = {
            "modes": modes,
            "population_paired": population_paired,
            "matched_successful_pairs": matched_pairs,
        }
        if population_paired and matched_pairs:
            ratio = ratio_for(selected, repetitions)
            bootstrap = [ratio_for(selected, sample) for sample in resampled_blocks]
            application_result.update(
                {
                    "ratio": ratio,
                    "overhead_percent": 100 * (ratio - 1),
                    "ratio_ci95": [
                        percentile(bootstrap, 0.025),
                        percentile(bootstrap, 0.975),
                    ],
                    "overhead_ci95_percent": [
                        100 * (percentile(bootstrap, 0.025) - 1),
                        100 * (percentile(bootstrap, 0.975) - 1),
                    ],
                }
            )
            included.append(application)
        else:
            application_result["exclusion"] = (
                "unpaired cohort"
                if not population_paired
                else "no pair completed correctly in both modes"
            )
        results[application] = application_result

    ratios = [results[item]["ratio"] for item in included]
    geometric_ratio = math.exp(statistics.fmean(math.log(value) for value in ratios))
    latency_records = [item for item in records if item["application"] in included]
    suite_ratio = ratio_for(latency_records, repetitions)
    suite_bootstrap = [ratio_for(latency_records, sample) for sample in resampled_blocks]
    geometric_bootstrap = []
    for sample in resampled_blocks:
        sampled_ratios = [
            ratio_for([item for item in records if item["application"] == application], sample)
            for application in included
        ]
        geometric_bootstrap.append(
            math.exp(statistics.fmean(math.log(value) for value in sampled_ratios))
        )
    statistics_output = {
        "run_id": args.run_id,
        "primary_timer": "application invocation wall clock after preparation",
        "latency_population": "task/repetition pairs completed correctly in both modes",
        "audit": "disabled in primary modes; measured separately as an explicit special case",
        "attempts": len(records),
        "repetitions": len(repetitions),
        "bootstrap": {
            "method": "paired repetition-block bootstrap; all application tasks stay in block",
            "seed": SEED,
            "resamples": RESAMPLES,
        },
        "applications": results,
        "suite": {
            "included": included,
            "excluded": [item for item in applications if item not in included],
            "pooled_matched_ratio": suite_ratio,
            "pooled_matched_overhead_percent": 100 * (suite_ratio - 1),
            "ratio_ci95": [
                percentile(suite_bootstrap, 0.025),
                percentile(suite_bootstrap, 0.975),
            ],
            "overhead_ci95_percent": [
                100 * (percentile(suite_bootstrap, 0.025) - 1),
                100 * (percentile(suite_bootstrap, 0.975) - 1),
            ],
            "equal_application_weight_secondary": {
                "included": included,
                "geometric_mean_ratio": geometric_ratio,
                "geometric_mean_overhead_percent": 100 * (geometric_ratio - 1),
                "ratio_ci95": [
                    percentile(geometric_bootstrap, 0.025),
                    percentile(geometric_bootstrap, 0.975),
                ],
                "overhead_ci95_percent": [
                    100 * (percentile(geometric_bootstrap, 0.025) - 1),
                    100 * (percentile(geometric_bootstrap, 0.975) - 1),
                ],
                "interpretation": (
                    "Secondary equal-application-weight summary. It magnifies ratios for "
                    "very short applications and is not the primary overhead estimate."
                ),
            },
            "interpretation": (
                "Ratio of pooled invocation durations over matched task/repetition pairs that "
                "completed correctly in both modes. Preparation, process startup, audit, "
                "failures, and timeouts are excluded from the overhead estimate."
            ),
        },
    }
    (output / "statistics.json").write_text(json.dumps(statistics_output, indent=2) + "\n")

    lines = [
        "# Matched ordinary-demo results",
        "",
        f"Run `{args.run_id}` contains {len(records)} retained attempts in "
        f"{len(repetitions)} paired repetition blocks. The primary timer begins after "
        "application and Argus preparation. Audit is disabled in both primary modes.",
        "",
        "| Application | Baseline success | Argus success | Status B/A | Matched pairs | "
        "Preparation B/A (ms) | Invocation B/A (ms) | Ratio [95% CI] |",
        "|---|---:|---:|---|---:|---:|---:|---:|",
    ]
    for application in applications:
        item = results[application]
        baseline = item["modes"]["Baseline"]
        argus = item["modes"]["Argus"]
        ratio = (
            f"{item['ratio']:.3f}x [{item['ratio_ci95'][0]:.3f}, {item['ratio_ci95'][1]:.3f}]"
            if "ratio" in item
            else f"not reported ({item['exclusion']})"
        )
        baseline_status = (
            f"C{baseline['completed']}/F{baseline['compatibility_failures']}/"
            f"E{baseline['execution_errors']}/T{baseline['timeouts']}"
        )
        argus_status = (
            f"C{argus['completed']}/F{argus['compatibility_failures']}/"
            f"E{argus['execution_errors']}/T{argus['timeouts']}"
        )
        baseline_preparation = (
            f"{baseline['mean_preparation_ms']:.1f}"
            if baseline["mean_preparation_ms"] is not None
            else "n/a"
        )
        argus_preparation = (
            f"{argus['mean_preparation_ms']:.1f}"
            if argus["mean_preparation_ms"] is not None
            else "n/a"
        )
        baseline_invocation = (
            f"{baseline['matched_mean_invocation_ms']:.1f}"
            if baseline["matched_mean_invocation_ms"] is not None
            else "n/a"
        )
        argus_invocation = (
            f"{argus['matched_mean_invocation_ms']:.1f}"
            if argus["matched_mean_invocation_ms"] is not None
            else "n/a"
        )
        lines.append(
            f"| {application} | {baseline['correct']}/{baseline['attempts']} | "
            f"{argus['correct']}/{argus['attempts']} | {baseline_status} / {argus_status} | "
            f"{item['matched_successful_pairs']} | "
            f"{baseline_preparation}/{argus_preparation} | "
            f"{baseline_invocation}/{argus_invocation} | {ratio} |"
        )
    suite = statistics_output["suite"]
    equal_weight = suite["equal_application_weight_secondary"]
    lines.extend(
        (
            "",
            "The primary suite result pools invocation time from task/repetition pairs that "
            "completed correctly in both modes. It excludes preparation, interpreter startup, "
            "audit logging, failures, and timeout caps.",
            "Status abbreviations: C=completed, F=compatibility failure, "
            "E=execution error, T=timeout. D4 timeout durations are capped at 300 seconds.",
            "",
            f"Included applications: {', '.join(included)}.",
            f"Excluded applications: {', '.join(suite['excluded']) or 'none'}.",
            f"Pooled matched invocation ratio: **{suite_ratio:.3f}x** "
            f"(95% paired-block CI {suite['ratio_ci95'][0]:.3f}-"
            f"{suite['ratio_ci95'][1]:.3f}); "
            f"overhead **{suite['pooled_matched_overhead_percent']:.1f}%**.",
            "",
            "Excluded applications have no task/repetition pair that completed correctly in "
            "both modes. Their failures remain in the status table but are never treated as "
            "successful latency.",
            "",
            "The secondary equal-application-weight geometric mean is "
            f"**{equal_weight['geometric_mean_ratio']:.3f}x** "
            f"(95% CI {equal_weight['ratio_ci95'][0]:.3f}-"
            f"{equal_weight['ratio_ci95'][1]:.3f}); overhead "
            f"**{equal_weight['geometric_mean_overhead_percent']:.1f}%**. It is retained as "
            "a sensitivity analysis because very short applications can dominate ratios.",
            "",
            "Preparation and parent-process wall time remain in `statistics.json` as separate "
            "diagnostics. Audit-on performance is a separate special case and is not called "
            "Argus overhead.",
        )
    )
    (output / "RESULTS.md").write_text("\n".join(lines) + "\n")

    plotted = [item for item in applications if "ratio" in results[item]]
    values = [results[item]["ratio"] for item in plotted]
    lower = [
        value - results[item]["ratio_ci95"][0] for item, value in zip(plotted, values, strict=True)
    ]
    upper = [
        results[item]["ratio_ci95"][1] - value for item, value in zip(plotted, values, strict=True)
    ]
    figure, axis = plt.subplots(figsize=(12, 6))
    axis.bar(range(len(plotted)), values, color="#4C78A8")
    axis.errorbar(
        range(len(plotted)),
        values,
        yerr=[lower, upper],
        fmt="none",
        color="black",
        capsize=3,
    )
    axis.axhline(1.0, color="black", linewidth=1, linestyle="--")
    axis.set_ylabel("Matched invocation runtime (Baseline = 1.0x)")
    axis.set_xticks(range(len(plotted)), plotted, rotation=45, ha="right")
    axis.set_title("Argus invocation overhead; preparation and audit excluded")
    figure.tight_layout()
    figure.savefig(output / "application-overhead.png", dpi=180)
    plt.close(figure)


if __name__ == "__main__":
    main()
