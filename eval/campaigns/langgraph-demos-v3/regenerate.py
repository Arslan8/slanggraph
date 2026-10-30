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


def ratio_for(records: list[dict], repetitions: list[int]) -> float:
    samples = {mode: [] for mode in MODES}
    for repetition in repetitions:
        for record in records:
            if record["repetition"] == repetition:
                samples[record["mode"]].append(record["wall_ms"])
    return statistics.fmean(samples["Argus"]) / statistics.fmean(samples["Baseline"])


def summarize_mode(records: list[dict]) -> dict:
    model_times = [item["model_time_ms"] for item in records if item["model_time_ms"] is not None]
    return {
        "attempts": len(records),
        "completed": sum(item["status"] == "completed" for item in records),
        "correct": sum(item["correct"] for item in records),
        "timeouts": sum(item["status"] == "timeout" for item in records),
        "compatibility_failures": sum(item["status"] == "compatibility_failed" for item in records),
        "execution_errors": sum(item["status"] == "execution_error" for item in records),
        "mean_wall_ms": statistics.fmean(item["wall_ms"] for item in records),
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
        paired = len({item["task"] for item in selected if item["mode"] == "Baseline"}) == len(
            {item["task"] for item in selected if item["mode"] == "Argus"}
        ) and all(modes[mode]["attempts"] > 0 for mode in MODES)
        runnable = all(modes[mode]["completed"] > 0 for mode in MODES)
        application_result = {"modes": modes, "paired": paired, "runnable": runnable}
        if paired and runnable:
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
                "unpaired cohort" if not paired else "no completed trial in at least one mode"
            )
        results[application] = application_result

    ratios = [results[item]["ratio"] for item in included]
    suite_ratio = math.exp(statistics.fmean(math.log(value) for value in ratios))
    suite_bootstrap = []
    for sample in resampled_blocks:
        sampled_ratios = []
        for application in included:
            selected = [item for item in records if item["application"] == application]
            sampled_ratios.append(ratio_for(selected, sample))
        suite_bootstrap.append(
            math.exp(statistics.fmean(math.log(value) for value in sampled_ratios))
        )
    utility_matched = [
        application
        for application in included
        if results[application]["modes"]["Baseline"]["correct"]
        == results[application]["modes"]["Argus"]["correct"]
    ]
    utility_ratio = math.exp(
        statistics.fmean(math.log(results[item]["ratio"]) for item in utility_matched)
    )
    utility_bootstrap = []
    for sample in resampled_blocks:
        sampled_ratios = []
        for application in utility_matched:
            selected = [item for item in records if item["application"] == application]
            sampled_ratios.append(ratio_for(selected, sample))
        utility_bootstrap.append(
            math.exp(statistics.fmean(math.log(value) for value in sampled_ratios))
        )
    statistics_output = {
        "run_id": args.run_id,
        "primary_timer": "parent subprocess wall clock including process startup",
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
            "geometric_mean_ratio": suite_ratio,
            "geometric_mean_overhead_percent": 100 * (suite_ratio - 1),
            "ratio_ci95": [
                percentile(suite_bootstrap, 0.025),
                percentile(suite_bootstrap, 0.975),
            ],
            "overhead_ci95_percent": [
                100 * (percentile(suite_bootstrap, 0.025) - 1),
                100 * (percentile(suite_bootstrap, 0.975) - 1),
            ],
            "utility_matched_secondary": {
                "included": utility_matched,
                "geometric_mean_ratio": utility_ratio,
                "geometric_mean_overhead_percent": 100 * (utility_ratio - 1),
                "ratio_ci95": [
                    percentile(utility_bootstrap, 0.025),
                    percentile(utility_bootstrap, 0.975),
                ],
                "overhead_ci95_percent": [
                    100 * (percentile(utility_bootstrap, 0.025) - 1),
                    100 * (percentile(utility_bootstrap, 0.975) - 1),
                ],
                "interpretation": (
                    "Sensitivity analysis limited to applications with identical task-success "
                    "counts in both modes; it is not a replacement suite average."
                ),
            },
            "interpretation": (
                "Attempt-duration summary over runnable applications. Differing correctness, "
                "compatibility failures, and capped timeouts remain in the means, so this is "
                "not a pure enforcement-only overhead estimate."
            ),
        },
    }
    (output / "statistics.json").write_text(json.dumps(statistics_output, indent=2) + "\n")

    lines = [
        "# Matched ordinary-demo results",
        "",
        f"Run `{args.run_id}` contains {len(records)} retained attempts in "
        f"{len(repetitions)} paired repetition blocks. The primary timer includes process startup.",
        "",
        "| Application | Baseline success | Argus success | Status B/A | "
        "Baseline mean (ms) | Argus mean (ms) | Ratio [95% CI] |",
        "|---|---:|---:|---|---:|---:|---:|",
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
        lines.append(
            f"| {application} | {baseline['correct']}/{baseline['attempts']} | "
            f"{argus['correct']}/{argus['attempts']} | {baseline_status} / {argus_status} | "
            f"{baseline['mean_wall_ms']:.1f} | {argus['mean_wall_ms']:.1f} | {ratio} |"
        )
    suite = statistics_output["suite"]
    utility = suite["utility_matched_secondary"]
    lines.extend(
        (
            "",
            "The suite result is the geometric mean of per-application attempt-duration ratios, "
            "not a pooled ratio or arithmetic mean of percentages. Because utility and failure "
            "status differ for some included applications, it is not a pure enforcement-only "
            "overhead estimate.",
            "Status abbreviations: C=completed, F=compatibility failure, "
            "E=execution error, T=timeout. D4 timeout durations are capped at 300 seconds.",
            "",
            f"Included applications: {', '.join(included)}.",
            f"Excluded applications: {', '.join(suite['excluded']) or 'none'}.",
            f"Geometric-mean ratio: **{suite_ratio:.3f}x** "
            f"(95% paired-block CI {suite['ratio_ci95'][0]:.3f}-"
            f"{suite['ratio_ci95'][1]:.3f}); "
            f"overhead **{suite['geometric_mean_overhead_percent']:.1f}%**.",
            "",
            "No defensible overhead average exists over all 15 applications. Excluded "
            "applications have no completed trial in at least one mode; their failed-attempt "
            "durations are retained in the table but never treated as successful latency.",
            "",
            "As a secondary sensitivity analysis, applications with the same success count "
            "in both modes have geometric-mean ratio "
            f"**{utility['geometric_mean_ratio']:.3f}x** "
            f"(95% CI {utility['ratio_ci95'][0]:.3f}-"
            f"{utility['ratio_ci95'][1]:.3f}); overhead "
            f"**{utility['geometric_mean_overhead_percent']:.1f}%** across "
            f"{len(utility['included'])} applications.",
            "",
            "Timeout-capped attempts, failures, and refusals remain in the per-mode means. "
            "Success counts are reported separately so a failed fast run is not presented "
            "as useful speed.",
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
    axis.set_ylabel("Complete-system runtime (matching Baseline = 1.0x)")
    axis.set_xticks(range(len(plotted)), plotted, rotation=45, ha="right")
    axis.set_title("Argus ordinary-demo overhead; paired repetition-block 95% intervals")
    figure.tight_layout()
    figure.savefig(output / "application-overhead.png", dpi=180)
    plt.close(figure)


if __name__ == "__main__":
    main()
