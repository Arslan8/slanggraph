# ruff: noqa: E501
"""Analyze the paired Baseline/slangGraph Pandas overhead campaign."""

from __future__ import annotations

import argparse
import json
import math
import random
import statistics
from collections import defaultdict
from pathlib import Path

BOOTSTRAP_SEED = 20261030
BOOTSTRAP_RESAMPLES = 100_000


def percentile(values: list[float], probability: float) -> float:
    ordered = sorted(values)
    position = probability * (len(ordered) - 1)
    lower = math.floor(position)
    upper = math.ceil(position)
    if lower == upper:
        return ordered[lower]
    weight = position - lower
    return ordered[lower] * (1 - weight) + ordered[upper] * weight


def ratio(baseline: list[float], protected: list[float]) -> float:
    return statistics.mean(protected) / statistics.mean(baseline)


def block_bootstrap(rows: list[dict], *, matched_success: bool) -> dict:
    blocks: dict[int, dict[str, list[float]]] = defaultdict(
        lambda: {"Baseline": [], "slangGraph": []}
    )
    pairs: dict[tuple[int, str], dict[str, dict]] = defaultdict(dict)
    for row in rows:
        pairs[(int(row["repeat"]), str(row["case_id"]))][str(row["mode"])] = row
    for (repetition, _), pair in pairs.items():
        if set(pair) != {"Baseline", "slangGraph"}:
            raise ValueError("Every repetition/task must contain both conditions")
        if matched_success and not all(item["legitimate_result"] for item in pair.values()):
            continue
        for condition in ("Baseline", "slangGraph"):
            blocks[repetition][condition].append(float(pair[condition]["analysis_wall_ms"]))
    repetitions = sorted({int(row["repeat"]) for row in rows})
    if repetitions != list(range(5)):
        raise ValueError("The interval requires five paired repetition blocks")
    randomizer = random.Random(BOOTSTRAP_SEED + int(matched_success))
    samples = []
    for _ in range(BOOTSTRAP_RESAMPLES):
        selected = randomizer.choices(repetitions, k=len(repetitions))
        baseline = [value for block in selected for value in blocks[block]["Baseline"]]
        protected = [value for block in selected for value in blocks[block]["slangGraph"]]
        if baseline and protected:
            samples.append(ratio(baseline, protected))
    if not samples:
        return {"available": False}
    return {
        "available": True,
        "low": percentile(samples, 0.025),
        "high": percentile(samples, 0.975),
        "resamples": BOOTSTRAP_RESAMPLES,
        "seed": BOOTSTRAP_SEED + int(matched_success),
        "unit": "paired repetition block containing ten tasks in both conditions",
        "method": "percentile bootstrap of the ratio of complete-condition means",
    }


def svg(summary: dict) -> str:
    result = summary["primary"]
    ratio_value = result["ratio"]
    low = result["ratio_ci95"]["low"]
    high = result["ratio_ci95"]["high"]
    maximum = max(1.2, high * 1.18)
    chart_top = 50
    chart_bottom = 330
    chart_height = chart_bottom - chart_top

    def y(value: float) -> float:
        return chart_bottom - value / maximum * chart_height

    baseline_y = y(1.0)
    protected_y = y(ratio_value)
    error_low = y(low)
    error_high = y(high)
    ticks = [index * maximum / 5 for index in range(6)]
    lines = [
        '<svg xmlns="http://www.w3.org/2000/svg" width="760" height="460" viewBox="0 0 760 460">',
        '<rect width="760" height="460" fill="white"/>',
        '<text x="380" y="25" text-anchor="middle" font-family="sans-serif" font-size="18">Matched Pandas complete-system runtime</text>',
    ]
    for tick in ticks:
        tick_y = y(tick)
        lines.append(
            f'<line x1="90" y1="{tick_y:.1f}" x2="700" y2="{tick_y:.1f}" stroke="#dddddd"/>'
        )
        lines.append(
            f'<text x="80" y="{tick_y + 5:.1f}" text-anchor="end" font-family="sans-serif" font-size="12">{tick:.2f}x</text>'
        )
    lines += [
        f'<rect x="200" y="{baseline_y:.1f}" width="120" height="{chart_bottom - baseline_y:.1f}" fill="#8da0cb"/>',
        f'<rect x="470" y="{protected_y:.1f}" width="120" height="{chart_bottom - protected_y:.1f}" fill="#fc8d62"/>',
        f'<line x1="530" y1="{error_high:.1f}" x2="530" y2="{error_low:.1f}" stroke="black" stroke-width="2"/>',
        f'<line x1="515" y1="{error_high:.1f}" x2="545" y2="{error_high:.1f}" stroke="black" stroke-width="2"/>',
        f'<line x1="515" y1="{error_low:.1f}" x2="545" y2="{error_low:.1f}" stroke="black" stroke-width="2"/>',
        '<text x="260" y="355" text-anchor="middle" font-family="sans-serif" font-size="15">Baseline</text>',
        '<text x="530" y="355" text-anchor="middle" font-family="sans-serif" font-size="15">slangGraph</text>',
        '<text x="260" y="42" text-anchor="middle" font-family="sans-serif" font-size="14">1.00x</text>',
        f'<text x="530" y="{max(42, protected_y - 28):.1f}" text-anchor="middle" font-family="sans-serif" font-size="14">{ratio_value:.2f}x</text>',
        '<text x="380" y="395" text-anchor="middle" font-family="sans-serif" font-size="12">Baseline is the same adapted application without slangGraph enforcement.</text>',
        '<text x="380" y="415" text-anchor="middle" font-family="sans-serif" font-size="12">slangGraph includes closed admission, policies, mediation, isolation, audit, and per-call Lean validation.</text>',
        f'<text x="380" y="435" text-anchor="middle" font-family="sans-serif" font-size="12">95% percentile interval: paired five-block bootstrap, {BOOTSTRAP_RESAMPLES:,} resamples, seed {BOOTSTRAP_SEED}.</text>',
        "</svg>",
    ]
    return "\n".join(lines) + "\n"


def run(raw: Path, output: Path) -> None:
    rows = [json.loads(line) for line in (raw / "trials.jsonl").read_text().splitlines()]
    selected = [row for row in rows if row.get("mode") in {"Baseline", "slangGraph"}]
    counts = {
        condition: sum(row["mode"] == condition for row in selected)
        for condition in ("Baseline", "slangGraph")
    }
    if counts != {"Baseline": 50, "slangGraph": 50}:
        raise ValueError(f"Expected 50 trials per condition, got {counts}")
    by_condition = {
        condition: [row for row in selected if row["mode"] == condition]
        for condition in ("Baseline", "slangGraph")
    }
    baseline_values = [float(row["analysis_wall_ms"]) for row in by_condition["Baseline"]]
    protected_values = [float(row["analysis_wall_ms"]) for row in by_condition["slangGraph"]]
    primary_ratio = ratio(baseline_values, protected_values)
    primary_interval = block_bootstrap(selected, matched_success=False)
    successful_pairs = []
    paired = defaultdict(dict)
    for row in selected:
        paired[(row["repeat"], row["case_id"])][row["mode"]] = row
    for pair in paired.values():
        if set(pair) == {"Baseline", "slangGraph"} and all(
            item["legitimate_result"] for item in pair.values()
        ):
            successful_pairs.append(pair)
    secondary_baseline = [float(pair["Baseline"]["analysis_wall_ms"]) for pair in successful_pairs]
    secondary_protected = [
        float(pair["slangGraph"]["analysis_wall_ms"]) for pair in successful_pairs
    ]

    def condition_summary(values: list[dict]) -> dict:
        failure_cases: dict[str, int] = defaultdict(int)
        status_counts: dict[str, int] = defaultdict(int)
        for row in values:
            status_counts[str(row["status"])] += 1
            if not row["legitimate_result"]:
                failure_cases[str(row["case_id"])] += 1
        return {
            "internal_configuration": sorted({row["internal_configuration"] for row in values}),
            "attempts": len(values),
            "successes": sum(bool(row["legitimate_result"]) for row in values),
            "failures_by_task": dict(sorted(failure_cases.items())),
            "status_counts": dict(sorted(status_counts.items())),
            "timeouts": sum(row["status"] == "timeout" for row in values),
            "timeout_cap_ms": 180_000,
            "output_validation_failures": sum(
                int(row["output_validation_failures"]) for row in values
            ),
            "mean_complete_system_wall_ms": statistics.mean(
                float(row["analysis_wall_ms"]) for row in values
            ),
            "mean_observed_wall_ms": statistics.mean(float(row["wall_ms"]) for row in values),
            "mean_startup_setup_ms": statistics.mean(
                float(row["startup_setup_ms"])
                for row in values
                if row.get("startup_setup_ms") is not None
            ),
            "mean_model_ms": statistics.mean(float(row["model_ms"]) for row in values),
            "model_calls": sum(int(row["model_calls"]) for row in values),
        }

    summary = {
        "artifact": str(raw),
        "conditions": {
            condition: condition_summary(values) for condition, values in by_condition.items()
        },
        "primary": {
            "estimand": "ratio of condition means over all 100 attempted task trials",
            "ratio": primary_ratio,
            "overhead_percent": 100 * (primary_ratio - 1),
            "ratio_ci95": primary_interval,
            "overhead_percent_ci95": {
                "low": 100 * (primary_interval["low"] - 1),
                "high": 100 * (primary_interval["high"] - 1),
            },
        },
        "secondary_matched_success": {
            "pairs": len(successful_pairs),
            "baseline_mean_ms": statistics.mean(secondary_baseline),
            "slanggraph_mean_ms": statistics.mean(secondary_protected),
            "ratio": ratio(secondary_baseline, secondary_protected),
            "ratio_ci95": block_bootstrap(selected, matched_success=True),
            "not_primary_reason": "Excludes any pair where either condition refused or failed",
        },
        "interval_warning": (
            "Only five independent paired repetition blocks are available; task trials "
            "within a block are not treated as independent repetitions."
        ),
        "preflight": json.loads((raw / "preflight.json").read_text()),
    }
    output.mkdir(parents=True, exist_ok=True)
    (output / "statistics.json").write_text(json.dumps(summary, indent=2) + "\n")
    (output / "application-overhead.svg").write_text(svg(summary))
    baseline = summary["conditions"]["Baseline"]
    protected = summary["conditions"]["slangGraph"]
    interval = summary["primary"]["ratio_ci95"]
    secondary = summary["secondary_matched_success"]
    markdown = f"""# Matched Pandas complete-system overhead

## Primary result

| Condition | Internal configuration | Attempts | Success | Timeouts | Mean complete-system wall time |
|---|---|---:|---:|---:|---:|
| Baseline | `Baseline` | {baseline["attempts"]} | {baseline["successes"]}/{baseline["attempts"]} | {baseline["timeouts"]}/{baseline["attempts"]} | {baseline["mean_complete_system_wall_ms"]:.1f} ms |
| slangGraph | `C-full-lean` | {protected["attempts"]} | {protected["successes"]}/{protected["attempts"]} | {protected["timeouts"]}/{protected["attempts"]} | {protected["mean_complete_system_wall_ms"]:.1f} ms |

Across the complete set of 100 attempted task trials, slangGraph is **{primary_ratio:.3f}x** the Baseline runtime, or **{100 * (primary_ratio - 1):.1f}% overhead**. The paired-block 95% interval is **[{interval["low"]:.3f}x, {interval["high"]:.3f}x]**, corresponding to **[{100 * (interval["low"] - 1):.1f}%, {100 * (interval["high"] - 1):.1f}%]** overhead.

The interval is a percentile bootstrap of the ratio of means with {BOOTSTRAP_RESAMPLES:,} resamples and seed `{BOOTSTRAP_SEED}`. Each resampling unit is one paired repetition block containing all ten tasks in both conditions. With only five blocks, precision is limited; the 100 task trials are not treated as independent repetitions.

Timeouts use a 180,000 ms cap in the primary estimand. The table reports timeout counts explicitly; capped durations are retained rather than discarded.

## Correctness and matched-success sensitivity

Baseline succeeded on {baseline["successes"]}/{baseline["attempts"]} attempts; slangGraph succeeded on {protected["successes"]}/{protected["attempts"]}. Baseline completed all five `monthly_mean` trials, while slangGraph refused all five at the preserved non-finite output-validation boundary. The primary comparison retains every attempt, including those five protected failures. The secondary matched-success analysis contains {secondary["pairs"]} task/repetition pairs, with means {secondary["baseline_mean_ms"]:.1f} ms and {secondary["slanggraph_mean_ms"]:.1f} ms and ratio {secondary["ratio"]:.3f}x. It is supporting analysis, not a replacement for the primary result.

## Measurement boundary

Both bars use the same subprocess wall-clock boundary: interpreter startup, application preparation, model callbacks, retries, computation, conversions, and output production. Common campaign preparation and the shared model warmup are excluded symmetrically and recorded in `raw/setup.json`. slangGraph additionally includes closed admission, principal and sealed operator policies, dataset/resource mediation, Linux isolation, security audit, output mediation, and per-call Lean runtime validation. Baseline uses direct dataset loading and the application's vendor sandbox subprocess with no slangGraph authorization, activation, broker, audit, or runtime validator.

![Matched Pandas overhead](application-overhead.svg)
"""
    (output / "RESULTS.md").write_text(markdown)


if __name__ == "__main__":
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--raw", required=True, type=Path)
    parser.add_argument("--output", required=True, type=Path)
    arguments = parser.parse_args()
    run(arguments.raw, arguments.output)
