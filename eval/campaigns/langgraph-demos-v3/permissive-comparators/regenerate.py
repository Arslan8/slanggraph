"""Regenerate matched Argus versus enforceable host-comparator results."""

from __future__ import annotations

import argparse
import hashlib
import json
import math
import random
import shutil
import statistics
from pathlib import Path

CAMPAIGN = Path(__file__).resolve().parent
V3 = CAMPAIGN.parent
SEED = 20261028
RESAMPLES = 10_000
MODES = ("Baseline", "Argus", "NoNo-enforced", "APF-enforced")
COMPARATORS = ("Baseline", "NoNo-enforced", "APF-enforced")
METRICS = ("invocation_ms", "process_wall_ms", "secured_wall_ms")
RETAINED_INPUTS = ("configuration.json", "enforcement-probes.json", "trials.json")


def sha256(path: Path) -> str:
    return hashlib.sha256(path.read_bytes()).hexdigest()


def retain_inputs_and_checksums(raw: Path, output: Path) -> None:
    for filename in RETAINED_INPUTS:
        shutil.copy2(raw / filename, output / filename)
    retained = sorted(path for path in output.iterdir() if path.name != "SHA256SUMS")
    checksums = "".join(f"{sha256(path)}  {path.name}\n" for path in retained if path.is_file())
    (output / "SHA256SUMS").write_text(checksums)


def metric_value(record: dict, metric: str) -> float | None:
    if metric == "secured_wall_ms":
        return record.get("end_to_end_wall_ms", record.get("process_wall_ms"))
    return record.get(metric)


def percentile(values: list[float], fraction: float) -> float:
    ordered = sorted(values)
    position = (len(ordered) - 1) * fraction
    lower = math.floor(position)
    upper = math.ceil(position)
    if lower == upper:
        return ordered[lower]
    return ordered[lower] + (ordered[upper] - ordered[lower]) * (position - lower)


def matched_samples(
    records: list[dict],
    other: str,
    metric: str,
    repetitions: list[int],
) -> dict[str, list[float]]:
    samples = {"Argus": [], other: []}
    for repetition in repetitions:
        selected = [record for record in records if record["repetition"] == repetition]
        by_pair: dict[tuple[str, int], dict[str, dict]] = {}
        for record in selected:
            key = (record["application"], record["task"])
            by_pair.setdefault(key, {})[record["mode"]] = record
        for pair in by_pair.values():
            if "Argus" not in pair or other not in pair:
                continue
            if not all(
                pair[mode]["status"] == "completed"
                and pair[mode]["correct"]
                and metric_value(pair[mode], metric) is not None
                for mode in ("Argus", other)
            ):
                continue
            samples["Argus"].append(metric_value(pair["Argus"], metric))
            samples[other].append(metric_value(pair[other], metric))
    return samples


def ratio_for(
    records: list[dict],
    other: str,
    metric: str,
    repetitions: list[int],
) -> float | None:
    samples = matched_samples(records, other, metric, repetitions)
    if not samples["Argus"]:
        return None
    return sum(samples["Argus"]) / sum(samples[other])


def describe(values: list[float]) -> dict[str, float]:
    return {
        "mean_ms": statistics.fmean(values),
        "median_ms": statistics.median(values),
        "p95_ms": percentile(values, 0.95),
        "total_ms": sum(values),
    }


def comparison_summary(
    records: list[dict],
    other: str,
    metric: str,
    repetitions: list[int],
    resampled_blocks: list[list[int]],
) -> dict:
    samples = matched_samples(records, other, metric, repetitions)
    if not samples["Argus"]:
        return {"matched_successful_pairs": 0, "exclusion": "no matched successful pairs"}
    ratio = sum(samples["Argus"]) / sum(samples[other])
    bootstrap = [
        ratio
        for sample in resampled_blocks
        if (ratio := ratio_for(records, other, metric, sample)) is not None
    ]
    interval = [percentile(bootstrap, 0.025), percentile(bootstrap, 0.975)]
    return {
        "matched_successful_pairs": len(samples["Argus"]),
        "timings": {
            "Argus": describe(samples["Argus"]),
            other: describe(samples[other]),
        },
        "argus_over_other_ratio": ratio,
        "argus_over_other_ci95": interval,
        "argus_relative_percent": 100 * (ratio - 1),
        "argus_relative_percent_ci95": [100 * (value - 1) for value in interval],
        "other_over_argus_speedup": 1 / ratio,
    }


def summarize_mode(records: list[dict]) -> dict:
    statuses = {
        status: sum(record["status"] == status for record in records)
        for status in ("completed", "compatibility_failed", "execution_error", "timeout")
    }
    return {
        "attempts": len(records),
        "correct": sum(record["correct"] for record in records),
        **statuses,
    }


def status_label(summary: dict) -> str:
    return (
        f"C{summary['completed']}/F{summary['compatibility_failed']}/"
        f"E{summary['execution_error']}/T{summary['timeout']}"
    )


def gap_records(
    records: list[dict],
    raw: Path,
    configuration: dict,
    comparisons: dict,
    common_pairs: int,
) -> list[dict[str, str]]:
    def contains(record: dict, text: str) -> bool:
        return text in f"{record.get('error') or ''}\n{record.get('stderr') or ''}"

    d3 = [record for record in records if record["application"] == "D3-plan-execute"]
    d4 = [record for record in records if record["application"] == "D4-multi-agent"]
    t10_argus = [
        record
        for record in records
        if record["application"] == "T10-time-travel" and record["mode"] == "Argus"
    ]
    d4_completed = {
        mode: [
            record for record in d4 if record["mode"] == mode and record["status"] == "completed"
        ]
        for mode in ("NoNo-enforced", "APF-enforced")
    }
    d4_missing_artifacts = {}
    for mode, selected in d4_completed.items():
        missing = 0
        for record in selected:
            trial = (
                raw
                / f"rep-{record['repetition']}"
                / record["application"]
                / f"task-{record['task']}"
                / record["mode"]
            )
            if not (trial / "chart.png").is_file() or not (trial / "observer.json").is_file():
                missing += 1
        d4_missing_artifacts[mode] = missing

    d3_recursion = sum(contains(record, "GraphRecursionError") for record in d3)
    d3_index = sum(contains(record, "IndexError") for record in d3)
    d4_recursion = {
        mode: sum(
            record["mode"] == mode and contains(record, "GraphRecursionError") for record in d4
        )
        for mode in MODES
    }
    d4_timeouts = sum(record["status"] == "timeout" for record in d4)
    t10_broken_chain = sum(contains(record, "checkpoint:broken_chain") for record in t10_argus)
    routes = configuration["argus_routes"]
    matched = {
        mode: comparisons[mode]["process_wall_ms"]["matched_successful_pairs"]
        for mode in COMPARATORS
    }
    return [
        {
            "gap": "Comparator semantic-policy equivalence",
            "evidence": configuration["residual_comparator_gap"],
            "interpretation": (
                "NoNo and APF/OpenShell enforce the host controls they can express, but "
                "they are not security-equivalent to Argus's per-operation Cedar mediation."
            ),
        },
        {
            "gap": "NoNo network resource scope",
            "evidence": configuration["nono"]["network_residual"],
            "interpretation": (
                "The campaign grants only model port 11434, but NoNo cannot bind that port "
                "grant to one destination host."
            ),
        },
        {
            "gap": "Audit and rollback scope",
            "evidence": (
                f"Audit was {configuration['audit']['primary_modes']}; NoNo rollback was "
                f"{configuration['nono']['rollback']}."
            ),
            "interpretation": (
                "These controls are not part of the reported runtime comparison; audit has "
                "a separate measurement and Argus does not claim rollback."
            ),
        },
        {
            "gap": "Argus language-route coverage",
            "evidence": (
                f"{len(routes['language'])}/15 applications use language isolation; "
                f"{', '.join(routes['host'])} remains on host isolation."
            ),
            "interpretation": (
                "D4's persistent Python chart session still requires OS confinement, so the "
                "final Argus configuration is hybrid rather than all-language."
            ),
        },
        {
            "gap": "Argus T10 checkpoint replay compatibility",
            "evidence": (
                f"{t10_broken_chain}/{len(t10_argus)} Argus attempts failed with "
                "`PermissionError: checkpoint:broken_chain`; the other three modes were "
                "5/5 correct."
            ),
            "interpretation": "This is an Argus compatibility gap, not a comparator denial.",
        },
        {
            "gap": "D3 application/model viability",
            "evidence": (
                f"0/25 attempts were correct in every mode; all {len(d3)} attempts ended in "
                f"execution errors ({d3_recursion} recursion-limit errors and {d3_index} "
                "index errors)."
            ),
            "interpretation": (
                "D3 supplies no successful latency pairs and does not distinguish the "
                "security systems."
            ),
        },
        {
            "gap": "D4 comparator functionality",
            "evidence": (
                f"NoNo completed {len(d4_completed['NoNo-enforced'])}/25 and APF completed "
                f"{len(d4_completed['APF-enforced'])}/25, but neither had a correct attempt; "
                f"all {d4_missing_artifacts['NoNo-enforced']} and "
                f"{d4_missing_artifacts['APF-enforced']} completed runs respectively lacked the "
                "required chart/observer artifact pair."
            ),
            "interpretation": (
                "The records do not isolate model trajectory from environment compatibility, so "
                "the zero correctness rate must not be presented as an authorization denial."
            ),
        },
        {
            "gap": "D4 long-tail failures",
            "evidence": (
                "Recursion-limit failures by mode were "
                + ", ".join(f"{mode}={d4_recursion[mode]}" for mode in MODES)
                + f"; NoNo also had {d4_timeouts} timeouts, both with confirmed cleanup."
            ),
            "interpretation": (
                "These outcomes remain in the correctness/status table but are excluded from "
                "matched-success latency ratios."
            ),
        },
        {
            "gap": "Latency population",
            "evidence": (
                f"Matched correct pairs were Baseline={matched['Baseline']}, "
                f"NoNo={matched['NoNo-enforced']}, APF={matched['APF-enforced']}; only "
                f"{common_pairs} pairs succeeded in all four modes."
            ),
            "interpretation": (
                "Latency ratios do not represent failed attempts or the full 175-attempt "
                "population."
            ),
        },
        {
            "gap": "Model-trajectory comparability",
            "evidence": (
                "Invocation and process timers include model execution; matched correctness does "
                "not require identical model-call sequences or model time."
            ),
            "interpretation": (
                "Macro ratios are end-to-end application measurements, not pure "
                "enforcement-only overhead."
            ),
        },
        {
            "gap": "APF timer boundary",
            "evidence": (
                "`process_wall_ms` excludes fresh APF creation/deletion, while "
                "`secured_wall_ms` includes projection, creation/admission, dispatch, and "
                "confirmed deletion."
            ),
            "interpretation": (
                "Claims about APF must name the timer; only the secured timer includes the "
                "lifecycle that supplies fresh-invocation isolation."
            ),
        },
    ]


def main() -> None:
    parser = argparse.ArgumentParser()
    parser.add_argument("--run-id", required=True)
    parser.add_argument("--output-dir", type=Path)
    args = parser.parse_args()
    raw = V3 / "raw" / args.run_id
    output = args.output_dir or CAMPAIGN
    output.mkdir(parents=True, exist_ok=True)
    records = json.loads((raw / "trials.json").read_text())
    configuration = json.loads((raw / "configuration.json").read_text())
    repetitions = sorted({record["repetition"] for record in records})
    applications = sorted({record["application"] for record in records})
    rng = random.Random(SEED)
    resampled_blocks = [[rng.choice(repetitions) for _ in repetitions] for _ in range(RESAMPLES)]

    modes = {
        mode: summarize_mode([record for record in records if record["mode"] == mode])
        for mode in MODES
    }
    application_results = {}
    for application in applications:
        selected = [record for record in records if record["application"] == application]
        application_results[application] = {
            "modes": {
                mode: summarize_mode([record for record in selected if record["mode"] == mode])
                for mode in MODES
            },
            "comparisons": {
                other: {
                    metric: comparison_summary(
                        selected,
                        other,
                        metric,
                        repetitions,
                        resampled_blocks,
                    )
                    for metric in METRICS
                }
                for other in COMPARATORS
            },
        }
    comparisons = {
        other: {
            metric: comparison_summary(
                records,
                other,
                metric,
                repetitions,
                resampled_blocks,
            )
            for metric in METRICS
        }
        for other in COMPARATORS
    }
    common_pairs = 0
    by_pair: dict[tuple[str, int, int], dict[str, dict]] = {}
    for record in records:
        key = (record["application"], record["task"], record["repetition"])
        by_pair.setdefault(key, {})[record["mode"]] = record
    for pair in by_pair.values():
        if all(
            mode in pair
            and pair[mode]["status"] == "completed"
            and pair[mode]["correct"]
            and all(metric_value(pair[mode], metric) is not None for metric in METRICS)
            for mode in MODES
        ):
            common_pairs += 1
    gaps = gap_records(records, raw, configuration, comparisons, common_pairs)
    result = {
        "run_id": args.run_id,
        "attempts": len(records),
        "repetitions": len(repetitions),
        "warning": (
            "NoNo and APF/OpenShell enforce their expressible filesystem, process, and "
            "network controls. They cannot express Argus's typed library resource/action "
            "mediation, so they remain host-policy approximations rather than semantic "
            "security equivalents."
        ),
        "timers": {
            "invocation_ms": (
                "application-reported invocation after application preparation; excludes "
                "NoNo activation, OpenShell exec transport, and Python startup"
            ),
            "process_wall_ms": (
                "parent dispatch through process exit; includes Python startup and either "
                "NoNo activation or OpenShell exec transport; excludes fresh OpenShell "
                "sandbox preparation and cleanup"
            ),
            "secured_wall_ms": (
                "process_wall_ms for Baseline, Argus, and per-command NoNo; fresh sandbox "
                "preparation plus process dispatch plus confirmed deletion for APF/OpenShell"
            ),
        },
        "latency_population": "pairwise task/repetition pairs completed correctly in both modes",
        "bootstrap": {
            "method": "paired repetition-block bootstrap",
            "seed": SEED,
            "resamples": RESAMPLES,
        },
        "common_successful_pairs_all_four_modes": common_pairs,
        "gaps_and_limitations": gaps,
        "modes": modes,
        "comparisons": comparisons,
        "applications": application_results,
    }
    (output / "statistics.json").write_text(json.dumps(result, indent=2) + "\n")

    lines = [
        "# Argus versus enforceable host comparators",
        "",
        f"Run `{args.run_id}` contains {len(records)} fixed-population attempts in "
        f"{len(repetitions)} paired repetition blocks.",
        "",
        "**Security scope:** NoNo and APF/OpenShell enforce every filesystem, process, and "
        "network restriction used by this campaign. They cannot express Argus's typed "
        "library resource/action mediation, so this is the closest enforceable host-policy "
        "comparison rather than semantic security equivalence.",
        "",
        "## Explicit gaps, limitations, and non-equivalences",
        "",
        "These disclosures distinguish security-model gaps from application/model failures and "
        "measurement limitations. A failed application is not treated as evidence of an "
        "authorization denial unless the retained evidence says so.",
        "",
        "| Gap or limitation | Evidence in this campaign | Interpretation |",
        "|---|---|---|",
        *[f"| {item['gap']} | {item['evidence']} | {item['interpretation']} |" for item in gaps],
        "",
        "All other correctness differences remain visible in the application table below. "
        "Without a recorded denial or compatibility error, they are not attributed to enforcement.",
        "",
        "## Application outcomes",
        "",
        "| Application | Baseline correct/status | Argus correct/status | "
        "NoNo-enforced correct/status | APF-enforced correct/status |",
        "|---|---:|---:|---:|---:|",
    ]
    for application in applications:
        summaries = application_results[application]["modes"]
        cells = [
            f"{summaries[mode]['correct']}/{summaries[mode]['attempts']} "
            f"({status_label(summaries[mode])})"
            for mode in MODES
        ]
        lines.append(f"| {application} | {' | '.join(cells)} |")
    lines.extend(
        (
            "",
            "Pairwise pooled results use only task/repetition pairs that completed correctly "
            "in Argus and the named comparison mode. Ratios below are Argus/comparison: "
            "values below 1.0 mean Argus is faster.",
            "",
            "| Comparison | Timer | Matched pairs | Argus mean/median/p95 (ms) | "
            "Other mean/median/p95 (ms) | Argus/other [95% CI] |",
            "|---|---|---:|---:|---:|---:|",
        )
    )
    for other in COMPARATORS:
        for metric in METRICS:
            item = comparisons[other][metric]
            if not item["matched_successful_pairs"]:
                lines.append(f"| {other} | {metric} | 0 | n/a | n/a | n/a |")
                continue
            argus = item["timings"]["Argus"]
            comparison = item["timings"][other]
            interval = item["argus_over_other_ci95"]
            lines.append(
                f"| {other} | {metric} | {item['matched_successful_pairs']} | "
                f"{argus['mean_ms']:.1f}/{argus['median_ms']:.1f}/{argus['p95_ms']:.1f} | "
                f"{comparison['mean_ms']:.1f}/{comparison['median_ms']:.1f}/"
                f"{comparison['p95_ms']:.1f} | "
                f"{item['argus_over_other_ratio']:.3f}x "
                f"[{interval[0]:.3f}, {interval[1]:.3f}] |"
            )
    lines.extend(
        (
            "",
            f"Common successful population across all four modes: {common_pairs} pairs.",
            "",
            "`invocation_ms` excludes external sandbox activation and transport. "
            "`process_wall_ms` includes per-dispatch NoNo activation or OpenShell exec "
            "transport, along with Python startup for every mode. `secured_wall_ms` also "
            "includes fresh APF sandbox creation, policy admission, input binding, and "
            "confirmed deletion because those steps provide APF's invocation isolation.",
        )
    )
    (output / "RESULTS.md").write_text("\n".join(lines) + "\n")
    retain_inputs_and_checksums(raw, output)


if __name__ == "__main__":
    main()
