"""Regenerate inline lifecycle-checker performance statistics."""

from __future__ import annotations

import json
import math
import random
import statistics
from collections import defaultdict
from pathlib import Path

ROOT = Path(__file__).resolve().parent
CURRENT = ROOT / "raw/landlock-aggressive"
PREVIOUS = ROOT.parent / "worker-broker-optimization-v1/raw/landlock-aggressive"
SEED = 20261030
RESAMPLES = 100_000
T_DF4 = 2.776445


def read_rows(path: Path) -> list[dict]:
    return [
        json.loads(line)
        for source in sorted(path.glob("session-*.jsonl"))
        for line in source.read_text().splitlines()
        if line
    ]


def session_means(rows: list[dict], field: str, phase: str) -> list[float]:
    grouped: dict[int, list[float]] = defaultdict(list)
    for row in rows:
        if (
            row.get("kind") == "call"
            and row.get("route") == "landlock"
            and row.get("phase") == phase
        ):
            grouped[int(row["session"])].append(float(row[field]))
    expected = 20 if phase == "measured" else 1
    if sorted(grouped) != list(range(5)) or any(
        len(values) != expected for values in grouped.values()
    ):
        raise ValueError(f"expected five complete sessions for {field}/{phase}")
    return [statistics.fmean(grouped[index]) for index in range(5)]


def interval(values: list[float]) -> dict:
    mean = statistics.fmean(values)
    half = T_DF4 * statistics.stdev(values) / math.sqrt(5)
    return {"n_sessions": 5, "mean": mean, "ci95": [mean - half, mean + half]}


def ratio(current: list[float], previous: list[float]) -> dict:
    rng = random.Random(SEED)
    samples = []
    for _ in range(RESAMPLES):
        now = statistics.fmean(rng.choice(current) for _ in current)
        old = statistics.fmean(rng.choice(previous) for _ in previous)
        samples.append(now / old)
    samples.sort()
    value = statistics.fmean(current) / statistics.fmean(previous)
    return {
        "ratio": value,
        "reduction_percent": 100 * (1 - value),
        "ci95": [samples[2_500], samples[97_499]],
        "method": "independent-session bootstrap of ratio of means",
        "seed": SEED,
        "resamples": RESAMPLES,
    }


def main() -> None:
    current_rows = read_rows(CURRENT)
    previous_rows = read_rows(PREVIOUS)
    current = session_means(current_rows, "elapsed_ms", "measured")
    previous = session_means(previous_rows, "elapsed_ms", "measured")
    previous_decision = session_means(previous_rows, "lean_ms", "measured")
    first = session_means(current_rows, "elapsed_ms", "first_use")
    phases = {
        field: interval(session_means(current_rows, field, "measured"))
        for field in (
            "authorization_ms",
            "lean_ms",
            "activation_ms",
            "execution_ms",
            "audit_ms",
            "cleanup_ms",
            "framework_residual_ms",
        )
    }
    setup = [row for row in current_rows if row.get("kind") == "setup"]
    if len(setup) != 5:
        raise ValueError("expected five setup records")
    output = {
        "evaluated_revision": "c1bdeff5c",
        "protocol": "5 fresh sessions, 1 first use, 10 warmups, 20 measured calls per session",
        "timer_scope": (
            "per-call recurring work; native-library loading and campaign preflight are setup"
        ),
        "all_measured_calls_valid": all(
            row.get("valid")
            for row in current_rows
            if row.get("kind") == "call" and row.get("phase") == "measured"
        ),
        "first_use_ms": interval(first),
        "reused_ms": interval(current),
        "previous_subprocess_reused_ms": interval(previous),
        "previous_subprocess_decision_ms": interval(previous_decision),
        "inline_over_subprocess": ratio(current, previous),
        "phases": phases,
        "checker_setup_ms": interval([float(row["checker_setup_ms"]) for row in setup]),
        "artifact": {
            "library": setup[0]["lean_binary"],
            "library_sha256": setup[0]["lean_sha256"],
            "runtime": setup[0]["lean_runtime"],
            "runtime_sha256": setup[0]["lean_runtime_sha256"],
            "execution": setup[0]["lean_execution"],
        },
        "comparison_caveat": (
            "campaigns ran sequentially; sessions are independent rather than interleaved"
        ),
    }
    (ROOT / "statistics.json").write_text(json.dumps(output, indent=2) + "\n")

    change = output["inline_over_subprocess"]
    decision_reduction = 100 * (1 - phases["lean_ms"]["mean"] / statistics.fmean(previous_decision))
    lines = [
        "# Inline lifecycle-checker performance",
        "",
        "The proved decision procedure is loaded once from a sealed native "
        "library and called inline. The measured call boundary includes every "
        "recurring authorization, lifecycle decision, activation, execution, "
        "audit, cleanup, and framework cost; library loading is recorded "
        "separately as setup.",
        "",
        "| Result | Sealed subprocess | Inline native | Change |",
        "|---|---:|---:|---:|",
        f"| Reused Landlock call | {output['previous_subprocess_reused_ms']['mean']:.2f} ms | "
        f"{output['reused_ms']['mean']:.2f} ms | {change['reduction_percent']:.1f}% reduction |",
        f"| Lifecycle decision phase | {statistics.fmean(previous_decision):.2f} ms | "
        f"{phases['lean_ms']['mean']:.2f} ms | "
        f"{decision_reduction:.1f}% reduction |",
        "",
        f"The reused-call ratio is **{change['ratio']:.3f}x** with an "
        "independent-session bootstrap 95% interval of "
        f"**[{change['ci95'][0]:.3f}, {change['ci95'][1]:.3f}]** "
        f"(100,000 resamples, seed {SEED}). Because the campaigns were "
        "sequential rather than interleaved, the comparison can include host drift.",
        "",
        "## Current phase means",
        "",
        "| Phase | Mean ms |",
        "|---|---:|",
    ]
    for name, item in phases.items():
        label = "native lifecycle decision" if name == "lean_ms" else name.removesuffix("_ms")
        lines.append(f"| {label} | {item['mean']:.2f} |")
    lines.extend(
        [
            "",
            f"First use is {output['first_use_ms']['mean']:.2f} ms. Loading "
            "and digest-checking the pinned native artifacts costs "
            f"{output['checker_setup_ms']['mean']:.2f} ms per fresh process "
            "session and is reported as setup, not recurring execution overhead.",
        ]
    )
    (ROOT / "RESULTS.md").write_text("\n".join(lines) + "\n")


if __name__ == "__main__":
    main()
