"""Regenerate route costs and compare them with the preceding aggressive run."""

from __future__ import annotations

import json
import math
import random
import statistics
from collections import defaultdict
from pathlib import Path

ROOT = Path(__file__).resolve().parent
REPO = ROOT.parents[2]
RAW = ROOT / "raw"
PREVIOUS = REPO / "eval/campaigns/aggressive-optimization-v1/raw"
SEED = 20261029
RESAMPLES = 100_000
T_DF4 = 2.776445
ROUTES = {
    "language": ("language", "upstream"),
    "landlock-aggressive": ("landlock", "upstream"),
    "container": ("container", "direct-container"),
    "broker": ("broker", "direct-broker"),
}


def rows(root: Path, name: str) -> list[dict]:
    return [
        json.loads(line)
        for path in sorted((root / name).glob("session-*.jsonl"))
        for line in path.read_text().splitlines()
        if line
    ]


def sessions(data: list[dict], route: str, field: str, phase: str) -> list[float]:
    grouped: dict[int, list[float]] = defaultdict(list)
    for row in data:
        if row.get("kind") == "call" and row.get("route") == route and row.get("phase") == phase:
            grouped[int(row["session"])].append(float(row[field]))
    expected = 20 if phase == "measured" else 1
    if sorted(grouped) != list(range(5)) or any(len(value) != expected for value in grouped.values()):
        raise ValueError(f"incomplete {route}/{phase}/{field}")
    return [statistics.fmean(grouped[index]) for index in range(5)]


def interval(values: list[float]) -> dict:
    mean = statistics.fmean(values)
    half = T_DF4 * statistics.stdev(values) / math.sqrt(5)
    return {"n_sessions": 5, "mean": mean, "ci95": [mean - half, mean + half]}


def bootstrap(current: list[float], previous: list[float]) -> dict:
    rng = random.Random(SEED)
    samples = []
    for _ in range(RESAMPLES):
        now = statistics.fmean(rng.choice(current) for _ in current)
        before = statistics.fmean(rng.choice(previous) for _ in previous)
        samples.append(now / before)
    samples.sort()
    ratio = statistics.fmean(current) / statistics.fmean(previous)
    return {
        "ratio": ratio,
        "percent_change": 100 * (ratio - 1),
        "ci95": [samples[2_500], samples[97_499]],
        "method": "independent-session bootstrap of ratio of means",
        "seed": SEED,
        "resamples": RESAMPLES,
    }


def main() -> None:
    results = {}
    for name, (route, baseline) in ROUTES.items():
        current_rows = rows(RAW, name)
        previous_rows = rows(PREVIOUS, name)
        measured_rows = [
            row for row in current_rows
            if row.get("kind") == "call" and row.get("route") == route and row.get("phase") == "measured"
        ]
        if len(measured_rows) != 100 or not all(row.get("valid") for row in measured_rows):
            raise ValueError(f"{name}: expected 100 valid calls")
        current = sessions(current_rows, route, "elapsed_ms", "measured")
        direct = sessions(current_rows, baseline, "elapsed_ms", "measured")
        first = sessions(current_rows, route, "elapsed_ms", "first_use")
        previous = sessions(previous_rows, route, "elapsed_ms", "measured")
        phases = {}
        for field in (
            "authorization_ms", "lean_ms", "activation_ms", "execution_ms",
            "audit_ms", "cleanup_ms", "framework_residual_ms",
        ):
            if all(field in row for row in measured_rows):
                phases[field] = interval(sessions(current_rows, route, field, "measured"))
        results[name] = {
            "measured_calls": 100,
            "all_valid": True,
            "first_use_ms": interval(first),
            "elapsed_ms": interval(current),
            "baseline_ms": interval(direct),
            "added_ms": interval([value - base for value, base in zip(current, direct, strict=True)]),
            "runtime_multiple": interval([value / base for value, base in zip(current, direct, strict=True)]),
            "phases": phases,
            "previous_reused_ms": interval(previous),
            "current_over_previous": bootstrap(current, previous),
        }
    document = {
        "evaluated_revision": "3ce6e3a6d620a5df454061f9cf5a58fc6e77cf4c",
        "protocol": "5 fresh process sessions, 1 first use, 10 warmups, 20 measured calls per session",
        "timer_scope": "per-call recurring work; campaign preflight and setup are recorded separately",
        "comparison_caveat": "campaigns were sequential rather than interleaved; sessions are independent",
        "routes": results,
    }
    (ROOT / "statistics.json").write_text(json.dumps(document, indent=2) + "\n")

    lines = [
        "# Worker and broker optimization route costs",
        "",
        "Five fresh sessions, ten warmups, and 20 measured calls per session were used for each route. "
        "The table reports Student-t intervals over session means. Preflight/setup is excluded; all recurring per-call enforcement is included.",
        "",
        "| Route | First use ms [95% CI] | Reused ms [95% CI] | Added ms vs matching direct baseline | Change from prior aggressive run |",
        "|---|---:|---:|---:|---:|",
    ]
    for name, item in results.items():
        first = item["first_use_ms"]
        reused = item["elapsed_ms"]
        added = item["added_ms"]
        change = item["current_over_previous"]
        lines.append(
            f"| {name} | {first['mean']:.2f} [{first['ci95'][0]:.2f}, {first['ci95'][1]:.2f}] | "
            f"{reused['mean']:.2f} [{reused['ci95'][0]:.2f}, {reused['ci95'][1]:.2f}] | "
            f"{added['mean']:.2f} [{added['ci95'][0]:.2f}, {added['ci95'][1]:.2f}] | "
            f"{change['percent_change']:+.1f}% (ratio CI {change['ci95'][0]:.3f}-{change['ci95'][1]:.3f}) |"
        )
    lines.extend([
        "",
        "Before/after intervals use an independent-session bootstrap of the ratio of means (100,000 resamples; seed 20261029). "
        "Because the campaigns were sequential, small differences may include host drift.",
    ])
    (ROOT / "RESULTS.md").write_text("\n".join(lines) + "\n")


if __name__ == "__main__":
    main()
