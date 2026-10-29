"""Regenerate the aggressive-mode route-cost statistics from retained raw calls."""

from __future__ import annotations

import json
import math
import random
import statistics
from collections import defaultdict
from pathlib import Path

ROOT = Path(__file__).resolve().parent
RAW = ROOT / "raw"
SEED = 20261029
RESAMPLES = 100_000
T_CRIT_DF4 = 2.776445

ROUTES = {
    "language": (
        "language",
        "upstream",
        "object/language authorizer; aggressive typed Cedar not applicable",
    ),
    "landlock-aggressive": ("landlock", "upstream", "typed Cedar aggressive"),
    "container": (
        "container",
        "direct-container",
        "object authorizer; aggressive typed Cedar not applicable",
    ),
    "broker": (
        "broker",
        "direct-broker",
        "object authorizer; aggressive typed Cedar not applicable",
    ),
}


def read_rows(name: str) -> list[dict]:
    rows: list[dict] = []
    for path in sorted((RAW / name).glob("session-*.jsonl")):
        rows.extend(json.loads(line) for line in path.read_text().splitlines() if line)
    return rows


def interval(values: list[float]) -> dict:
    mean = statistics.fmean(values)
    half = T_CRIT_DF4 * statistics.stdev(values) / math.sqrt(len(values))
    return {"n_sessions": len(values), "mean": mean, "ci95": [mean - half, mean + half]}


def session_values(rows: list[dict], route: str, field: str, phase: str) -> list[float]:
    grouped: dict[int, list[float]] = defaultdict(list)
    for row in rows:
        if row.get("kind") == "call" and row.get("route") == route and row.get("phase") == phase:
            grouped[int(row["session"])].append(float(row[field]))
    if sorted(grouped) != list(range(5)):
        raise ValueError(f"{route}/{phase}: expected sessions 0..4")
    expected = 20 if phase == "measured" else 1
    if any(len(values) != expected for values in grouped.values()):
        raise ValueError(f"{route}/{phase}: expected {expected} calls per session")
    return [statistics.fmean(grouped[index]) for index in range(5)]


def summarize(name: str, route: str, baseline: str, applicability: str) -> dict:
    rows = read_rows(name)
    measured = [
        row
        for row in rows
        if row.get("kind") == "call"
        and row.get("route") == route
        and row.get("phase") == "measured"
    ]
    if len(measured) != 100 or not all(row.get("valid") for row in measured):
        raise ValueError(f"{name}: incomplete or invalid protected calls")
    elapsed = session_values(rows, route, "elapsed_ms", "measured")
    direct = session_values(rows, baseline, "elapsed_ms", "measured")
    first = session_values(rows, route, "elapsed_ms", "first_use")
    phases = {}
    for field in (
        "authorization_ms",
        "lean_ms",
        "activation_ms",
        "execution_ms",
        "audit_ms",
        "cleanup_ms",
        "framework_residual_ms",
    ):
        if all(field in row for row in measured):
            phases[field] = interval(session_values(rows, route, field, "measured"))
    setups = [row for row in rows if row.get("kind") == "setup"]
    return {
        "applicability": applicability,
        "measured_calls": len(measured),
        "all_valid": True,
        "elapsed_ms": interval(elapsed),
        "baseline_ms": interval(direct),
        "added_ms": interval([value - base for value, base in zip(elapsed, direct, strict=True)]),
        "runtime_multiple": interval(
            [value / base for value, base in zip(elapsed, direct, strict=True)]
        ),
        "first_use_ms": interval(first),
        "phases": phases,
        "setup_records": len(setups),
        "cedar_optimization_levels": sorted(
            {row["cedar_optimization_level"] for row in setups if "cedar_optimization_level" in row}
        ),
    }


def bootstrap_ratio(numerator: list[float], denominator: list[float]) -> dict:
    rng = random.Random(SEED)
    samples = []
    for _ in range(RESAMPLES):
        top = [rng.choice(numerator) for _ in numerator]
        bottom = [rng.choice(denominator) for _ in denominator]
        samples.append(statistics.fmean(top) / statistics.fmean(bottom))
    samples.sort()
    return {
        "ratio": statistics.fmean(numerator) / statistics.fmean(denominator),
        "ci95": [samples[2_500], samples[97_499]],
        "method": "independent session bootstrap of ratio of means",
        "seed": SEED,
        "resamples": RESAMPLES,
    }


def main() -> None:
    routes = {
        name: summarize(name, route, baseline, applicability)
        for name, (route, baseline, applicability) in ROUTES.items()
    }
    normal_rows = read_rows("landlock-normal")
    aggressive_rows = read_rows("landlock-aggressive")
    normal_measured = session_values(normal_rows, "landlock", "elapsed_ms", "measured")
    aggressive_measured = session_values(aggressive_rows, "landlock", "elapsed_ms", "measured")
    normal_first = session_values(normal_rows, "landlock", "elapsed_ms", "first_use")
    aggressive_first = session_values(aggressive_rows, "landlock", "elapsed_ms", "first_use")
    comparison = {
        "normal": {
            "measured_ms": interval(normal_measured),
            "first_use_ms": interval(normal_first),
        },
        "aggressive": {
            "measured_ms": routes["landlock-aggressive"]["elapsed_ms"],
            "first_use_ms": routes["landlock-aggressive"]["first_use_ms"],
        },
        "aggressive_over_normal_measured": bootstrap_ratio(aggressive_measured, normal_measured),
        "aggressive_over_normal_first_use": bootstrap_ratio(aggressive_first, normal_first),
        "caveat": (
            "Modes were run sequentially, not interleaved; sessions are treated as independent."
        ),
    }
    output = {
        "protocol": (
            "5 fresh process sessions, 1 first use, 10 warmups, 20 measured calls per session"
        ),
        "routes": routes,
        "landlock_optimization_comparison": comparison,
    }
    (ROOT / "statistics.json").write_text(json.dumps(output, indent=2) + "\n")

    first = comparison["aggressive_over_normal_first_use"]
    reused = comparison["aggressive_over_normal_measured"]
    lines = [
        "# Aggressive optimization route costs",
        "",
        "All routes use five fresh process sessions, ten warmups, and 20 measured "
        "calls per session. "
        "Intervals in the route table are Student-t intervals over session means.",
        "",
        "| Route | Optimization applicability | First use (ms) | Reused call (ms) | "
        "Added ms vs matching direct baseline |",
        "|---|---|---:|---:|---:|",
    ]
    for name in ROUTES:
        item = routes[name]
        lines.append(
            f"| {name} | {item['applicability']} | "
            f"{item['first_use_ms']['mean']:.2f} "
            f"[{item['first_use_ms']['ci95'][0]:.2f}, {item['first_use_ms']['ci95'][1]:.2f}] | "
            f"{item['elapsed_ms']['mean']:.2f} "
            f"[{item['elapsed_ms']['ci95'][0]:.2f}, {item['elapsed_ms']['ci95'][1]:.2f}] | "
            f"{item['added_ms']['mean']:.2f} "
            f"[{item['added_ms']['ci95'][0]:.2f}, {item['added_ms']['ci95'][1]:.2f}] |"
        )
    lines.extend(
        [
            "",
            "## Direct Cedar-mode comparison",
            "",
            f"On the Lean-backed Landlock route, first use was "
            f"{comparison['normal']['first_use_ms']['mean']:.2f} ms in `normal` mode and "
            f"{comparison['aggressive']['first_use_ms']['mean']:.2f} ms in `aggressive` mode. "
            f"The ratio is {first['ratio']:.3f}x (independent-session bootstrap 95% CI "
            f"{first['ci95'][0]:.3f}-{first['ci95'][1]:.3f}), a "
            f"{100 * (1 - first['ratio']):.1f}% reduction.",
            "",
            f"After ten warmups, reused calls were "
            f"{comparison['normal']['measured_ms']['mean']:.2f} ms and "
            f"{comparison['aggressive']['measured_ms']['mean']:.2f} ms, ratio "
            f"{reused['ratio']:.3f}x (95% CI {reused['ci95'][0]:.3f}-{reused['ci95'][1]:.3f}). "
            "Exact-result caching makes Cedar authorization a sub-millisecond phase "
            "on reused calls, so the large cold-path batching benefit should not be "
            "generalized to the full reused-call runtime.",
            "",
            "The language, container, broker, Pandas, and ordinary-demo cohorts do not traverse "
            "`CedarPolicyBackend`; they are regression/control measurements under the "
            "aggressive-default revision.",
        ]
    )
    (ROOT / "RESULTS.md").write_text("\n".join(lines) + "\n")


if __name__ == "__main__":
    main()
