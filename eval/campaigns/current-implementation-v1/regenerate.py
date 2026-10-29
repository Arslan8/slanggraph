"""Regenerate all campaign statistics from immutable raw JSON/JSONL files."""

from __future__ import annotations

import csv
import json
import math
import statistics
from collections import defaultdict
from pathlib import Path

ROOT = Path(__file__).resolve().parent
RAW = ROOT / "raw"
T_CRIT_DF4 = 2.776445


def read_jsonl(path: Path) -> list[dict]:
    """Read a JSON-lines file without skipping failed or null-valued rows."""
    return [json.loads(line) for line in path.read_text().splitlines() if line.strip()]


def interval(values: list[float]) -> dict:
    """Return a Student-t interval over independent session-level values."""
    if not values:
        return {"n_sessions": 0, "mean": None, "ci95": [None, None]}
    mean = statistics.fmean(values)
    if len(values) == 1:
        return {"n_sessions": 1, "mean": mean, "ci95": [None, None]}
    critical = T_CRIT_DF4 if len(values) == 5 else 2.0
    half = critical * statistics.stdev(values) / math.sqrt(len(values))
    return {"n_sessions": len(values), "mean": mean, "ci95": [mean - half, mean + half]}


def session_summary(rows: list[dict], route: str, baseline: str) -> dict:
    """Summarize measured calls and paired overhead at the session level."""
    measured = [row for row in rows if row.get("phase") == "measured"]
    first = [row for row in rows if row.get("phase") == "first_use"]
    grouped: dict[tuple[str, int], list[dict]] = defaultdict(list)
    for row in measured:
        grouped[(row["route"], int(row["session"]))].append(row)
    route_means = {
        session: statistics.fmean(row["elapsed_ms"] for row in group)
        for (name, session), group in grouped.items()
        if name == route
    }
    base_means = {
        session: statistics.fmean(row["elapsed_ms"] for row in group)
        for (name, session), group in grouped.items()
        if name == baseline
    }
    sessions = sorted(route_means.keys() & base_means.keys())
    if sessions != list(range(5)):
        raise ValueError(f"{route}: expected sessions 0..4, found {sessions}")
    for session in sessions:
        route_count = len(grouped[(route, session)])
        baseline_count = len(grouped[(baseline, session)])
        if (route_count, baseline_count) != (20, 20):
            raise ValueError(
                f"{route}/{session}: expected 20 paired calls, found {route_count}/{baseline_count}"
            )
    selected_route = [row for row in measured if row.get("route") == route]
    if not all(row.get("valid", False) for row in selected_route):
        raise ValueError(f"{route}: invalid measured result")
    residuals = [
        row["framework_residual_ms"] for row in selected_route if "framework_residual_ms" in row
    ]
    if residuals and min(residuals) < -0.1:
        raise ValueError(f"{route}: overlapping phase ledger")
    added = [route_means[item] - base_means[item] for item in sessions]
    multiples = [route_means[item] / base_means[item] for item in sessions]
    phases = {}
    for key in (
        "authorization_ms",
        "lean_ms",
        "activation_ms",
        "execution_ms",
        "audit_ms",
        "cleanup_ms",
        "framework_residual_ms",
    ):
        by_session = []
        for session in sessions:
            values = [
                row[key]
                for row in measured
                if row["route"] == route and row["session"] == session and key in row
            ]
            if values:
                by_session.append(statistics.fmean(values))
        if by_session:
            phases[key] = interval(by_session)
    return {
        "route": route,
        "baseline": baseline,
        "measured_calls": sum(1 for row in measured if row.get("route") == route),
        "all_valid": True,
        "elapsed_ms": interval(list(route_means.values())),
        "baseline_ms": interval(list(base_means.values())),
        "added_ms": interval(added),
        "runtime_multiple": interval(multiples),
        "percent_overhead": interval([(item - 1) * 100 for item in multiples]),
        "first_use_ms": interval([row["elapsed_ms"] for row in first if row.get("route") == route]),
        "phases": phases,
    }


def graph_route(name: str) -> dict | None:
    directory = RAW / name
    if not directory.exists():
        return None
    rows = []
    for path in sorted(directory.glob("session-*.jsonl")):
        rows.extend(read_jsonl(path))
    route = (
        "container"
        if "container" in name
        else "broker"
        if "broker" in name
        else "landlock"
        if "landlock" in name
        else "language"
    )
    result = session_summary(rows, route, "upstream")
    setups = [row for row in rows if row.get("kind") == "setup"]
    cleanups = [row for row in rows if row.get("kind") == "cleanup"]
    for key in (
        "setup_ms",
        "checker_setup_ms",
        "executor_setup_ms",
        "dispatcher_setup_ms",
        "admission_setup_ms",
    ):
        values = [row[key] for row in setups if key in row]
        if values:
            result[key] = interval(values)
    if cleanups:
        result["cleanup_ms"] = interval([row["cleanup_ms"] for row in cleanups])
        result["all_removals_confirmed"] = all(row["removal_confirmed"] for row in cleanups)
    if route == "language":
        result["raw_bypass_refused"] = all(row["raw_file_bypass"]["refused"] for row in setups)
    return result


def typed_routes() -> list[dict]:
    directory = RAW / "typed-costs-v1"
    if not directory.exists():
        return []
    original = []
    for path in sorted(directory.glob("session-*.jsonl")):
        original.extend(read_jsonl(path))
    rows = [
        {
            **row,
            "route": row["mode"],
            "valid": row["legitimate_result"],
        }
        for row in original
    ]
    verified = session_summary(rows, "verified", "plain")
    verified["route"] = "language_typed_authorization_only"
    broker = session_summary(rows, "broker", "plain")
    broker["route"] = "broker_authorization_only"
    return [verified, broker]


def landlock_routes() -> list[dict]:
    directory = RAW / "verified-rerun"
    if not directory.exists():
        return []
    by_case: dict[str, list[dict]] = defaultdict(list)
    for session_path in sorted(directory.glob("session-*")):
        session = int(session_path.name.split("-")[-1])
        for row in read_jsonl(session_path / "samples.jsonl"):
            by_case[row["case"]].append(
                {
                    **row,
                    "session": session,
                    "route": row["condition"],
                }
            )
    return [
        {"workload": case, **session_summary(rows, "host", "verified")}
        for case, rows in sorted(by_case.items())
    ]


def pandas_results(name: str) -> dict | None:
    path = RAW / name / "trials.jsonl"
    if not path.exists():
        return None
    rows = read_jsonl(path)
    modes = sorted({str(row.get("mode")) for row in rows})
    expected_modes = {"A", "B", "C"} if name == "pandas-v19-rerun" else {"C-closed"}
    if set(modes) != expected_modes or len(rows) != 50 * len(expected_modes):
        raise ValueError(f"{name}: incomplete task/configuration matrix")
    for mode in modes:
        selected = [row for row in rows if str(row.get("mode")) == mode]
        matrix = {(row["case_id"], int(row["repeat"])) for row in selected}
        if len(selected) != 50 or len(matrix) != 50:
            raise ValueError(f"{name}/{mode}: expected ten tasks by five repeats")
    result = {"trials": len(rows), "modes": {}}
    for mode in modes:
        selected = [row for row in rows if str(row.get("mode")) == mode]
        repeats = sorted({int(row.get("repeat", row.get("session", 0))) for row in selected})
        timing = []
        for repeat in repeats:
            values = [
                float(row["wall_ms"])
                for row in selected
                if int(row.get("repeat", row.get("session", 0))) == repeat
            ]
            if values:
                timing.append(statistics.fmean(values))
        failures = [
            {
                "case_id": row.get("case_id"),
                "repeat": row.get("repeat"),
                "status": row.get("status"),
                "error": row.get("error"),
            }
            for row in selected
            if not row.get("legitimate_result", False)
        ]
        result["modes"][mode] = {
            "successes": sum(bool(row.get("legitimate_result")) for row in selected),
            "attempts": len(selected),
            "failures": failures,
            "mean_task_wall_ms": statistics.fmean(float(row["wall_ms"]) for row in selected),
            "mean_repeat_wall_ms": interval(timing),
            "repeat_mean_wall_ms": timing,
            "model_calls": sum(int(row.get("model_calls", 0)) for row in selected),
        }
    if "A" in result["modes"]:
        baseline = result["modes"]["A"]["mean_task_wall_ms"]
        baseline_repeats = result["modes"]["A"]["repeat_mean_wall_ms"]
        for values in result["modes"].values():
            ratio = values["mean_task_wall_ms"] / baseline
            values["runtime_multiple_vs_A"] = ratio
            values["percent_overhead_vs_A"] = (ratio - 1) * 100
            repeat_ratios = [
                current / reference
                for current, reference in zip(
                    values["repeat_mean_wall_ms"], baseline_repeats, strict=True
                )
            ]
            values["runtime_multiple_vs_A_interval"] = interval(repeat_ratios)
            values["percent_overhead_vs_A_interval"] = interval(
                [(item - 1) * 100 for item in repeat_ratios]
            )
    return result


def main() -> None:
    routes = typed_routes()
    for name in (
        "language-useful-work-v1",
        "landlock-costs-v1",
        "container-costs-v1",
        "broker-costs-v1",
    ):
        value = graph_route(name)
        if value is not None:
            routes.append(value)
    output = {
        "method": {
            "confidence_interval": (
                "two-sided 95% Student-t interval over five independent session means; "
                "t(4)=2.776445"
            ),
            "warmups_excluded": True,
            "first_use_reported_separately": True,
        },
        "routes": routes,
        "landlock": landlock_routes(),
        "pandas_v19": pandas_results("pandas-v19-rerun"),
        "pandas_closed": pandas_results("pandas-closed-rerun"),
    }
    (ROOT / "statistics.json").write_text(json.dumps(output, indent=2) + "\n")
    with (ROOT / "statistics.csv").open("w", newline="") as stream:
        writer = csv.writer(stream)
        writer.writerow(
            [
                "route",
                "workload",
                "calls",
                "mean_ms",
                "ci95_low_ms",
                "ci95_high_ms",
                "multiple",
                "overhead_percent",
            ]
        )
        for row in [*routes, *output["landlock"]]:
            elapsed = row["elapsed_ms"]
            multiple = row["runtime_multiple"]["mean"]
            overhead = row["percent_overhead"]["mean"]
            writer.writerow(
                [
                    row["route"],
                    row.get("workload", ""),
                    row["measured_calls"],
                    elapsed["mean"],
                    *elapsed["ci95"],
                    multiple,
                    overhead,
                ]
            )
    lines = [
        "# Current-implementation results",
        "",
        "All intervals are 95% Student-t intervals over five independent session means. "
        "Warmups are excluded and first-use calls are reported separately.",
        "",
        "## Absolute route latency",
        "",
        "| Route | Measured calls | Mean ms [95% CI] | First use ms |",
        "| --- | ---: | ---: | ---: |",
    ]
    for row in routes:
        elapsed = row["elapsed_ms"]
        first = row["first_use_ms"]
        lines.append(
            f"| {row['route']} | {row['measured_calls']} | "
            f"{elapsed['mean']:.3f} [{elapsed['ci95'][0]:.3f}, {elapsed['ci95'][1]:.3f}] | "
            f"{first['mean']:.3f} [{first['ci95'][0]:.3f}, {first['ci95'][1]:.3f}] |"
        )
    lines += [
        "",
        "## Cold setup and final teardown",
        "",
        "| Route | Admission/setup ms | Dispatcher/executor ms | Checker setup ms | "
        "Final removal ms |",
        "| --- | ---: | ---: | ---: | ---: |",
    ]
    for row in routes:
        admission = row.get("admission_setup_ms", row.get("setup_ms", {})).get("mean")
        executor = row.get("dispatcher_setup_ms", row.get("executor_setup_ms", {})).get("mean")
        checker = row.get("checker_setup_ms", {}).get("mean")
        cleanup = row.get("cleanup_ms", {}).get("mean")

        def cold(value: float | None) -> str:
            return "N/A" if value is None else f"{value:.3f}"

        lines.append(
            f"| {row['route']} | {cold(admission)} | {cold(executor)} | "
            f"{cold(checker)} | {cold(cleanup)} |"
        )
    lines += [
        "",
        "## Additive route phases",
        "",
        "| Route | Authorization ms | Lean ms | Activation ms | Execution ms | "
        "Audit ms | Cleanup ms | Residual ms |",
        "| --- | ---: | ---: | ---: | ---: | ---: | ---: | ---: |",
    ]
    for row in routes:
        phase = row["phases"]

        def mean(name: str, values: dict = phase) -> str:
            value = values.get(name, {}).get("mean")
            return "N/A" if value is None else f"{value:.3f}"

        lines.append(
            f"| {row['route']} | {mean('authorization_ms')} | {mean('lean_ms')} | "
            f"{mean('activation_ms')} | {mean('execution_ms')} | {mean('audit_ms')} | "
            f"{mean('cleanup_ms')} | {mean('framework_residual_ms')} |"
        )
    lines += [
        "",
        "For the broker route, `execution_ms` includes isolated Python startup, "
        "trusted-module import, the Unix-socket broker round trip, and the tool body. "
        "It is not a transport-only measurement.",
        "",
        "## Appendix: primitive-relative ratios",
        "",
        "The ratios below divide whole protected calls by in-process primitive "
        "baselines. They are retained for completeness and are not the headline "
        "comparison for an LLM-driven tool invocation.",
        "",
        "| Route | Baseline ms [95% CI] | Runtime multiple | Overhead |",
        "| --- | ---: | ---: | ---: |",
    ]
    for row in routes:
        baseline = row["baseline_ms"]
        multiple = row["runtime_multiple"]
        overhead = row["percent_overhead"]
        lines.append(
            f"| {row['route']} | {baseline['mean']:.6f} "
            f"[{baseline['ci95'][0]:.6f}, {baseline['ci95'][1]:.6f}] | "
            f"{multiple['mean']:.2f}x [{multiple['ci95'][0]:.2f}, "
            f"{multiple['ci95'][1]:.2f}] | {overhead['mean']:.1f}% "
            f"[{overhead['ci95'][0]:.1f}, {overhead['ci95'][1]:.1f}] |"
        )
    lines += ["", "## Pandas utility and wall time", ""]
    for title, key in (("Matched v19 A/B/C", "pandas_v19"), ("C-closed v21", "pandas_closed")):
        result = output[key]
        if result is None:
            continue
        lines += [
            f"### {title}",
            "",
            "| Mode | Utility | Mean task wall ms [95% CI] | vs A | Overhead vs A |",
            "| --- | ---: | ---: | ---: | ---: |",
        ]
        for mode, values in result["modes"].items():
            ratio = values.get("runtime_multiple_vs_A")
            timing = values["mean_repeat_wall_ms"]
            ratio_interval = values.get("runtime_multiple_vs_A_interval")
            overhead_interval = values.get("percent_overhead_vs_A_interval")
            if ratio_interval is None:
                ratio_text = "N/A"
                overhead_text = "N/A"
            else:
                ratio_text = (
                    f"{ratio:.3f}x [{ratio_interval['ci95'][0]:.3f}, "
                    f"{ratio_interval['ci95'][1]:.3f}]"
                )
                overhead_text = (
                    f"{values['percent_overhead_vs_A']:.1f}% "
                    f"[{overhead_interval['ci95'][0]:.1f}, "
                    f"{overhead_interval['ci95'][1]:.1f}]"
                )
            lines.append(
                f"| {mode} | {values['successes']}/{values['attempts']} | "
                f"{values['mean_task_wall_ms']:.1f} "
                f"[{timing['ci95'][0]:.1f}, {timing['ci95'][1]:.1f}] | "
                f"{ratio_text} | {overhead_text} |"
            )
        lines.append("")
    lines += [
        "Raw records and failure details are under `raw/`; `statistics.json` is the "
        "machine-readable source for these tables.",
        "",
    ]
    (ROOT / "RESULTS.md").write_text("\n".join(lines))


if __name__ == "__main__":
    main()
