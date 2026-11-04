"""Summarize paired prepared object-broker timing records without subtraction."""

from __future__ import annotations

import argparse
import json
import statistics
from pathlib import Path


def percentile(values: list[float], fraction: float) -> float:
    ordered = sorted(values)
    return ordered[min(len(ordered) - 1, int(len(ordered) * fraction))]


def summary(values: list[float]) -> dict[str, float]:
    mean = statistics.fmean(values)
    deviation = statistics.stdev(values) if len(values) > 1 else 0.0
    return {
        "mean_ms": mean,
        "median_ms": statistics.median(values),
        "p95_ms": percentile(values, 0.95),
        "stdev_ms": deviation,
        "coefficient_of_variation": deviation / mean if mean else 0.0,
    }


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--raw", type=Path, required=True)
    parser.add_argument("--output", type=Path, required=True)
    args = parser.parse_args()
    rows = [
        json.loads(line)
        for path in sorted(args.raw.glob("session-*.jsonl"))
        for line in path.read_text().splitlines()
    ]
    setups = [row for row in rows if row["kind"] == "setup"]
    calls = [row for row in rows if row["kind"] == "call"]
    protected = [row for row in calls if row["route"] == "broker"]
    baseline = [row for row in calls if row["route"] == "direct-broker"]
    first_protected = [row for row in protected if row["phase"] == "first_use"]
    first_baseline = [row for row in baseline if row["phase"] == "first_use"]
    steady_protected = [row for row in protected if row["phase"] == "measured"]
    steady_baseline = [row for row in baseline if row["phase"] == "measured"]
    if not setups or len(steady_protected) != len(steady_baseline):
        raise ValueError("incomplete paired broker timing records")
    protected_values = [row["elapsed_ms"] for row in steady_protected]
    baseline_values = [row["elapsed_ms"] for row in steady_baseline]
    protected_stats = summary(protected_values)
    baseline_stats = summary(baseline_values)
    breakdown = {
        name: statistics.fmean(row[field] for row in steady_protected)
        for name, field in {
            "authorization": "authorization_ms",
            "invocation_and_activation": "activation_ms",
            "lean_grant": "lean_grant_ms",
            "lean_pre_execution": "lean_go_ms",
            "worker_transport": "mediator_transport_ms",
            "resource_execution": "execution_ms",
            "lean_result_cleanup": "lean_result_ms",
            "required_cleanup": "cleanup_ms",
            "audit": "audit_ms",
            "framework_residual": "framework_residual_ms",
        }.items()
    }
    activation_breakdown = {
        name: statistics.fmean(row[field] for row in steady_protected)
        for name, field in {
            "prepared_worker_selection": "prepared_worker_selection_ms",
            "grant_construction": "grant_construction_ms",
            "mediator_setup_inclusive": "mediator_setup_ms",
            "prepared_policy_binding": "prepared_policy_binding_ms",
            "channel_thread_setup": "channel_thread_setup_ms",
            "certificate_construction": "certificate_construction_ms",
            "receipt_activation_validation": "receipt_validation_ms",
            "lean_certificate_preparation": "lean_prepare_ms",
            "request_encoding": "request_encoding_ms",
            "worker_ready_wait": "worker_ready_wait_ms",
        }.items()
        if all(field in row for row in steady_protected)
    }
    result = {
        "schema": 2,
        "sessions": len(set(row["session"] for row in protected)),
        "warmups_per_session": sum(row["phase"] == "warmup" for row in protected)
        // len(set(row["session"] for row in protected)),
        "measured_pairs": len(steady_protected),
        "preparation": {
            "checker_load_mean_ms": statistics.fmean(row["checker_setup_ms"] for row in setups),
            "dispatcher_mean_ms": statistics.fmean(row["dispatcher_setup_ms"] for row in setups),
            "admission_policy_mean_ms": statistics.fmean(
                row["admission_setup_ms"] for row in setups
            ),
            "first_worker_mean_ms": statistics.fmean(
                row["worker_preparation_ms"] for row in first_protected
            ),
            "recurring_replenishment": summary(
                [row["worker_preparation_ms"] for row in protected if row["phase"] != "first_use"]
            ),
            "contents": [
                "sealed inline checker and pinned runtime",
                "closed graph admission and parsed Cedar policy",
                "exact host plan template and mediator decisions",
                "confined single-use worker waiting at the authorization barrier",
            ],
            "replenishment_can_delay_next_request": True,
        },
        "first_invocation_after_preparation": {
            "baseline": summary([row["elapsed_ms"] for row in first_baseline]),
            "argus": summary([row["elapsed_ms"] for row in first_protected]),
        },
        "prepared_steady_state": {
            "baseline": baseline_stats,
            "argus": protected_stats,
            "absolute_difference_mean_ms": protected_stats["mean_ms"] - baseline_stats["mean_ms"],
            "relative_overhead_ratio": protected_stats["mean_ms"] / baseline_stats["mean_ms"],
        },
        "online_breakdown_mean_ms": breakdown,
        "invocation_activation_detail_mean_ms": activation_breakdown,
        "release_detail_mean_ms": {
            "worker_result_wait": statistics.fmean(
                row.get("worker_result_wait_ms", 0.0) for row in steady_protected
            ),
            "worker_release": statistics.fmean(row["cleanup_ms"] for row in steady_protected),
        },
        "online_breakdown_reconciled_ms": sum(breakdown.values()),
        "instrumentation": {
            "inline_checking_active": all(row["checker"]["inline"] for row in protected),
            "checker_subprocess_calls": max(
                row["checker"]["subprocess_calls"] for row in protected
            ),
            "checker_loaded_during_preparation": all(
                row["checker_loaded_during_preparation"] for row in setups
            ),
            "prepared_lowering_repeated_online": any(
                row["prepared_lowering_repeated_online"] for row in protected
            ),
            "pool_misses": max(row["pool"]["misses"] for row in protected),
            "fallbacks": max(row["pool"]["fallbacks"] for row in protected),
            "policy_lowerings_per_session": sorted(
                {row["session"]: row["pool"]["policy_lowerings"] for row in protected}.values()
            ),
            "required_check_spans_positive": all(
                row["lean_grant_ms"] > 0 and row["lean_go_ms"] > 0 and row["lean_result_ms"] > 0
                for row in protected
            ),
        },
    }
    args.output.write_text(json.dumps(result, indent=2) + "\n")
    print(json.dumps(result["prepared_steady_state"], sort_keys=True))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
