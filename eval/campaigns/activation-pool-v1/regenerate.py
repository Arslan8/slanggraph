"""Regenerate exact-policy worker-pool statistics."""

from __future__ import annotations

import json
import math
import statistics
from collections import defaultdict
from pathlib import Path

ROOT = Path(__file__).resolve().parent
RAW = ROOT / "raw"
T_DF4 = 2.776445


def interval(values: list[float]) -> dict[str, object]:
    mean = statistics.fmean(values)
    half = T_DF4 * statistics.stdev(values) / math.sqrt(len(values))
    return {"ci95": [mean - half, mean + half], "mean": mean, "n_sessions": 5}


def session_means(rows: list[dict], route: str, field: str) -> list[float]:
    grouped: dict[int, list[float]] = defaultdict(list)
    for row in rows:
        if (
            row.get("kind") == "call"
            and row.get("phase") == "measured"
            and row.get("route") == route
        ):
            grouped[int(row["session"])].append(float(row[field]))
    if sorted(grouped) != list(range(5)) or any(
        len(values) != 20 for values in grouped.values()
    ):
        raise ValueError(f"incomplete {route}/{field} measurements")
    return [statistics.fmean(grouped[index]) for index in range(5)]


def main() -> None:
    rows = [
        json.loads(line)
        for path in sorted(RAW.glob("*.jsonl"))
        for line in path.read_text().splitlines()
        if line
    ]
    routes = {}
    fields = (
        "elapsed_ms",
        "worker_preflight_ms",
        "authorization_ms",
        "policy_lowering_ms",
        "lean_ms",
        "activation_ms",
        "execution_ms",
        "audit_ms",
        "cleanup_ms",
        "framework_residual_ms",
    )
    for route in ("linux", "linux-lean"):
        selected = [
            row
            for row in rows
            if row.get("kind") == "call"
            and row.get("phase") == "measured"
            and row.get("route") == route
        ]
        routes[route] = {
            "n_calls": len(selected),
            "n_sessions": 5,
            "all_valid": all(row["valid"] for row in selected),
            "all_pool_hits": all(row["worker_reused"] for row in selected),
            "metrics": {
                field: interval(session_means(rows, route, field)) for field in fields
            },
        }
    output = {
        "evaluated_revision": "6fd3b2a08",
        "protocol": "5 fresh sessions, 5 warmups, 20 measured calls per route/session",
        "timer_scope": (
            "online elapsed_ms excludes explicitly recorded exact-policy worker_preflight_ms; "
            "it includes fresh authorization, lowering, attestation, pool claim, activation "
            "receipt validation, execution, audit, cleanup, and framework work"
        ),
        "preflight_scope": (
            "authorization and lowering for the preflight template, bubblewrap creation, "
            "mount/namespace setup, seccomp and limits, pinned artifact compilation"
        ),
        "routes": routes,
    }
    (ROOT / "statistics.json").write_text(json.dumps(output, indent=2) + "\n")
    lines = [
        "# Exact-policy worker-pool evaluation",
        "",
        "Workers are single-use and enter the pool only after exact mounts, namespaces, "
        "limits, seccomp, and pinned source compilation are installed. Idle workers contain "
        "no principal grant or invocation credential. Every claim receives a fresh host "
        "attestation, grant, nonce, execution-context binding, activation receipt, and `GO`.",
        "",
        "| Route | Calls | Online mean (95% CI) | Preflight mean | Activation mean |",
        "|---|---:|---:|---:|---:|",
    ]
    for route, item in routes.items():
        metrics = item["metrics"]
        elapsed = metrics["elapsed_ms"]
        lines.append(
            f"| {route} | {item['n_calls']} | {elapsed['mean']:.2f} ms "
            f"[{elapsed['ci95'][0]:.2f}, {elapsed['ci95'][1]:.2f}] | "
            f"{metrics['worker_preflight_ms']['mean']:.2f} ms | "
            f"{metrics['activation_ms']['mean']:.2f} ms |"
        )
    lines.extend(
        [
            "",
            "All measured calls must be valid pool hits for regeneration to succeed. "
            "Preflight is reported separately and is not counted as recurring online "
            "execution overhead; deployments that cannot keep an exact worker ready must "
            "pay that provisioning cost.",
        ]
    )
    if not all(
        item["all_valid"] and item["all_pool_hits"] for item in routes.values()
    ):
        raise ValueError("invalid result or pool miss in measured calls")
    (ROOT / "RESULTS.md").write_text("\n".join(lines) + "\n")


if __name__ == "__main__":
    main()
