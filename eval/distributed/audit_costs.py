"""Measure synchronous durability versus trusted asynchronous audit acceptance."""

from __future__ import annotations

import argparse
import json
import statistics
import tempfile
import time
from pathlib import Path

from langgraph.prebuilt.security import AuditRecord, SqliteAuditSink, Verdict


def _record(index: int) -> AuditRecord:
    return AuditRecord(
        call_index=index,
        tool_name="common_read",
        user_id="alice",
        args_hash=f"args-{index}",
        stage="outcome",
        module="host",
        verdict=Verdict.ALLOW,
        reason="host:completed",
        session_id="audit-cost",
    )


def _interval(values: list[float]) -> list[float]:
    mean = statistics.fmean(values)
    if len(values) < 2:
        return [mean, mean]
    half = 2.776445 * statistics.stdev(values) / len(values) ** 0.5
    return [mean - half, mean + half]


def main() -> None:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--sessions", type=int, default=5)
    parser.add_argument("--warmups", type=int, default=10)
    parser.add_argument("--calls", type=int, default=20)
    parser.add_argument("--output", type=Path, required=True)
    args = parser.parse_args()
    raw: list[dict[str, object]] = []
    session_means: dict[str, list[float]] = {
        "synchronous": [],
        "trusted-async": [],
    }
    with tempfile.TemporaryDirectory(prefix="argus-audit-cost-") as folder:
        root = Path(folder)
        for session in range(args.sessions):
            for durability in ("synchronous", "trusted-async"):
                sink = SqliteAuditSink(
                    root / f"{session}-{durability}.sqlite",
                    durability=durability,
                )
                measured: list[float] = []
                for index in range(args.warmups + args.calls):
                    started = time.perf_counter_ns()
                    sink.write(_record(index))
                    elapsed_ms = (time.perf_counter_ns() - started) / 1e6
                    if index >= args.warmups:
                        measured.append(elapsed_ms)
                        raw.append(
                            {
                                "session": session,
                                "durability": durability,
                                "call": index - args.warmups,
                                "acceptance_ms": elapsed_ms,
                            }
                        )
                flush_started = time.perf_counter_ns()
                sink.close()
                flush_ms = (time.perf_counter_ns() - flush_started) / 1e6
                raw.append(
                    {
                        "session": session,
                        "durability": durability,
                        "kind": "close",
                        "flush_and_close_ms": flush_ms,
                    }
                )
                session_means[durability].append(statistics.fmean(measured))
    summary = {
        durability: {
            "mean_acceptance_ms": statistics.fmean(values),
            "ci95_session_means_ms": _interval(values),
        }
        for durability, values in session_means.items()
    }
    summary["trusted_async_speedup"] = {
        "removed_ms": summary["synchronous"]["mean_acceptance_ms"]
        - summary["trusted-async"]["mean_acceptance_ms"],
        "ratio": summary["trusted-async"]["mean_acceptance_ms"]
        / summary["synchronous"]["mean_acceptance_ms"],
    }
    args.output.parent.mkdir(parents=True, exist_ok=True)
    args.output.write_text(
        json.dumps(
            {
                "sessions": args.sessions,
                "warmups_per_session": args.warmups,
                "measured_calls_per_session": args.calls,
                "summary": summary,
                "records": raw,
            },
            indent=2,
            sort_keys=True,
        )
        + "\n"
    )


if __name__ == "__main__":
    main()
