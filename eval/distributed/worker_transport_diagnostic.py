"""Split the Linux worker's post-release execution and transport costs.

This diagnostic launches the production worker shim directly so it can run in
environments where bubblewrap namespaces are unavailable. It measures only the
post-`GO` protocol path; it is not a protected-route performance result.
"""

from __future__ import annotations

import argparse
import json
import statistics
import subprocess
import sys
import tempfile
import time
import uuid
from pathlib import Path

SOURCE = """from pathlib import Path

def run(path):
    return Path(path).read_text()
"""


def _percentile(values: list[float], probability: float) -> float:
    ordered = sorted(values)
    position = probability * (len(ordered) - 1)
    lower = int(position)
    upper = min(lower + 1, len(ordered) - 1)
    fraction = position - lower
    return ordered[lower] * (1.0 - fraction) + ordered[upper] * fraction


def _summary(records: list[dict[str, float]]) -> dict[str, object]:
    fields = tuple(records[0])
    return {
        name: {
            "mean_ms": statistics.fmean(record[name] for record in records),
            "median_ms": statistics.median(record[name] for record in records),
            "p95_ms": _percentile([record[name] for record in records], 0.95),
        }
        for name in fields
    }


def _one(worker: Path, source: Path, allowed: Path, *, wait_mode: str) -> dict[str, float]:
    process = subprocess.Popen(
        [sys.executable, "-I", str(worker)],
        stdin=subprocess.PIPE,
        stdout=subprocess.PIPE,
        stderr=subprocess.PIPE,
        text=True,
        bufsize=1,
    )
    assert process.stdin is not None
    assert process.stdout is not None
    request = {
        "args": {"path": str(allowed)},
        "artifact_path": str(source),
        "asynchronous": False,
        "call_id": uuid.uuid4().hex,
        "entrypoint": "common_worker:run",
        "evaluation_telemetry": True,
        "limits": {},
        "plan_digest": "0" * 64,
        "runtime_roots": [str(source.parent)],
        "startup_challenge": uuid.uuid4().hex,
        "tool_import_roots": [],
        "tool_name": "common_read",
    }
    process.stdin.write(json.dumps(request, sort_keys=True) + "\n")
    process.stdin.flush()
    ready_line = process.stdout.readline()
    if not ready_line:
        return_code = process.wait(timeout=5)
        stderr = process.stderr.read() if process.stderr is not None else ""
        raise RuntimeError(f"worker exited before ready ({return_code}): {stderr}")
    ready = json.loads(ready_line)
    if ready.get("status") != "ready":
        raise RuntimeError(f"worker did not become ready: {ready!r}")

    post_go_started = time.perf_counter_ns()
    process.stdin.write("GO\n")
    process.stdin.flush()
    go_written = time.perf_counter_ns()
    response_line = process.stdout.readline()
    response_received = time.perf_counter_ns()
    response = json.loads(response_line)
    decoded = time.perf_counter_ns()
    return_code = process.wait(timeout=5) if wait_mode == "timeout" else process.wait()
    waited = time.perf_counter_ns()
    if return_code != 0 or response.get("status") != "ok":
        stderr = process.stderr.read() if process.stderr is not None else ""
        raise RuntimeError(f"worker failed ({return_code}): {response!r} {stderr}")
    timing = response["evaluation_timing_ns"]
    body_ns = int(timing["function_body"])
    serialization_ns = int(timing["result_serialization"])
    measured_ns = waited - post_go_started
    named_ns = (
        body_ns
        + serialization_ns
        + (go_written - post_go_started)
        + (decoded - response_received)
        + (waited - decoded)
    )
    return {
        "post_go_total_ms": measured_ns / 1e6,
        "go_write_flush_ms": (go_written - post_go_started) / 1e6,
        "worker_function_body_ms": body_ns / 1e6,
        "worker_module_execution_ms": int(timing["module_execution"]) / 1e6,
        "worker_target_resolution_ms": int(timing["target_resolution"]) / 1e6,
        "worker_target_call_ms": int(timing["target_call"]) / 1e6,
        "worker_result_serialization_ms": serialization_ns / 1e6,
        "response_wait_inclusive_ms": (response_received - go_written) / 1e6,
        "parent_json_decode_ms": (decoded - response_received) / 1e6,
        "process_wait_ms": (waited - decoded) / 1e6,
        "scheduling_pipe_and_envelope_ms": max(0, measured_ns - named_ns) / 1e6,
    }


def main() -> None:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--sessions", type=int, default=5)
    parser.add_argument("--calls", type=int, default=20)
    parser.add_argument("--warmups", type=int, default=5)
    parser.add_argument("--wait-mode", choices=("timeout", "blocking"), default="timeout")
    parser.add_argument("--output", type=Path, required=True)
    args = parser.parse_args()
    worker = (
        Path(__file__).parents[2] / "libs/prebuilt/langgraph/prebuilt/security/_linux_worker.py"
    )
    all_records: list[dict[str, float]] = []
    raw: list[dict[str, object]] = []
    with tempfile.TemporaryDirectory(prefix="argus-worker-transport-") as folder:
        root = Path(folder)
        source = root / "common_worker.py"
        allowed = root / "allowed.txt"
        source.write_text(SOURCE)
        allowed.write_text("COMMON_FILE_VALUE")
        for session in range(args.sessions):
            for index in range(args.warmups + args.calls):
                values = _one(worker, source, allowed, wait_mode=args.wait_mode)
                if index >= args.warmups:
                    all_records.append(values)
                    raw.append(
                        {
                            "session": session,
                            "call": index - args.warmups,
                            **values,
                        }
                    )
    artifact = {
        "scope": "direct production worker shim; post-GO only; no bubblewrap or Landlock",
        "python": sys.executable,
        "sessions": args.sessions,
        "measured_calls_per_session": args.calls,
        "warmups_per_session": args.warmups,
        "parent_wait_mode": args.wait_mode,
        "summary": _summary(all_records),
        "records": raw,
    }
    args.output.parent.mkdir(parents=True, exist_ok=True)
    args.output.write_text(json.dumps(artifact, indent=2, sort_keys=True) + "\n")


if __name__ == "__main__":
    main()
