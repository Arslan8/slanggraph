"""Record whether one CPU is quiet enough for interleaved Linux measurements."""

from __future__ import annotations

import argparse
import json
import os
import platform
import subprocess
import time
from pathlib import Path


def cpu_times() -> dict[int, tuple[int, int]]:
    rows = {}
    for line in Path("/proc/stat").read_text().splitlines():
        fields = line.split()
        if not fields or not fields[0].startswith("cpu") or not fields[0][3:].isdigit():
            continue
        values = [int(value) for value in fields[1:]]
        idle = values[3] + (values[4] if len(values) > 4 else 0)
        rows[int(fields[0][3:])] = (sum(values), idle)
    return rows


def read(path: str) -> str | None:
    try:
        return Path(path).read_text().strip()
    except OSError:
        return None


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--output", type=Path, required=True)
    parser.add_argument("--seconds", type=float, default=30.0)
    args = parser.parse_args()
    if args.seconds < 10:
        parser.error("qualification requires at least ten seconds")
    if args.output.exists():
        parser.error("output already exists")
    allowed = sorted(os.sched_getaffinity(0))
    before = cpu_times()
    load_before = list(os.getloadavg())
    time.sleep(args.seconds)
    after = cpu_times()
    load_after = list(os.getloadavg())
    utilization = {}
    for cpu in allowed:
        total = after[cpu][0] - before[cpu][0]
        idle = after[cpu][1] - before[cpu][1]
        utilization[cpu] = 1.0 if total <= 0 else (total - idle) / total
    selected = min(allowed, key=lambda cpu: (utilization[cpu], cpu))
    cpu_count = len(allowed)
    otherwise_quiet = (
        utilization[selected] <= 0.10 and max(load_before[0], load_after[0]) / cpu_count <= 0.10
    )
    processes = subprocess.run(
        ["ps", "-eo", "user,pid,psr,pcpu,stat,comm,args", "--sort=-pcpu"],
        check=True,
        text=True,
        stdout=subprocess.PIPE,
    ).stdout.splitlines()[:51]
    record = {
        "schema": 1,
        "otherwise_quiet": otherwise_quiet,
        "dedicated": False,
        "qualification_seconds": args.seconds,
        "selected_cpu": selected,
        "selected_cpu_utilization": utilization[selected],
        "per_cpu_utilization": {str(key): value for key, value in utilization.items()},
        "load_before": load_before,
        "load_after": load_after,
        "allowed_cpus": allowed,
        "host": {
            "platform": platform.platform(),
            "kernel": platform.release(),
            "machine": platform.machine(),
            "governor": read(f"/sys/devices/system/cpu/cpu{selected}/cpufreq/scaling_governor"),
            "driver": read(f"/sys/devices/system/cpu/cpu{selected}/cpufreq/scaling_driver"),
            "minimum_khz": read(f"/sys/devices/system/cpu/cpu{selected}/cpufreq/scaling_min_freq"),
            "maximum_khz": read(f"/sys/devices/system/cpu/cpu{selected}/cpufreq/scaling_max_freq"),
            "boost": read("/sys/devices/system/cpu/cpufreq/boost"),
            "isolated": read("/sys/devices/system/cpu/isolated"),
            "nohz_full": read("/sys/devices/system/cpu/nohz_full"),
        },
        "top_processes_after": processes,
        "limitation": (
            "shared physical host with dynamic frequency; qualified as otherwise quiet, "
            "not dedicated or frequency-fixed"
        ),
    }
    args.output.parent.mkdir(parents=True, exist_ok=True)
    args.output.write_text(json.dumps(record, indent=2) + "\n")
    print(json.dumps({"otherwise_quiet": otherwise_quiet, "selected_cpu": selected}))
    return 0 if otherwise_quiet else 2


if __name__ == "__main__":
    raise SystemExit(main())
