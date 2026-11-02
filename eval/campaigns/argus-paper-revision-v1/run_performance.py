"""Launch final Linux measurements only after an explicit controlled-host gate."""

from __future__ import annotations

import argparse
import hashlib
import json
import os
import platform
import subprocess
import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parents[3]
BENCHMARK = ROOT / "eval/campaigns/cross-host-security-v2/microbenchmarks/run_broker_costs.py"
PREFLIGHT = Path(__file__).with_name("preflight.py")
SOURCES = (
    ROOT / "libs/prebuilt/langgraph/prebuilt/security/landlock.py",
    ROOT / "libs/prebuilt/langgraph/prebuilt/security/object_broker.py",
    BENCHMARK,
    PREFLIGHT,
    Path(__file__).resolve(),
    Path(__file__).with_name("run_example.py"),
    Path(__file__).with_name("worker.py"),
)


def digest(path: Path) -> str:
    return hashlib.sha256(path.read_bytes()).hexdigest()


def read(path: str) -> str | None:
    try:
        return Path(path).read_text().strip()
    except OSError:
        return None


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--output", type=Path, required=True)
    parser.add_argument("--checker", type=Path, required=True)
    parser.add_argument("--acknowledge-controlled-host", action="store_true")
    parser.add_argument("--sessions", type=int, default=5)
    parser.add_argument("--warmups", type=int, default=10)
    parser.add_argument("--measured", type=int, default=20)
    args = parser.parse_args()
    if not args.acknowledge_controlled_host:
        parser.error(
            "final measurements require --acknowledge-controlled-host after checking "
            "load/frequency isolation"
        )
    args.output.mkdir(parents=True, exist_ok=False)
    preflight = subprocess.run(
        [
            sys.executable,
            str(PREFLIGHT),
            "--checker",
            str(args.checker.resolve(strict=True)),
            "--output",
            str(args.output / "preflight"),
            "--run-example",
        ],
        cwd=ROOT,
        check=False,
    )
    if preflight.returncode != 0:
        return 2
    before = {str(path.relative_to(ROOT)): digest(path) for path in SOURCES}
    metadata = {
        "schema": 1,
        "commit": subprocess.run(
            ["git", "rev-parse", "HEAD"],
            cwd=ROOT,
            check=True,
            text=True,
            stdout=subprocess.PIPE,
        ).stdout.strip(),
        "host": {
            "platform": platform.platform(),
            "kernel": platform.release(),
            "machine": platform.machine(),
            "python": sys.version,
            "loadavg": list(os.getloadavg()),
            "cpu_online": read("/sys/devices/system/cpu/online"),
            "governor_cpu0": read("/sys/devices/system/cpu/cpu0/cpufreq/scaling_governor"),
            "driver_cpu0": read("/sys/devices/system/cpu/cpu0/cpufreq/scaling_driver"),
            "boost": read("/sys/devices/system/cpu/cpufreq/boost"),
        },
        "checker": {
            "path": str(args.checker.resolve(strict=True)),
            "sha256": digest(args.checker.resolve(strict=True)),
        },
        "source_before": before,
        "controlled_host_acknowledged": True,
    }
    (args.output / "environment.json").write_text(json.dumps(metadata, indent=2) + "\n")
    command = [
        sys.executable,
        str(BENCHMARK),
        "--output",
        str(args.output / "raw"),
        "--checker",
        str(args.checker.resolve(strict=True)),
        "--sessions",
        str(args.sessions),
        "--warmups",
        str(args.warmups),
        "--measured",
        str(args.measured),
    ]
    completed = subprocess.run(command, cwd=ROOT, check=False)
    after = {str(path.relative_to(ROOT)): digest(path) for path in SOURCES}
    metadata["source_after"] = after
    metadata["source_stable"] = before == after
    metadata["returncode"] = completed.returncode
    (args.output / "environment.json").write_text(json.dumps(metadata, indent=2) + "\n")
    return 0 if completed.returncode == 0 and before == after else 1


if __name__ == "__main__":
    raise SystemExit(main())
