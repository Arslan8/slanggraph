"""Shared configuration, scheduling, and record helpers for unified-final-v1."""

from __future__ import annotations

import hashlib
import json
import math
import os
import platform
import random
import subprocess
import sys
from collections.abc import Iterable, Iterator, Mapping
from dataclasses import dataclass
from pathlib import Path
from typing import Any

HERE = Path(__file__).resolve().parent
ROOT = HERE.parents[2]
CONFIGURATION = HERE / "configuration.json"
RECORD_FIELDS = frozenset(
    {
        "schema_version",
        "campaign_id",
        "config_id",
        "build_id",
        "evaluation",
        "mode",
        "workload",
        "task",
        "session",
        "repetition",
        "seed",
        "phase",
        "route",
        "preflight_ns",
        "runtime_start_ns",
        "runtime_end_ns",
        "runtime_ns",
        "outcome",
        "oracle_passed",
        "counters",
    }
)


def canonical_json(value: Any) -> bytes:
    return (json.dumps(value, sort_keys=True, separators=(",", ":")) + "\n").encode()


def sha256_bytes(value: bytes) -> str:
    return hashlib.sha256(value).hexdigest()


def sha256_file(path: Path) -> str:
    return sha256_bytes(path.read_bytes())


def load_config(path: Path = CONFIGURATION) -> dict[str, Any]:
    config = json.loads(path.read_text(encoding="utf-8"))
    if config.get("schema_version") != 1 or config.get("campaign_id") != "unified-final-v1":
        raise ValueError("not a unified-final-v1 configuration")
    return config


def config_id(config: Mapping[str, Any]) -> str:
    return sha256_bytes(canonical_json(config))


def git_output(*arguments: str) -> str:
    return subprocess.run(
        ["git", *arguments],
        cwd=ROOT,
        check=True,
        capture_output=True,
        text=True,
    ).stdout.strip()


def build_identity() -> dict[str, Any]:
    status = git_output("status", "--porcelain=v1", "--untracked-files=all")
    source_paths = (
        ROOT / "libs/prebuilt/langgraph/prebuilt/security",
        ROOT / "libs/langgraph/langgraph",
        ROOT / "eval/apps/demos",
        ROOT / "eval/apps/pandas",
        HERE,
    )
    sources: dict[str, str] = {}
    for base in source_paths:
        for path in sorted(base.rglob("*")):
            if (
                path.is_file()
                and "__pycache__" not in path.parts
                and "results" not in path.parts
                and "raw-pandas-qualification" not in path.parts
                and "supporting" not in path.parts
                and path.suffix != ".pyc"
            ):
                sources[str(path.relative_to(ROOT))] = sha256_file(path)
    payload = {
        "commit": git_output("rev-parse", "HEAD"),
        "tree": git_output("write-tree"),
        "dirty_status_sha256": sha256_bytes(status.encode()),
        "source_digests": sources,
    }
    payload["build_id"] = sha256_bytes(canonical_json(payload))
    return payload


def host_environment() -> dict[str, Any]:
    def text(path: str) -> str | None:
        try:
            return Path(path).read_text(encoding="utf-8").strip()
        except OSError:
            return None

    cpu = ""
    for line in (text("/proc/cpuinfo") or "").splitlines():
        if line.startswith("model name"):
            cpu = line.partition(":")[2].strip()
            break
    memory = os.sysconf("SC_PAGE_SIZE") * os.sysconf("SC_PHYS_PAGES")
    os_release = {}
    for line in (text("/etc/os-release") or "").splitlines():
        key, separator, value = line.partition("=")
        if separator:
            os_release[key] = value.strip('"')
    return {
        "platform": platform.platform(),
        "system": platform.system().lower(),
        "kernel": platform.release(),
        "machine": platform.machine(),
        "python": sys.version,
        "cpu_model": cpu,
        "cpu_affinity": sorted(os.sched_getaffinity(0))
        if hasattr(os, "sched_getaffinity")
        else None,
        "memory_bytes": memory,
        "governor": text("/sys/devices/system/cpu/cpu0/cpufreq/scaling_governor"),
        "boost": text("/sys/devices/system/cpu/cpufreq/boost"),
        "load_average": list(os.getloadavg()),
        "os_release": os_release,
    }


@dataclass(frozen=True, slots=True)
class Cell:
    evaluation: int
    mode: str
    workload: str
    task: str
    session: int
    repetition: int
    phase: str
    seed: int

    @property
    def key(self) -> tuple[Any, ...]:
        return (
            self.evaluation,
            self.mode,
            self.workload,
            self.task,
            self.session,
            self.repetition,
            self.phase,
        )


def _seed(config: Mapping[str, Any], *parts: object) -> int:
    material = ":".join([str(config["random_seed"]), *(str(part) for part in parts)])
    return int(hashlib.sha256(material.encode()).hexdigest()[:16], 16)


def request_cells(config: Mapping[str, Any], evaluation: int | None = None) -> Iterator[Cell]:
    performance = config["performance"]
    sessions = range(performance["sessions"])
    measured = performance["measured_repetitions_per_workload_per_session"]
    evaluations = {item["id"]: item for item in config["evaluations"]}
    if evaluation in (None, 1):
        spec = evaluations[1]
        for session in sessions:
            blocks: list[list[Cell]] = []
            for app in spec["applications"]:
                for task in range(1, app["tasks"] + 1):
                    for mode in spec["modes"]:
                        block = [
                            Cell(
                                1,
                                mode,
                                app["id"],
                                str(task),
                                session,
                                -1,
                                "warmup",
                                _seed(config, 1, mode, app["id"], task, session, -1),
                            )
                        ]
                        block.extend(
                            Cell(
                                1,
                                mode,
                                app["id"],
                                str(task),
                                session,
                                repetition,
                                "measured",
                                _seed(config, 1, mode, app["id"], task, session, repetition),
                            )
                            for repetition in range(measured)
                        )
                        blocks.append(block)
            random.Random(_seed(config, "macro-order", session)).shuffle(blocks)
            for block in blocks:
                yield from block
    if evaluation in (None, 3):
        spec = evaluations[3]
        for session in sessions:
            for workload in spec["workloads"]:
                modes = list(spec["modes"])
                random.Random(_seed(config, "micro-order", workload["id"], session)).shuffle(modes)
                for mode in modes:
                    yield Cell(
                        3,
                        mode,
                        workload["id"],
                        "request",
                        session,
                        -1,
                        "warmup",
                        _seed(config, 3, mode, workload["id"], session, -1),
                    )
                    for repetition in range(measured):
                        yield Cell(
                            3,
                            mode,
                            workload["id"],
                            "request",
                            session,
                            repetition,
                            "measured",
                            _seed(config, 3, mode, workload["id"], session, repetition),
                        )
    if evaluation in (None, 4):
        spec = evaluations[4]
        for session in sessions:
            blocks = []
            for task in spec["tasks"]:
                for mode in spec["modes"]:
                    block = [
                        Cell(
                            4,
                            mode,
                            "pandas",
                            task,
                            session,
                            -1,
                            "warmup",
                            _seed(config, 4, mode, task, session, -1),
                        )
                    ]
                    block.extend(
                        Cell(
                            4,
                            mode,
                            "pandas",
                            task,
                            session,
                            repetition,
                            "measured",
                            _seed(config, 4, mode, task, session, repetition),
                        )
                        for repetition in range(measured)
                    )
                    blocks.append(block)
            random.Random(_seed(config, "pandas-order", session)).shuffle(blocks)
            for block in blocks:
                yield from block


def expected_route(config: Mapping[str, Any], cell: Cell) -> str:
    if cell.mode == "baseline":
        return "unprotected"
    if cell.mode == "argus-language":
        return "language"
    if cell.mode == "argus-host":
        return "host"
    if cell.mode == "argus" and cell.evaluation == 1:
        applications = config["evaluations"][0]["applications"]
        return next(item["argus_route"] for item in applications if item["id"] == cell.workload)
    if cell.mode == "argus" and cell.evaluation == 4:
        return "host"
    if cell.mode in {"nono", "apf"}:
        return cell.mode
    raise ValueError(f"no expected route for {cell}")


def record_for(
    cell: Cell,
    *,
    configuration_id: str,
    build_id: str,
    route: str,
    preflight_ns: int,
    runtime_start_ns: int,
    runtime_end_ns: int,
    outcome: str,
    oracle_passed: bool,
    counters: Mapping[str, Any] | None = None,
    **extra: Any,
) -> dict[str, Any]:
    record = {
        "schema_version": 1,
        "campaign_id": "unified-final-v1",
        "config_id": configuration_id,
        "build_id": build_id,
        "evaluation": cell.evaluation,
        "mode": cell.mode,
        "workload": cell.workload,
        "task": cell.task,
        "session": cell.session,
        "repetition": cell.repetition,
        "seed": cell.seed,
        "phase": cell.phase,
        "route": route,
        "preflight_ns": preflight_ns,
        "runtime_start_ns": runtime_start_ns,
        "runtime_end_ns": runtime_end_ns,
        "runtime_ns": runtime_end_ns - runtime_start_ns,
        "outcome": outcome,
        "oracle_passed": oracle_passed,
        "counters": dict(counters or {}),
        **extra,
    }
    return record


def percentile(values: Iterable[float], probability: float) -> float:
    ordered = sorted(values)
    if not ordered:
        return math.nan
    position = (len(ordered) - 1) * probability
    low = math.floor(position)
    high = math.ceil(position)
    if low == high:
        return ordered[low]
    return ordered[low] + (ordered[high] - ordered[low]) * (position - low)


def write_json(path: Path, value: Any) -> None:
    path.write_text(json.dumps(value, indent=2, sort_keys=True) + "\n", encoding="utf-8")


def append_jsonl(path: Path, values: Iterable[Mapping[str, Any]]) -> None:
    with path.open("a", encoding="utf-8") as stream:
        for value in values:
            stream.write(json.dumps(value, sort_keys=True) + "\n")
