"""Identical-body language/host file microbenchmarks."""

from __future__ import annotations

import hashlib
import importlib.util
import json
import random
import statistics
import sys
import tempfile
import threading
import time
import uuid
from collections import defaultdict
from concurrent.futures import ThreadPoolExecutor
from dataclasses import dataclass
from pathlib import Path
from typing import Any

from campaign import (
    HERE,
    append_jsonl,
    load_config,
    percentile,
    record_for,
    request_cells,
    sha256_file,
)
from langchain_core.tools import StructuredTool
from langgraph.prebuilt.security import (
    IntegrityRecheckMode,
    LinuxObjectDispatcher,
    LinuxToolSpec,
    Principal,
    cedar_security,
)
from langgraph.prebuilt.security.lean_lifecycle import LeanLifecycleChecker
from langgraph.prebuilt.security.types import Tool, ToolCall, ToolDac
from micro_workload import read_file, write_file

WORKLOAD_SOURCE = HERE / "micro_workload.py"
HOST_ADAPTER_SOURCE = HERE / "micro_host_adapter.py"
CHECKER = HERE.parents[2] / "proofs/worker-route/.lake/build/lib/libargus_worker_route.so"
CHECKER_MANIFEST = CHECKER.with_suffix(CHECKER.suffix + ".json")


@dataclass(frozen=True, slots=True)
class Workload:
    identifier: str
    operation: str
    size: int
    content: bytes


def workloads(config: dict[str, Any]) -> dict[str, Workload]:
    result = {}
    for spec in config["evaluations"][2]["workloads"]:
        size = spec["bytes"]
        content = (b"argus-file-workload-0123456789!!" * ((size // 32) + 1))[:size]
        if len(content) != size:
            raise AssertionError("microbenchmark fixture size changed")
        result[spec["id"]] = Workload(spec["id"], spec["operation"], size, content)
    return result


def _runtime_roots() -> tuple[Path, ...]:
    roots = [HERE]
    roots.extend(Path(item).resolve() for item in sys.path if item and Path(item).is_dir())
    return tuple(dict.fromkeys(roots))


def _tool(workload: Workload) -> StructuredTool:
    function = read_file if workload.operation == "read" else write_file
    return StructuredTool.from_function(
        function,
        name=f"micro_{workload.operation}",
        description=function.__doc__ or "file microbenchmark",
    )


def _call(workload: Workload, path: Path, call_id: str) -> ToolCall:
    name = f"micro_{workload.operation}"
    arguments = {"path": str(path)}
    if workload.operation == "write":
        arguments["value"] = workload.content.decode("ascii")
    return ToolCall(
        Tool(name, ToolDac("application", {"*": "x"}), frozenset(), ()),
        arguments,
        {},
        call_id,
        0,
    )


def _policy(path: Path, workload: Workload, route: str) -> str:
    operations = [workload.operation]
    if route == "linux" and workload.operation == "write":
        operations = ["write", "truncate"]
    selector = json.dumps(str(path.resolve()))
    return "\n".join(
        (
            'permit(principal == slangGraph::User::"alice", '
            f'action == slangGraph::Action::"fs::{operation}", resource) '
            f"when {{ resource.selector == {selector} }};"
        )
        for operation in operations
    )


def _manifest(workload: Workload, route: str) -> str:
    operations = [workload.operation]
    if route == "linux" and workload.operation == "write":
        operations = ["write", "truncate"]
    return "\n".join(
        [f"runs {route}", *(f"fs {operation} @{{path}} need" for operation in operations)]
    )


def _load_baseline_module(label: str):
    name = f"unified_final_micro_{label}_{uuid.uuid4().hex}"
    # Baseline and host execute the same minimal native useful operation.  The
    # language route expresses that operation through its registered facade.
    spec = importlib.util.spec_from_file_location(name, HOST_ADAPTER_SOURCE)
    if spec is None or spec.loader is None:
        raise RuntimeError("cannot load shared microbenchmark source")
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


class Route:
    route = "unprotected"

    def __init__(self, workload: Workload, path: Path, concurrency: int = 1) -> None:
        self.workload = workload
        self.path = path
        self.concurrency = concurrency
        self.preflight_ns = 0

    def invoke(self, call_id: str, worker: int = 0) -> tuple[str, int, dict[str, Any]]:
        raise NotImplementedError

    def restore(self, timeout: float = 60.0) -> tuple[int, int]:
        del timeout
        restored = time.monotonic_ns()
        return restored, restored

    def close(self) -> None:
        pass


class BaselineRoute(Route):
    route = "unprotected"

    def __init__(self, workload: Workload, path: Path, concurrency: int = 1) -> None:
        started = time.monotonic_ns()
        super().__init__(workload, path, concurrency)
        self.modules = [_load_baseline_module(str(index)) for index in range(concurrency)]
        self.preflight_ns = time.monotonic_ns() - started

    def invoke(self, call_id: str, worker: int = 0) -> tuple[str, int, dict[str, Any]]:
        del call_id
        module = self.modules[worker]
        if self.workload.operation == "read":
            value = module.host_read_file(str(self.path))
        else:
            value = module.host_write_file(str(self.path), self.workload.content.decode("ascii"))
        return value, 0, {}


class LanguageRoute(Route):
    route = "language"

    def __init__(self, workload: Workload, path: Path, concurrency: int = 1) -> None:
        started = time.monotonic_ns()
        super().__init__(workload, path, concurrency)
        security = cedar_security(
            _tool(workload),
            manifest=_manifest(workload, "inprocess"),
            policy=_policy(path, workload, "inprocess"),
            executable="cedar",
        )
        self.executor = security.host_executor
        self.principal = Principal("alice", frozenset(), frozenset(), "micro-session")
        self.preflight_ns = time.monotonic_ns() - started

    def invoke(self, call_id: str, worker: int = 0) -> tuple[str, int, dict[str, Any]]:
        del worker
        result = self.executor.invoke(
            self.principal,
            _call(self.workload, self.path, call_id),
            (),
        )
        return (
            result.value,
            0,
            {
                "authorization_checks": 1,
                "cleanup_completed": 1,
                "receipt_mode": result.receipt.mode.value,
            },
        )


class HostRoute(Route):
    route = "host"

    def __init__(self, workload: Workload, path: Path, concurrency: int = 1) -> None:
        started = time.monotonic_ns()
        super().__init__(workload, path, concurrency)
        if not CHECKER.is_file() or not CHECKER_MANIFEST.is_file():
            raise RuntimeError(f"compiled worker checker or build manifest missing: {CHECKER}")
        checker_manifest = json.loads(CHECKER_MANIFEST.read_text())
        runtime = Path(checker_manifest["native_runtime"])
        if not runtime.is_file():
            raise RuntimeError(f"compiled checker runtime missing: {runtime}")
        checker = LeanLifecycleChecker(
            str(CHECKER),
            sha256_file(CHECKER),
            str(runtime),
            sha256_file(runtime),
        )
        checker.require_inline()
        self.checker = checker
        digest = hashlib.sha256(HOST_ADAPTER_SOURCE.read_bytes()).hexdigest()
        entrypoint = (
            "micro_host_adapter:host_read_file"
            if workload.operation == "read"
            else "micro_host_adapter:host_write_file"
        )
        self.dispatcher = LinuxObjectDispatcher(
            {
                f"micro_{workload.operation}": LinuxToolSpec(
                    entrypoint,
                    HOST_ADAPTER_SOURCE,
                    digest,
                )
            },
            runtime_roots=_runtime_roots(),
            lifecycle_checker=checker,
            worker_pool_capacity=8,
            integrity_recheck=IntegrityRecheckMode.PREFLIGHT_ONLY,
        )
        security = cedar_security(
            _tool(workload),
            manifest=_manifest(workload, "linux"),
            policy=_policy(path, workload, "linux"),
            executable="cedar",
            dispatcher=self.dispatcher,
        )
        self.executor = security.host_executor
        self.principal = Principal("alice", frozenset(), frozenset(), "micro-session")
        self.preflight_call = _call(workload, path, "pool-preflight")
        prepared = self.executor.prewarm(
            self.principal,
            self.preflight_call,
            (),
            count=8,
        )
        if prepared != 8:
            raise RuntimeError(f"host pool prepared {prepared}, expected 8")
        self._permits = threading.Semaphore(8)
        self._stop = threading.Event()
        self._provision_error: BaseException | None = None
        self._replenishments = 0
        self._thread = threading.Thread(
            target=self._provision,
            name="argus-micro-provisioner",
            daemon=True,
        )
        self._thread.start()
        self.preflight_ns = time.monotonic_ns() - started

    def _provision(self) -> None:
        while not self._stop.is_set():
            try:
                idle = self.dispatcher.worker_pool_stats()["idle"]
                if idle < 8:
                    prepared = self.executor.prewarm(
                        self.principal,
                        self.preflight_call,
                        (),
                        count=1,
                    )
                    if prepared:
                        self._replenishments += prepared
                        self._permits.release()
                        continue
            except BaseException as exc:
                if "worker_pool_full" not in str(exc):
                    self._provision_error = exc
                    self._stop.set()
                    return
            self._stop.wait(0.0005)

    def invoke(self, call_id: str, worker: int = 0) -> tuple[str, int, dict[str, Any]]:
        del worker
        queued = time.monotonic_ns()
        if not self._permits.acquire(timeout=60):
            raise TimeoutError("timed out waiting for a prepared host worker")
        queue_wait_ns = time.monotonic_ns() - queued
        before = dict(self.dispatcher.worker_pool_stats())
        try:
            result = self.executor.invoke(
                self.principal,
                _call(self.workload, self.path, call_id),
                (),
            )
        except BaseException:
            after = dict(self.dispatcher.worker_pool_stats())
            if after["idle"] == before["idle"]:
                self._permits.release()
            raise
        stats = dict(self.dispatcher.worker_pool_stats())
        if self._provision_error is not None:
            raise RuntimeError("host provisioner failed") from self._provision_error
        return (
            result.value,
            queue_wait_ns,
            {
                "authorization_checks": 1,
                "cleanup_completed": 1,
                "checker_protocol": "worker-route-grant-v3",
                "checker_interface": "compiled-shared-library",
                "checker_statistics": self.checker.statistics(),
                "integrity_recheck": "preflight-only",
                "pool_hits": stats["hits"],
                "pool_misses": stats["misses"],
                "replenishments": self._replenishments,
                "ready_inventory": stats["idle"],
                "receipt_mode": result.receipt.mode.value,
            },
        )

    def restore(self, timeout: float = 60.0) -> tuple[int, int]:
        delivered = time.monotonic_ns()
        deadline = time.monotonic() + timeout
        while time.monotonic() < deadline:
            if self._provision_error is not None:
                raise RuntimeError("host provisioner failed") from self._provision_error
            if self.dispatcher.worker_pool_stats()["idle"] == 8:
                return delivered, time.monotonic_ns()
            time.sleep(0.001)
        raise TimeoutError("host worker inventory was not restored")

    def close(self) -> None:
        self._stop.set()
        self._thread.join(timeout=5)
        self.dispatcher.close()


def make_route(mode: str, workload: Workload, path: Path, concurrency: int = 1) -> Route:
    routes = {
        "baseline": BaselineRoute,
        "argus-language": LanguageRoute,
        "argus-host": HostRoute,
    }
    return routes[mode](workload, path, concurrency)


def _restore_fixture(path: Path, workload: Workload) -> None:
    path.write_bytes(workload.content)
    if path.read_bytes() != workload.content:
        raise RuntimeError("fixture restoration failed")


def _oracle(path: Path, workload: Workload, value: str) -> bool:
    returned = value.encode("utf-8") == workload.content
    return returned and (workload.operation == "read" or path.read_bytes() == workload.content)


def security_probes(
    mode: str,
    workload: Workload,
    root: Path,
) -> dict[str, Any]:
    root.mkdir(parents=True, exist_ok=False)
    allowed = root / "allowed.txt"
    secret = root / "secret.txt"
    symlink = root / "secret-link.txt"
    hardlink = root / "secret-hardlink.txt"
    nested = root / "nested"
    allowed.write_bytes(workload.content)
    secret.write_text("secret-canary-" + uuid.uuid4().hex)
    symlink.symlink_to(secret)
    hardlink.hardlink_to(secret)
    nested.mkdir()
    route = make_route(mode, workload, allowed)
    try:
        value, _, _ = route.invoke("probe-allowed")
        allowed_passed = _oracle(allowed, workload, value)
        forbidden = {}
        for label, path in (
            ("sibling", secret),
            ("alternate", nested / ".." / secret.name),
            ("symlink", symlink),
            ("hardlink", hardlink),
        ):
            try:
                route.path = path
                route.invoke("probe-" + label)
            except BaseException as exc:
                forbidden[label] = {"denied": True, "error": type(exc).__name__}
            else:
                forbidden[label] = {"denied": False, "error": None}
            finally:
                route.path = allowed
        secret_unchanged = secret.read_text().startswith("secret-canary-")
        protected = mode != "baseline"
        return {
            "mode": mode,
            "workload": workload.identifier,
            "allowed_passed": allowed_passed,
            "forbidden": forbidden,
            "secret_unchanged": secret_unchanged,
            "expected_protected": protected,
            "passed": (
                allowed_passed
                and (
                    all(item["denied"] for item in forbidden.values()) and secret_unchanged
                    if protected
                    else any(not item["denied"] for item in forbidden.values())
                )
            ),
        }
    finally:
        route.close()


def collect_request_latency(
    result: Path, *, selected_modes: frozenset[str] | None = None
) -> dict[str, Any]:
    config = load_config(result / "configuration.json")
    prepared = json.loads((result / "prepared.json").read_text())
    by_group: dict[tuple[int, str, str], list[Any]] = defaultdict(list)
    for cell in request_cells(config, 3):
        if selected_modes is not None and cell.mode not in selected_modes:
            continue
        by_group[(cell.session, cell.workload, cell.mode)].append(cell)
    specs = workloads(config)
    records = []
    probes = []
    evidence_root = result / "microbenchmarks" / "request-latency"
    evidence_root.mkdir(parents=True, exist_ok=False)
    # Keep bind-mount destinations short.  Deep result-directory paths can
    # intermittently fail inside bubblewrap before the allowed file is opened;
    # fixtures are transient inputs, while all records remain in the result.
    result_key = hashlib.sha256(str(result.resolve()).encode()).hexdigest()[:8]
    root = Path("/tmp") / f"argus-ufv1-micro-{prepared['build_id'][:12]}-{result_key}"
    root.mkdir(parents=True, exist_ok=False)
    for session in range(config["performance"]["sessions"]):
        modes = list(config["evaluations"][2]["modes"])
        if selected_modes is not None:
            modes = [mode for mode in modes if mode in selected_modes]
        random.Random(config["random_seed"] + session).shuffle(modes)
        for workload_id, workload in specs.items():
            for mode in modes:
                cells = by_group[(session, workload_id, mode)]
                folder = root / f"session-{session}" / workload_id / mode
                folder.mkdir(parents=True)
                path = folder / "fixture.txt"
                _restore_fixture(path, workload)
                path.read_bytes()
                probes.append(security_probes(mode, workload, folder / "probes"))
                route = make_route(mode, workload, path)
                try:
                    for cell in cells:
                        if workload.operation == "write":
                            _restore_fixture(path, workload)
                        started = time.monotonic_ns()
                        outcome = "completed"
                        passed = False
                        counters: dict[str, Any] = {}
                        try:
                            value, queue_wait_ns, counters = route.invoke(
                                f"s{session}-{workload_id}-{mode}-{cell.repetition}"
                            )
                            counters["queue_wait_ns"] = queue_wait_ns
                            passed = _oracle(path, workload, value)
                        except BaseException as exc:
                            outcome = "failed"
                            counters = {"error_type": type(exc).__name__, "error": str(exc)}
                        ended = time.monotonic_ns()
                        records.append(
                            record_for(
                                cell,
                                configuration_id=prepared["config_id"],
                                build_id=prepared["build_id"],
                                route=route.route,
                                preflight_ns=route.preflight_ns,
                                runtime_start_ns=started,
                                runtime_end_ns=ended,
                                outcome=outcome,
                                oracle_passed=passed,
                                counters=counters,
                            )
                        )
                finally:
                    route.close()
    append_jsonl(result / "records.jsonl", records)
    append_jsonl(result / "micro-security.jsonl", probes)
    return {
        "records": len(records),
        "probes": len(probes),
        "passed": all(row["passed"] for row in probes)
        and all(row["outcome"] == "completed" and row["oracle_passed"] for row in records),
    }


def _sustained_session(
    mode: str,
    workload: Workload,
    path: Path,
    concurrency: int,
    warmup_seconds: float,
    issue_seconds: float,
) -> dict[str, Any]:
    route = make_route(mode, workload, path, concurrency)
    sequence = 0
    sequence_lock = threading.Lock()

    def next_id(prefix: str) -> str:
        nonlocal sequence
        with sequence_lock:
            sequence += 1
            return f"{prefix}-{sequence}"

    def warm(worker: int) -> None:
        deadline = time.monotonic() + warmup_seconds
        while time.monotonic() < deadline:
            route.invoke(next_id("warm"), worker)

    latencies = []
    queue_waits = []
    failures = 0
    lock = threading.Lock()

    with ThreadPoolExecutor(max_workers=concurrency) as executor:
        list(executor.map(warm, range(concurrency)))
        measured_start_ns = time.monotonic_ns()
        issue_deadline_ns = measured_start_ns + int(issue_seconds * 1e9)

        def measured(worker: int) -> None:
            nonlocal failures
            local_latencies = []
            local_waits = []
            local_failures = 0
            while time.monotonic_ns() < issue_deadline_ns:
                started = time.monotonic_ns()
                try:
                    value, queue_wait, _ = route.invoke(next_id("measured"), worker)
                    if not _oracle(path, workload, value):
                        local_failures += 1
                    local_waits.append(queue_wait)
                except BaseException:
                    local_failures += 1
                local_latencies.append(time.monotonic_ns() - started)
            with lock:
                latencies.extend(local_latencies)
                queue_waits.extend(local_waits)
                failures += local_failures

        list(executor.map(measured, range(concurrency)))
        delivery_end_ns = time.monotonic_ns()
    delivered, restoration_end_ns = route.restore()
    del delivered
    stats = (
        dict(route.dispatcher.worker_pool_stats())
        if isinstance(route, HostRoute)
        else {"idle": 0, "misses": 0}
    )
    replenishments = route._replenishments if isinstance(route, HostRoute) else 0
    route.close()
    completed = len(latencies) - failures
    return {
        "offered": len(latencies),
        "completed": completed,
        "failed": failures,
        "completions_per_second": completed / issue_seconds,
        "latency_p50_ns": percentile(latencies, 0.50),
        "latency_p95_ns": percentile(latencies, 0.95),
        "latency_p99_ns": percentile(latencies, 0.99),
        "latency_mean_ns": statistics.fmean(latencies) if latencies else None,
        "latency_ns": latencies,
        "queue_wait_ns": queue_waits,
        "queue_wait_p95_ns": percentile(queue_waits, 0.95),
        "pool_misses": stats["misses"],
        "replenishments": replenishments,
        "initial_ready": 8 if mode == "argus-host" else 0,
        "final_ready": stats["idle"],
        "runtime_start_ns": measured_start_ns,
        "issue_end_ns": issue_deadline_ns,
        "delivery_end_ns": delivery_end_ns,
        "restoration_end_ns": restoration_end_ns,
        "drain_ns": delivery_end_ns - issue_deadline_ns,
        "restoration_ns": restoration_end_ns - delivery_end_ns,
        "preflight_ns": route.preflight_ns,
    }


def qualification_pilot() -> dict[str, Any]:
    """Exercise every micro route and the real host replacement lifecycle."""
    config = load_config()
    rows = []
    sustained = []
    with tempfile.TemporaryDirectory(prefix="argus-unified-micro-pilot-") as directory:
        root = Path(directory)
        for workload in workloads(config).values():
            for mode in config["evaluations"][2]["modes"]:
                rows.append(
                    security_probes(
                        mode,
                        workload,
                        root / f"probe-{workload.identifier}-{mode}",
                    )
                )
        workload = workloads(config)["read-32"]
        for mode in config["evaluations"][2]["modes"]:
            path = root / f"sustained-{mode}.txt"
            _restore_fixture(path, workload)
            path.read_bytes()
            row = {
                "mode": mode,
                **_sustained_session(mode, workload, path, 8, 0.05, 0.20),
            }
            row["queue_wait_observed"] = (
                bool(row["queue_wait_ns"]) and max(row["queue_wait_ns"]) > 0
            )
            row.pop("latency_ns")
            row.pop("queue_wait_ns")
            sustained.append(row)
    host = next(row for row in sustained if row["mode"] == "argus-host")
    passed = (
        all(row["passed"] for row in rows)
        and all(row["failed"] == 0 for row in sustained)
        and host["replenishments"] > 0
        and host["initial_ready"] == host["final_ready"] == 8
        and host["queue_wait_observed"]
    )
    return {"request_and_security_probes": rows, "sustained": sustained, "passed": passed}


def collect_sustained(
    result: Path,
    *,
    warmup_seconds: float | None = None,
    issue_seconds: float | None = None,
    sessions: int | None = None,
    selected_modes: frozenset[str] | None = None,
) -> dict[str, Any]:
    config = load_config(result / "configuration.json")
    prepared = json.loads((result / "prepared.json").read_text())
    spec = config["evaluations"][2]["sustained"]
    workload = workloads(config)[spec["workload"]]
    warmup = spec["warmup_seconds"] if warmup_seconds is None else warmup_seconds
    issue = spec["issue_seconds"] if issue_seconds is None else issue_seconds
    count = spec["sessions"] if sessions is None else sessions
    evidence_root = result / "microbenchmarks" / "sustained"
    evidence_root.mkdir(parents=True, exist_ok=False)
    result_key = hashlib.sha256(str(result.resolve()).encode()).hexdigest()[:8]
    root = Path("/tmp") / f"argus-ufv1-sustained-{prepared['build_id'][:12]}-{result_key}"
    root.mkdir(parents=True, exist_ok=False)
    rows = []
    for session in range(count):
        for concurrency in spec["concurrency"]:
            modes = list(config["evaluations"][2]["modes"])
            if selected_modes is not None:
                modes = [mode for mode in modes if mode in selected_modes]
            random.Random(config["random_seed"] + session * 100 + concurrency).shuffle(modes)
            for mode in modes:
                folder = root / f"session-{session}" / f"c{concurrency}" / mode
                folder.mkdir(parents=True)
                path = folder / "fixture.txt"
                _restore_fixture(path, workload)
                path.read_bytes()
                row = _sustained_session(
                    mode,
                    workload,
                    path,
                    concurrency,
                    warmup,
                    issue,
                )
                rows.append(
                    {
                        "schema_version": 1,
                        "campaign_id": config["campaign_id"],
                        "config_id": prepared["config_id"],
                        "build_id": prepared["build_id"],
                        "evaluation": 3,
                        "mode": mode,
                        "route": {
                            "baseline": "unprotected",
                            "argus-language": "language",
                            "argus-host": "host",
                        }[mode],
                        "workload": workload.identifier,
                        "session": session,
                        "concurrency": concurrency,
                        "warmup_seconds": warmup,
                        "issue_seconds": issue,
                        **row,
                    }
                )
    append_jsonl(result / "sustained.jsonl", rows)
    return {"records": len(rows), "passed": all(not row["failed"] for row in rows)}
