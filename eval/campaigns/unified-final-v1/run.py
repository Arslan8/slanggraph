"""Single preparation, qualification, and collection entry point."""

from __future__ import annotations

import argparse
import json
import shutil
import subprocess
import sys
import time
import urllib.request
from collections import deque
from concurrent.futures import ThreadPoolExecutor
from pathlib import Path
from typing import Any

from admission_fuzz import run_fuzz
from campaign import (
    HERE,
    ROOT,
    build_identity,
    config_id,
    host_environment,
    load_config,
    request_cells,
    sha256_file,
    write_json,
)
from comparator_qualification import run as comparator_qualification_pilot
from host_security import collect_linux as collect_linux_host_security
from macrobenchmarks import collect as collect_macrobenchmarks
from macrobenchmarks import qualification_pilot as macro_qualification_pilot
from microbenchmarks import (
    collect_request_latency,
    collect_sustained,
)
from microbenchmarks import (
    qualification_pilot as micro_qualification_pilot,
)
from pandas_case_study import collect as collect_pandas
from pandas_case_study import qualification_pilot as pandas_qualification_pilot


def _copy_frozen_inputs(result: Path) -> None:
    for name in (
        "configuration.json",
        "admission_inventory.json",
        "policy_mapping.json",
        "host_cases.json",
    ):
        shutil.copy2(HERE / name, result / name)


def _binary(name: str, fallback: Path | None = None) -> dict[str, Any]:
    found = shutil.which(name)
    path = Path(found) if found else fallback
    if path is None or not path.is_file():
        return {"available": False, "requested": name}
    version = subprocess.run(
        [str(path), "--version"], cwd=ROOT, capture_output=True, text=True, check=False, timeout=10
    )
    return {
        "available": True,
        "path": str(path.resolve()),
        "sha256": sha256_file(path),
        "version_stdout": version.stdout.strip(),
        "version_stderr": version.stderr.strip(),
        "version_returncode": version.returncode,
    }


def _model(config: dict[str, Any]) -> dict[str, Any]:
    try:
        with urllib.request.urlopen("http://127.0.0.1:11434/api/tags", timeout=5) as response:
            payload = json.load(response)
    except Exception as exc:
        return {"available": False, "error": repr(exc)}
    expected = config["model"]
    candidates = [
        item for item in payload.get("models", []) if item.get("name") == expected["name"]
    ]
    return {
        "available": bool(candidates),
        "expected_name": expected["name"],
        "expected_digest": expected["digest"],
        "matches_digest": any(item.get("digest") == expected["digest"] for item in candidates),
        "served": candidates,
    }


def _docker_image(tag: str) -> dict[str, Any]:
    completed = subprocess.run(
        ["docker", "image", "inspect", tag, "--format", "{{.Id}}"],
        cwd=ROOT,
        capture_output=True,
        text=True,
        check=False,
        timeout=30,
    )
    return {
        "tag": tag,
        "available": completed.returncode == 0,
        "image_id": completed.stdout.strip() if completed.returncode == 0 else None,
        "stderr": completed.stderr.strip(),
    }


def prepare(result: Path) -> dict[str, Any]:
    result.mkdir(parents=True, exist_ok=False)
    _copy_frozen_inputs(result)
    config = load_config(result / "configuration.json")
    build = build_identity()
    environment = host_environment()
    nono = ROOT / "eval/vendor/nono/target/release/nono"
    openshell = ROOT / "eval/campaigns/remediation-v2/raw/openshell-setup/openshell"
    pins = {
        "schema_version": 1,
        "campaign_id": config["campaign_id"],
        "config_id": config_id(config),
        "build": build,
        "environment": environment,
        "executables": {
            "cedar": _binary("cedar"),
            "bubblewrap": _binary("bwrap"),
            "nono": _binary("nono", nono),
            "openshell": _binary("openshell", openshell),
        },
        "model": _model(config),
        "apf_image": _docker_image(config["comparators"]["apf"]["image"]),
        "checker_candidates": [],
        "dependency_lock_digests": {
            str(path.relative_to(ROOT)): sha256_file(path)
            for path in sorted(ROOT.rglob("uv.lock"))
            if ".git" not in path.parts
        },
        "background_services": ["ollama:127.0.0.1:11434", "openshell:127.0.0.1:18080"],
    }
    for path in (
        ROOT / "proofs/worker-route/.lake/build/lib/libargus_worker_route.so",
        ROOT / "proofs/worker-route/.lake/build/lib/libargus_worker_route.dylib",
        ROOT / "proofs/language-route/.lake/build/lib/libargus_language_route.so",
        ROOT / "proofs/language-route/.lake/build/lib/libargus_language_route.dylib",
    ):
        if path.is_file():
            checker = {"path": str(path.relative_to(ROOT)), "sha256": sha256_file(path)}
            manifest_path = path.with_suffix(path.suffix + ".json")
            if manifest_path.is_file():
                manifest = json.loads(manifest_path.read_text())
                runtime = Path(manifest["native_runtime"])
                checker.update(
                    manifest_path=str(manifest_path.relative_to(ROOT)),
                    manifest_sha256=sha256_file(manifest_path),
                    native_runtime=str(runtime),
                    native_runtime_sha256=sha256_file(runtime),
                    checker_interface="compiled-shared-library",
                )
            pins["checker_candidates"].append(checker)
    write_json(result / "source-pins.json", pins)
    schedule = [
        {
            "evaluation": cell.evaluation,
            "mode": cell.mode,
            "workload": cell.workload,
            "task": cell.task,
            "session": cell.session,
            "repetition": cell.repetition,
            "phase": cell.phase,
            "seed": cell.seed,
        }
        for cell in request_cells(config)
    ]
    write_json(result / "schedule.json", schedule)
    for name in ("records.jsonl", "host-security.jsonl", "sustained.jsonl"):
        (result / name).touch()
    prepared = {
        "prepared": True,
        "campaign_id": config["campaign_id"],
        "config_id": config_id(config),
        "build_id": build["build_id"],
        "scheduled_request_records": len(schedule),
        "prepared_at_unix_ns": time.time_ns(),
    }
    write_json(result / "prepared.json", prepared)
    return prepared


def _timing_probe(mode: str, preflight_delay: float, runtime_delay: float) -> dict[str, Any]:
    command = [
        sys.executable,
        str(HERE / "qualification_worker.py"),
        "--mode",
        mode,
        "--preflight-delay",
        str(preflight_delay),
        "--runtime-delay",
        str(runtime_delay),
    ]
    setup_started = time.monotonic_ns()
    process = subprocess.Popen(
        command,
        cwd=ROOT,
        stdin=subprocess.PIPE,
        stdout=subprocess.PIPE,
        stderr=subprocess.PIPE,
        text=True,
    )
    assert process.stdout is not None and process.stdin is not None
    ready = json.loads(process.stdout.readline())
    preflight_ns = time.monotonic_ns() - setup_started
    runtime_start = time.monotonic_ns()
    process.stdin.write(json.dumps({"value": "oracle"}) + "\n")
    process.stdin.flush()
    result = json.loads(process.stdout.readline())
    runtime_end = time.monotonic_ns()
    _, stderr = process.communicate(timeout=5)
    return {
        "mode": mode,
        "ready": ready,
        "result": result,
        "preflight_ns": preflight_ns,
        "runtime_ns": runtime_end - runtime_start,
        "returncode": process.returncode,
        "stderr": stderr,
    }


def _timer_qualification() -> dict[str, Any]:
    modes = ("baseline", "argus", "nono", "apf", "argus-language", "argus-host", "pandas")
    preflight = [_timing_probe(mode, 0.08, 0.0) for mode in modes]
    runtime = [_timing_probe(mode, 0.0, 0.08) for mode in modes]
    passed = all(
        row["preflight_ns"] >= 70_000_000 and row["runtime_ns"] < 50_000_000 for row in preflight
    ) and all(row["runtime_ns"] >= 70_000_000 for row in runtime)
    return {
        "scope": (
            "campaign parent/ready handshake unit qualification; production adapters "
            "must independently expose the same boundary"
        ),
        "preflight_delay": preflight,
        "runtime_delay": runtime,
        "passed": passed,
    }


def _pool_qualification() -> dict[str, Any]:
    ready = deque(range(2))
    pool_misses = 0
    replacements = 0
    waits_ns = []

    def request(_: int) -> None:
        nonlocal pool_misses, replacements
        started = time.monotonic_ns()
        while True:
            try:
                worker = ready.popleft()
                break
            except IndexError:
                pool_misses += 1
                time.sleep(0.002)
        waits_ns.append(time.monotonic_ns() - started)
        time.sleep(0.01)
        replacements += 1
        ready.append(worker)

    with ThreadPoolExecutor(max_workers=4) as executor:
        list(executor.map(request, range(8)))
    return {
        "initial_ready": 2,
        "final_ready": len(ready),
        "pool_misses": pool_misses,
        "replacements": replacements,
        "waits_ns": waits_ns,
        "passed": pool_misses > 0 and replacements == 8 and len(ready) == 2 and max(waits_ns) > 0,
    }


def _test_command() -> dict[str, Any]:
    command = [
        "uv",
        "run",
        "--project",
        "libs/prebuilt",
        "pytest",
        "-q",
        "libs/prebuilt/tests/security/test_language_loops.py",
        "libs/prebuilt/tests/security/test_library_mediators.py",
        "libs/prebuilt/tests/security/test_language_file_binding.py",
        "libs/prebuilt/tests/security/test_language_route_verification.py",
    ]
    completed = subprocess.run(
        command, cwd=ROOT, capture_output=True, text=True, check=False, timeout=900
    )
    return {
        "command": command,
        "returncode": completed.returncode,
        "stdout": completed.stdout,
        "stderr": completed.stderr,
        "passed": completed.returncode == 0,
    }


def qualify(result: Path, macos_evidence: Path | None) -> dict[str, Any]:
    config = load_config(result / "configuration.json")
    pins = json.loads((result / "source-pins.json").read_text())
    fuzz_dir = result / "supporting" / "admission-fuzz"
    if fuzz_dir.exists():
        raise FileExistsError(f"qualification output already exists: {fuzz_dir}")
    fuzz = run_fuzz(config, fuzz_dir)
    tests = _test_command()
    timer = _timer_qualification()
    pool = _pool_qualification()
    micro = micro_qualification_pilot()
    macro = macro_qualification_pilot()
    comparators = comparator_qualification_pilot()
    pandas = pandas_qualification_pilot()
    current_build = build_identity()
    external = {
        "linux_host": pins["environment"]["system"] == "linux",
        "ubuntu_24_04": pins["environment"].get("os_release", {}).get("VERSION_ID") == "24.04",
        "model_available": pins["model"].get("available") is True,
        "model_digest": pins["model"].get("matches_digest") is True,
        "cedar": pins["executables"]["cedar"].get("available") is True,
        "bubblewrap": pins["executables"]["bubblewrap"].get("available") is True,
        "nono": pins["executables"]["nono"].get("available") is True,
        "openshell": pins["executables"]["openshell"].get("available") is True,
        "apf_image": pins["apf_image"].get("image_id") == config["comparators"]["apf"]["image_id"],
        "compiled_checker": bool(pins["checker_candidates"]),
        "build_stable": current_build["build_id"] == pins["build"]["build_id"],
        "macos_evidence_external_pending": not (
            macos_evidence is not None and macos_evidence.is_file()
        ),
    }
    adapter_contracts = {
        "macro_parent_ready_handshake": macro["passed"],
        "comparators_parent_ready_handshake": comparators["passed"],
        "comparators_best_available_enforcement_pilot": comparators["passed"],
        "pandas_parent_ready_handshake": pandas["passed"],
        "micro_identical_source_three_routes": micro["passed"],
        "sustained_inventory_restoration": micro["passed"],
    }
    required_external = {
        name: passed
        for name, passed in external.items()
        if name != "macos_evidence_external_pending"
    }
    blockers = [
        name for name, passed in {**required_external, **adapter_contracts}.items() if not passed
    ]
    passed = (
        fuzz["passed"] and tests["passed"] and timer["passed"] and pool["passed"] and not blockers
    )
    report = {
        "schema_version": 1,
        "campaign_id": config["campaign_id"],
        "config_id": config_id(config),
        "build_id": pins["build"]["build_id"],
        "fuzz": fuzz,
        "correspondence_and_mediator_tests": tests,
        "timer_contract_unit_probe": timer,
        "worker_pool_unit_probe": pool,
        "production_microbenchmark_pilot": micro,
        "production_macrobenchmark_pilot": macro,
        "production_comparator_pilot": comparators,
        "production_pandas_pilot": pandas,
        "external_prerequisites": external,
        "production_adapter_contracts": adapter_contracts,
        "blockers": blockers,
        "passed": passed,
        "delay_injection_removed": True,
    }
    write_json(result / "supporting-validation.json", report)
    write_json(result / "qualification.json", report)
    return report


def freeze(result: Path) -> dict[str, Any]:
    qualification = json.loads((result / "qualification.json").read_text())
    if qualification.get("passed") is not True:
        raise RuntimeError("qualification has not passed; collection freeze is forbidden")
    build = build_identity()
    if build["build_id"] != qualification["build_id"]:
        raise RuntimeError("source/build changed after qualification")
    report = {
        "frozen": True,
        "config_id": qualification["config_id"],
        "build_id": qualification["build_id"],
        "frozen_at_unix_ns": time.time_ns(),
    }
    write_json(result / "freeze.json", report)
    return report


def collect(result: Path, evaluation: int) -> None:
    freeze_record = result / "freeze.json"
    if not freeze_record.exists() or not json.loads(freeze_record.read_text()).get("frozen"):
        raise RuntimeError("collection requires a passing qualification and frozen build")
    if evaluation == 3:
        request = collect_request_latency(result)
        sustained = collect_sustained(result)
        if not request["passed"] or not sustained["passed"]:
            raise RuntimeError(
                "microbenchmark collection completed with failed correctness/security outcomes"
            )
        return
    if evaluation == 1:
        report = collect_macrobenchmarks(result)
        if not report["passed"]:
            raise RuntimeError("macrobenchmark collection did not complete")
        return
    if evaluation == 2:
        report = collect_linux_host_security(result)
        if not report["passed"]:
            raise RuntimeError("Linux host-security evidence failed verification")
        return
    if evaluation == 4:
        report = collect_pandas(result)
        if not report["passed"]:
            raise RuntimeError("Pandas collection or resource controls did not complete")
        return
    raise AssertionError(f"unexpected evaluation: {evaluation}")


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    subparsers = parser.add_subparsers(dest="command", required=True)
    prepare_parser = subparsers.add_parser("prepare")
    prepare_parser.add_argument("--output", type=Path, required=True)
    qualify_parser = subparsers.add_parser("qualify")
    qualify_parser.add_argument("--result", type=Path, required=True)
    qualify_parser.add_argument("--macos-evidence", type=Path)
    freeze_parser = subparsers.add_parser("freeze")
    freeze_parser.add_argument("--result", type=Path, required=True)
    collect_parser = subparsers.add_parser("collect")
    collect_parser.add_argument("--result", type=Path, required=True)
    collect_parser.add_argument("--evaluation", type=int, choices=(1, 2, 3, 4), required=True)
    fuzz_parser = subparsers.add_parser("fuzz")
    fuzz_parser.add_argument("--output", type=Path, required=True)
    schedule_parser = subparsers.add_parser("schedule")
    schedule_parser.add_argument("--evaluation", type=int, choices=(1, 3, 4))
    args = parser.parse_args()
    if args.command == "prepare":
        print(json.dumps(prepare(args.output), indent=2))
    elif args.command == "qualify":
        report = qualify(args.result, args.macos_evidence)
        print(json.dumps(report, indent=2))
        return 0 if report["passed"] else 2
    elif args.command == "freeze":
        print(json.dumps(freeze(args.result), indent=2))
    elif args.command == "collect":
        collect(args.result, args.evaluation)
    elif args.command == "fuzz":
        print(json.dumps(run_fuzz(load_config(), args.output), indent=2))
    else:
        config = load_config()
        print(
            json.dumps(
                [
                    {
                        "evaluation": cell.evaluation,
                        "mode": cell.mode,
                        "workload": cell.workload,
                        "task": cell.task,
                        "session": cell.session,
                        "repetition": cell.repetition,
                        "phase": cell.phase,
                        "seed": cell.seed,
                    }
                    for cell in request_cells(config, args.evaluation)
                ],
                indent=2,
            )
        )
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
