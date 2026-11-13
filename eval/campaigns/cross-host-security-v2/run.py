"""Deterministic security campaign; no model and no overhead measurements."""

import argparse
import concurrent.futures
import importlib.metadata
import json
import os
import platform
import secrets
import shutil
import signal
import subprocess
import sys
import time
from contextlib import suppress
from pathlib import Path

import host
from specification import (
    ADDITIONAL_CASES,
    CASES,
    CLASSES,
    CLEANUP,
    MAC_POLICY,
    POLICY,
    REQUIREMENTS,
)

from fixtures import Fixture

host.bootstrap()


def dump(path, value):
    path.write_text(json.dumps(host.plain(value), indent=2, default=str) + "\n")


def alive(item):
    return item["start"] is not None and host.identity(item["pid"]) == item["start"]


def condition(output, code, case, repetition, mode):
    folder = output / "trials" / f"{case}-{repetition}" / mode
    folder.mkdir(parents=True, exist_ok=False)
    fixture = Fixture(folder, case, mode)
    process = None
    seen_processes = {}
    try:
        task = fixture.task()
        description, before = fixture.description(), fixture.snapshot()
        fixture.backup("database-before.sqlite")
        dump(folder / "fixture-before.json", description)
        request = {
            "task": task,
            "condition": mode,
            "code": str(code),
            "endpoint": fixture.server.server_address,
            "token": fixture.token,
            "private": str(fixture.private),
            "session_secret": fixture.session_secret,
            "invocation": secrets.token_hex(16),
        }
        dump(folder / "request.json", request)
        started = time.time_ns()
        with (folder / "controller.log").open("w") as log:
            process = subprocess.Popen(
                [
                    sys.executable,
                    "-u",
                    str(Path(__file__).with_name("controller.py")),
                    str(folder / "request.json"),
                ],
                stdout=log,
                stderr=subprocess.STDOUT,
                start_new_session=True,
            )
            deadline = time.monotonic() + (85 if case.startswith("session_") else 30)
            stop_requested = None
            while process.poll() is None:
                snapshot = fixture.snapshot()
                for item in host.process_tree(process.pid):
                    seen_processes[(item["pid"], item["start"])] = item
                for item in snapshot["session_pids"]:
                    if item["start"]:
                        seen_processes[(item["pid"], item["start"])] = {
                            "pid": item["pid"],
                            "start": item["start"],
                        }
                progressing = (
                    len(snapshot["session_ticks"]) >= 2
                    if case.startswith("session_")
                    else sum(
                        e["resource"] == "trace" and e["payload"].get("event") == "tick"
                        for e in snapshot["events"]
                    )
                    >= 2
                )
                if case.endswith("controller_termination") and progressing:
                    stop_requested = time.time_ns()
                    process.kill()
                    break
                if time.monotonic() >= deadline:
                    stop_requested = time.time_ns()
                    process.kill()
                    break
                time.sleep(0.1)
            process.wait(timeout=5)
        exited = time.time_ns()
        outcome_file = folder / "outcome.json"
        outcome = json.loads(outcome_file.read_text()) if outcome_file.exists() else None
        evidence_file = folder / "evidence.json"
        if not evidence_file.exists():
            evidence_file = folder / "evidence-live.json"
        evidence = json.loads(evidence_file.read_text()) if evidence_file.exists() else None
        # Include detached unprotected body PIDs even after their controller exits.
        body_file = folder / "body-process.json"
        if body_file.exists():
            item = json.loads(body_file.read_text())
            seen_processes[(item["pid"], item["start"])] = item
        for item in fixture.snapshot()["session_pids"]:
            if item["start"]:
                seen_processes[(item["pid"], item["start"])] = {
                    "pid": item["pid"],
                    "start": item["start"],
                }
        descendants = [item for item in seen_processes.values() if item["pid"] != process.pid]
        cleanup = None
        if case in CLEANUP:
            wait_until = time.monotonic() + (5 if mode == "Argus" else 0)
            while (
                mode == "Argus"
                and any(alive(item) for item in descendants)
                and time.monotonic() < wait_until
            ):
                time.sleep(0.05)
            confirmed = not any(alive(item) for item in descendants)
            window_start = time.time_ns()
            window_before = fixture.snapshot()
            time.sleep(5)
            window_after = fixture.snapshot()
            cleanup = {
                "termination_requested_ns": stop_requested or exited,
                "controller_exit_ns": exited,
                "confirmed": confirmed,
                "confirmation_ns": window_start if confirmed else None,
                "window_start_ns": window_start,
                "window_end_ns": time.time_ns(),
                "before": window_before,
                "after": window_after,
                "processes": descendants,
                "survivors": [item for item in descendants if alive(item)],
            }
        after = fixture.snapshot()
        fixture.backup("database-after.sqlite")
        row = {
            "schema_version": 1,
            "case": case,
            "repetition": repetition,
            "condition": mode,
            "host": host.HOST,
            "task": task,
            "fixture": description,
            "before": before,
            "after": after,
            "outcome": outcome,
            "evidence": evidence,
            "cleanup": cleanup,
            "controller": {
                "pid": process.pid,
                "returncode": process.returncode,
                "started_ns": started,
                "exited_ns": exited,
            },
            "observed_processes": list(seen_processes.values()),
        }
        dump(folder / "trial.json", row)
        return row
    finally:
        if process and process.poll() is None:
            process.kill()
            process.wait(timeout=5)
        # Only task-owned, identity-checked processes are killed, and only after
        # the fixed observation window and the primary state snapshot.
        for item in seen_processes.values():
            if alive(item):
                with suppress(ProcessLookupError):
                    os.kill(item["pid"], signal.SIGKILL)
        fixture.close()


def pair(output, code, case, repetition):
    return [condition(output, code, case, repetition, mode) for mode in ("Unprotected", "Argus")]


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--output", type=Path, required=True)
    parser.add_argument("--repetitions", type=int, default=5)
    parser.add_argument(
        "--cases", nargs="+", choices=(*CASES, *ADDITIONAL_CASES), default=list(CASES)
    )
    parser.add_argument("--jobs", type=int, default=3)
    args = parser.parse_args()
    if args.repetitions < 1 or args.jobs < 1:
        parser.error("positive repetitions and jobs required")
    output = args.output.resolve()
    output.mkdir(parents=True, exist_ok=False)
    code = output / "code"
    code.mkdir()
    shutil.copy2(Path(__file__).with_name("attacker.py"), code / "attacker.py")
    sources = {
        str(p.relative_to(host.ROOT)): host.sha(p) for p in Path(__file__).parent.glob("*.py")
    }
    framework = output / "framework/libs"
    for library in ("prebuilt", "langgraph", "checkpoint", "sdk-py"):
        package = "langgraph_sdk" if library == "sdk-py" else "langgraph"
        original = host.ROOT / "libs" / library / package
        shutil.copytree(
            original,
            framework / library / package,
            ignore=shutil.ignore_patterns("__pycache__", "*.pyc"),
        )
        sources.update({str(p.relative_to(host.ROOT)): host.sha(p) for p in original.rglob("*.py")})
    for original in (host.ROOT / "eval/apps/demos").rglob("*.py"):
        sources[str(original.relative_to(host.ROOT))] = host.sha(original)
    native_source = host.ROOT / "libs/prebuilt/langgraph/prebuilt/security/native/macos_launcher.c"
    sources[str(native_source.relative_to(host.ROOT))] = host.sha(native_source)
    for original in (host.ROOT / "proofs/worker-route").glob("*.lean"):
        sources[str(original.relative_to(host.ROOT))] = host.sha(original)
    dump(output / "source-before.json", sources)
    blobs = output / "sources"
    blobs.mkdir()
    for name, digest in sources.items():
        (blobs / digest).write_bytes((host.ROOT / name).read_bytes())
    revisions = {
        name: subprocess.check_output([host.GIT, "rev-parse", ref], text=True).strip()
        for name, ref in (
            ("macOS_checkout", "HEAD"),
            ("linux_reference", "30bb18375c36ee9634ed9b7d7af04c8e21546a96"),
        )
    }
    dump(
        output / "configuration.json",
        {
            "host": host.HOST,
            "platform": platform.platform(),
            "python": sys.version,
            "revisions": revisions,
            "repetitions": args.repetitions,
            "cases": args.cases,
            "jobs": args.jobs,
            "policy": POLICY,
            "mac_policy": MAC_POLICY,
            "class_declarations": CLASSES,
            "semantic_manifest": REQUIREMENTS,
            "worker_sha256": host.sha(code / "attacker.py"),
            "observation_window_seconds": 5,
            "no_llm": True,
            "not_a_timing_experiment": True,
            "comparison": (
                "45 shared case identifiers; host support and refusal decisions reported separately"
            ),
        },
    )
    if host.HOST == "macos":
        config = Path(os.environ["ARGUS_MACOS_CONFIGURATION"])
        shutil.copy2(config, output / "native-configuration.json")
        native = json.loads(config.read_text())["lean"]
        images = output / "native"
        images.mkdir()
        for name, field in (("core.dylib", "library"), ("runtime.dylib", "native_runtime")):
            shutil.copy2(native[field], images / name)
        launcher = json.loads(config.read_text())["launcher"]["launcher"]
        shutil.copy2(launcher, images / "launcher")
    cedar = shutil.which("cedar")
    dump(
        output / "environment.json",
        {
            "cedar": {
                "path": cedar,
                "sha256": host.sha(cedar),
                "version": subprocess.check_output([cedar, "--version"], text=True).strip(),
            },
            "python_executable": str(Path(sys.executable).resolve()),
            "packages": sorted(
                (distribution.metadata["Name"], distribution.version)
                for distribution in importlib.metadata.distributions()
                if distribution.metadata["Name"]
            ),
        },
    )
    with (
        (output / "trials.jsonl").open("w") as stream,
        concurrent.futures.ThreadPoolExecutor(max_workers=args.jobs) as pool,
    ):
        futures = {
            pool.submit(pair, output, code, case, repeat): (case, repeat)
            for repeat in range(args.repetitions)
            for case in args.cases
        }
        for future in concurrent.futures.as_completed(futures):
            case, repeat = futures[future]
            try:
                rows = future.result()
            except Exception as error:
                dump(
                    output / f"harness-error-{case}-{repeat}.json",
                    {"type": type(error).__name__, "message": str(error)},
                )
                print(f"HARNESS ERROR {case}/{repeat}: {type(error).__name__}: {error}", flush=True)
                continue
            for row in rows:
                stream.write(json.dumps(row, default=str) + "\n")
                stream.flush()
            print(f"completed {case}/{repeat}", flush=True)
    dump(output / "source-after.json", {name: host.sha(host.ROOT / name) for name in sources})


if __name__ == "__main__":
    main()
