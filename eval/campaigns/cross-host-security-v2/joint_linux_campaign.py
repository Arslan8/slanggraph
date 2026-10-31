"""One gated Docker campaign: matched security, route costs, and Pandas utility."""

import argparse
import hashlib
import json
import os
import platform
import subprocess
import sys
import time
from pathlib import Path

HERE = Path(__file__).resolve().parent
ROOT = HERE.parents[2]


def dump(path, value):
    path.write_text(json.dumps(value, indent=2) + "\n")


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--output", type=Path, required=True)
    parser.add_argument("--wait-for-macos-source-after", type=Path)
    parser.add_argument(
        "--stages",
        nargs="+",
        choices=("security", "microbenchmarks", "pandas"),
        default=("security", "microbenchmarks", "pandas"),
    )
    args = parser.parse_args()
    if sys.platform != "linux":
        parser.error("run inside the configured Linux Docker harness")
    out = args.output.resolve()
    out.mkdir(parents=True, exist_ok=False)
    revision = subprocess.check_output(["git", "rev-parse", "HEAD"], cwd=ROOT, text=True).strip()
    source_files = [
        *HERE.glob("*.py"),
        *(HERE / "microbenchmarks").glob("*.py"),
        ROOT / "eval/apps/pandas/closed_campaign.py",
    ]
    for library in ("prebuilt", "langgraph", "checkpoint", "sdk-py"):
        package = "langgraph_sdk" if library == "sdk-py" else "langgraph"
        source_files.extend((ROOT / "libs" / library / package).rglob("*.py"))
    before = {
        str(p.relative_to(ROOT)): hashlib.sha256(p.read_bytes()).hexdigest() for p in source_files
    }
    dump(out / "source-before.json", before)
    probe = subprocess.run(
        [
            "bwrap",
            "--unshare-all",
            "--die-with-parent",
            "--ro-bind",
            "/",
            "/",
            "--proc",
            "/proc",
            "--dev",
            "/dev",
            "/bin/true",
        ],
        capture_output=True,
        text=True,
    )
    dump(
        out / "harness.json",
        {
            "revision": revision,
            "platform": platform.platform(),
            "kernel": platform.release(),
            "outer_process_status": Path("/proc/self/status").read_text(),
            "outer_apparmor": Path("/proc/self/attr/current").read_text(),
            "bubblewrap": {
                "returncode": probe.returncode,
                "stdout": probe.stdout,
                "stderr": probe.stderr,
            },
            "docker_info": subprocess.run(
                ["docker", "info", "--format", "{{json .}}"], capture_output=True, text=True
            ).stdout,
            "stages": args.stages,
        },
    )
    if probe.returncode:
        raise SystemExit("bubblewrap activation failed; no protected timing runs admitted")
    native = json.loads(Path(os.environ["ARGUS_EVAL_NATIVE_MANIFEST"]).read_text())
    env = dict(os.environ)
    env.update(
        {
            "ARGUS_EVAL_LEAN_BINARY": native["library"],
            "ARGUS_EVAL_LEAN_SHA256": native["sha256"],
            "ARGUS_EVAL_LEAN_RUNTIME": native["native_runtime"],
            "ARGUS_EVAL_LEAN_RUNTIME_SHA256": native["native_runtime_sha256"],
        }
    )
    manifest = json.loads((ROOT / "eval/apps/pandas/policy/manifest-v22-full.json").read_text())
    manifest["lean_worker"].update(
        binary=native["library"],
        sha256=native["sha256"],
        runtime=native["native_runtime"],
        runtime_sha256=native["native_runtime_sha256"],
    )
    dump(out / "pandas-runtime-manifest.json", manifest)
    ledger = []

    def stage(name, command):
        started = time.time_ns()
        with (out / f"{name}.log").open("w") as log:
            process = subprocess.run(
                command, cwd=ROOT, env=env, stdout=log, stderr=subprocess.STDOUT
            )
        ledger.append(
            {
                "name": name,
                "command": command,
                "started_ns": started,
                "ended_ns": time.time_ns(),
                "returncode": process.returncode,
            }
        )
        dump(out / "stage-ledger.json", ledger)
        print(name, process.returncode, flush=True)
        return process.returncode

    if "security" in args.stages:
        stage("security", [sys.executable, str(HERE / "run.py"), "--output", str(out / "security")])
        stage(
            "security-verification",
            [sys.executable, str(HERE / "verify.py"), str(out / "security")],
        )
        stage(
            "security-ledger",
            [
                sys.executable,
                str(HERE / "regenerate_ledger.py"),
                str(out / "security"),
                "--output",
                str(out / "security-attempt-ledger.jsonl"),
            ],
        )
    if "microbenchmarks" in args.stages:
        if args.wait_for_macos_source_after:
            deadline = time.monotonic() + 7200
            while not args.wait_for_macos_source_after.exists():
                if time.monotonic() > deadline:
                    raise TimeoutError("macOS security run did not finish before timing stages")
                time.sleep(5)
        for route in ("landlock", "container", "broker"):
            stage(
                f"micro-{route}",
                [
                    sys.executable,
                    str(HERE / "microbenchmarks" / f"run_{route}_costs.py"),
                    "--output",
                    str(out / "microbenchmarks" / route),
                ],
            )
    if "pandas" in args.stages:
        stage(
            "pandas",
            [
                sys.executable,
                str(ROOT / "eval/apps/pandas/closed_campaign.py"),
                "--output",
                str(out / "pandas"),
                "--configuration",
                "matched",
                "--repetitions",
                "5",
                "--runtime-manifest",
                str(out / "pandas-runtime-manifest.json"),
            ],
        )
    after = {name: hashlib.sha256((ROOT / name).read_bytes()).hexdigest() for name in before}
    dump(out / "source-after.json", after)
    dump(
        out / "completion.json",
        {
            "all_requested_stages_attempted": len(ledger)
            == (3 if "security" in args.stages else 0)
            + (3 if "microbenchmarks" in args.stages else 0)
            + (1 if "pandas" in args.stages else 0),
            "source_stable": before == after,
            "revision": revision,
            "stage_failures": [item["name"] for item in ledger if item["returncode"]],
        },
    )


if __name__ == "__main__":
    main()
