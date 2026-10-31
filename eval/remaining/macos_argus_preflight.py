"""Exercise unchanged protected entry points; report readiness, not utility scores."""

from __future__ import annotations

import argparse
import hashlib
import importlib.util
import json
import os
import platform
import shutil
import subprocess
import sys
import urllib.request
from datetime import UTC, datetime
from pathlib import Path

ROOT = Path(__file__).resolve().parents[2]


def load(name, path):
    spec = importlib.util.spec_from_file_location(name, path)
    module = importlib.util.module_from_spec(spec)
    sys.modules[name] = module
    spec.loader.exec_module(module)
    return module


def dump(path, value):
    path.write_text(json.dumps(value, indent=2) + "\n")


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--output", type=Path, required=True)
    args = parser.parse_args()
    if sys.platform != "darwin":
        parser.error("this readiness probe is for macOS")
    tags = json.load(urllib.request.urlopen("http://127.0.0.1:11434/api/tags", timeout=10))
    expected_digest = "500a1f067a9f782620b40bee6f7b0c89e17ae61f686b92c24933e4ca4b2b8b41"
    if not any(
        item["name"] == "qwen3:8b" and item["digest"] == expected_digest for item in tags["models"]
    ):
        raise RuntimeError("Pinned model is not served")
    output = args.output.resolve()
    output.relative_to(ROOT)
    output.mkdir(parents=True, exist_ok=False)
    dump(output / "models.json", tags)
    os.environ["PYTHONPATH"] = os.pathsep.join(
        str(ROOT / "libs" / library) for library in ("prebuilt", "langgraph", "checkpoint")
    )
    os.environ.update(OPENBLAS_NUM_THREADS="1", OMP_NUM_THREADS="1", MPLBACKEND="Agg")
    runner_path = ROOT / "eval/campaigns/langgraph-demos-v3/run_campaign.py"
    runner = load("argus_demo_readiness", runner_path)
    tasks = json.loads((runner.V1 / "tasks.json").read_text())
    sources = [
        runner_path,
        Path(__file__).resolve(),
        *(ROOT / "eval/apps/demos").glob("*.py"),
        *(ROOT / "eval/apps/pandas").glob("*.py"),
        *(ROOT / "libs/prebuilt/langgraph/prebuilt/security").glob("*.py"),
        ROOT / "eval/apps/pandas/policy/manifest-v22-full.json",
    ]

    def source_hashes():
        return {
            str(path.relative_to(ROOT)): hashlib.sha256(path.read_bytes()).hexdigest()
            for path in sorted(sources)
        }

    before = source_hashes()
    dump(output / "source-before.json", before)
    dump(
        output / "configuration.json",
        dict(
            scope="protected startup probes; not the 175+50 application evaluation",
            started_utc=datetime.now(UTC).isoformat(),
            platform=platform.platform(),
            python=sys.version,
            worker_route=str(runner.WORKER),
            worker_route_exists=runner.WORKER.is_file(),
            executables={name: shutil.which(name) for name in ("cedar", "bwrap", "lake")},
            environment={
                name: os.environ[name]
                for name in ("PYTHONPATH", "OPENBLAS_NUM_THREADS", "OMP_NUM_THREADS", "MPLBACKEND")
            },
            model_service_available=True,
            cpu_limit_deferral="unchanged; no other protection disabled",
        ),
    )
    records = []
    for application in (*runner.NEW_DEMOS, *runner.OLD_DEMOS):
        row = runner.execute(runner.Job(application, 1, 0, "Argus"), output / "demos", tasks)
        records.append(row)
        print(f"{application}: {row['status']}", flush=True)
    dump(output / "demo-startup-probes.json", records)
    pandas_command = [
        sys.executable,
        str(ROOT / "eval/apps/pandas/closed_campaign.py"),
        "--output",
        str(output / "pandas"),
        "--pilot",
        "--configuration",
        "C-full-lean",
    ]
    completed = subprocess.run(
        pandas_command, cwd=ROOT, capture_output=True, text=True, timeout=60, check=False
    )
    pandas = dict(
        command=pandas_command,
        returncode=completed.returncode,
        stdout=completed.stdout,
        stderr=completed.stderr,
    )
    dump(output / "pandas-campaign-preflight.json", pandas)
    # Probe the loader's host requirement independently of missing build artifacts.
    loader = subprocess.run(
        [
            sys.executable,
            "-c",
            ("from langgraph.prebuilt.security.lean_lifecycle import _memfd; _memfd()"),
        ],
        cwd=ROOT,
        capture_output=True,
        text=True,
        timeout=30,
        check=False,
    )
    dump(
        output / "lean-loader-probe.json",
        dict(
            returncode=loader.returncode,
            stdout=loader.stdout,
            stderr=loader.stderr,
        ),
    )
    after = source_hashes()
    dump(output / "source-after.json", after)
    summary = dict(
        demo_entry_points_attempted=len(records),
        demo_completed=sum(row["status"] == "completed" for row in records),
        demo_security_evidence=sum(row["security_evidence"] for row in records),
        pandas_campaign_preflight_returncode=completed.returncode,
        lean_loader_probe_returncode=loader.returncode,
        source_unchanged=before == after,
        utility_evaluation="not started; inspect startup failures before expanding repetitions",
    )
    dump(output / "summary.json", summary)
    print(json.dumps(summary), flush=True)


if __name__ == "__main__":
    main()
