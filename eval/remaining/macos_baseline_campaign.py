"""Run the frozen ordinary-demo and Pandas baseline conditions on macOS.

Reuses existing task commands, application sources and correctness oracles.
Only host setup/protected-only campaign preflights are bypassed; no protected
trial is manufactured. CPU affinity is uncontrolled and recorded explicitly.
"""

from __future__ import annotations

import argparse
import hashlib
import importlib.metadata
import importlib.util
import json
import os
import platform
import random
import shutil
import subprocess
import sys
import time
import urllib.request
from collections import Counter
from datetime import UTC, datetime
from pathlib import Path

ROOT = Path(__file__).resolve().parents[2]
DEMO_ROOT = ROOT / "eval/campaigns/langgraph-demos-v3"
PANDAS_ROOT = ROOT / "eval/apps/pandas"
MODEL_DIGEST = "500a1f067a9f782620b40bee6f7b0c89e17ae61f686b92c24933e4ca4b2b8b41"
GIT = "/Library/Developer/CommandLineTools/usr/bin/git"


def load(name, path):
    spec = importlib.util.spec_from_file_location(name, path)
    module = importlib.util.module_from_spec(spec)
    sys.modules[name] = module
    spec.loader.exec_module(module)
    return module


def dump(path, value):
    path.write_text(json.dumps(value, indent=2, sort_keys=True) + "\n")


def sha(path):
    return hashlib.sha256(path.read_bytes()).hexdigest()


def jobs(demos, repetitions, pilot):
    for repetition in range(repetitions):
        block = [
            demos.Job(app, task, repetition, mode)
            for app in (*demos.OLD_DEMOS, *demos.NEW_DEMOS)
            for task in ((1,) if app in demos.OLD_DEMOS or pilot else range(1, 6))
            for mode in demos.MODES
        ]
        random.Random(demos.SEED + repetition).shuffle(block)
        yield from (job for job in block if job.mode == "Baseline")


def sources(upstream):
    paths = {
        Path(__file__),
        DEMO_ROOT / "run_campaign.py",
        ROOT / "eval/tests/test_macos_baseline.py",
    }
    for folder in (
        ROOT / "eval/apps/demos",
        PANDAS_ROOT,
        ROOT / "eval/remaining",
        upstream / "ai_data_science_team",
    ):
        paths.update(folder.rglob("*.py"))
    paths.add(PANDAS_ROOT / "policy/manifest-v22-full.json")
    v1 = ROOT / "eval/campaigns/langgraph-demos-v1"
    paths.add(v1 / "tasks.json")
    paths.add(v1 / "upstream/docs/docs/tutorials/customer-support/customer-support.ipynb")
    paths.update(p for p in (v1 / "fixtures").rglob("*") if p.is_file())
    for library in ("prebuilt", "langgraph", "checkpoint", "sdk-py"):
        paths.update((ROOT / "libs" / library / "langgraph").rglob("*.py"))
    return {str(p.relative_to(ROOT)): sha(p) for p in sorted(paths)}


def pandas_trial(output, upstream, framework, module, manifest, task, repetition):
    case, prompt, expected = task
    folder = output / "pandas" / f"rep-{repetition}" / case
    folder.mkdir(parents=True)
    fixture = module.write_fixture(folder / "fixture")
    if sha(fixture) != manifest["dataset"]["sha256"]:
        raise ValueError("Pandas fixture differs from the frozen dataset")
    request = dict(
        app="pandas",
        task=prompt,
        model=manifest["model"],
        fixture_root=str(fixture.parent),
        output=str(folder / "output.json"),
        events=str(folder / "events.jsonl"),
        configuration="Baseline",
        reader_label="Baseline",
        integration=True,
        slanggraph_root=str(framework),
        run_id=f"{case}-Baseline-{repetition}",
        principal_policy=manifest["principal_policy"],
        operator_policy=manifest["operator_policy"],
        sandbox_serialization=manifest["sandbox_serialization"],
        workflow_contract=manifest["workflow_contract"],
        computation_api=manifest["computation_api"],
        graph_retries=manifest["graph_retries"],
        lean_worker=None,
        dataset=dict(
            path=str(fixture.resolve()),
            sha256=manifest["dataset"]["sha256"],
            max_bytes=manifest["dataset"]["max_bytes"],
        ),
        trusted_declarations=manifest["trusted_declarations"],
        state_normalization=manifest.get("state_normalization"),
    )
    dump(folder / "request.json", request)
    command = [
        sys.executable,
        str(output / "harness/pandas/backend_closed.py"),
        str(folder / "request.json"),
    ]
    started = time.perf_counter_ns()
    with (folder / "process.log").open("w") as log:
        try:
            completed = subprocess.run(
                command,
                cwd=upstream,
                stdout=log,
                stderr=subprocess.STDOUT,
                timeout=180,
                check=False,
            )
            code = completed.returncode
            status = "completed" if code == 0 else "error"
        except subprocess.TimeoutExpired:
            code, status = None, "timeout"
    wall_ms = (time.perf_counter_ns() - started) / 1e6
    result = (
        json.loads((folder / "output.json").read_text())
        if (folder / "output.json").exists()
        else {}
    )
    evidence_path = folder / "baseline-security-evidence.json"
    evidence = json.loads(evidence_path.read_text()) if evidence_path.exists() else None
    forbidden = any(
        (folder / name).exists()
        for name in ("security.sqlite", "activation-receipts.json", "closed-inventory.json")
    )
    oracle_match = module.oracle(result, expected, case == "monthly_chart")
    row = dict(
        application="Pandas",
        case_id=case,
        repetition=repetition,
        mode="Baseline",
        status=status,
        returncode=code,
        wall_ms=wall_ms,
        analysis_wall_ms=180_000.0 if status == "timeout" else wall_ms,
        correct=status == "completed"
        and oracle_match
        and evidence is not None
        and not any(evidence.values())
        and not forbidden,
        output_matches_oracle=oracle_match,
        baseline_security_evidence=evidence,
        security_evidence=forbidden,
        command=command,
        fixture_sha256=sha(fixture),
        trial=str(folder.relative_to(output)),
    )
    dump(folder / "trial.json", row)
    return row


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--output", type=Path, required=True)
    parser.add_argument("--upstream", type=Path, default=ROOT / "eval/vendor/ai-data-science-team")
    parser.add_argument("--repetitions", type=int, default=5)
    parser.add_argument("--pilot", action="store_true", help="first task per app, one repetition")
    parser.add_argument("--only", choices=("demos", "pandas", "all"), default="all")
    args = parser.parse_args()
    if args.repetitions < 1:
        parser.error("repetitions must be positive")
    output = args.output.resolve()
    output.relative_to(ROOT)  # Existing demo runner records repository-relative output paths.
    output.mkdir(parents=True, exist_ok=False)
    upstream = args.upstream.resolve()
    tags = json.load(urllib.request.urlopen("http://127.0.0.1:11434/api/tags", timeout=10))
    if not any(m["name"] == "qwen3:8b" and m["digest"] == MODEL_DIGEST for m in tags["models"]):
        raise RuntimeError("Pinned model is not served")
    dump(output / "models.json", tags)
    reference = json.loads(
        (DEMO_ROOT / "raw/parity-matched-20261029/configuration.json").read_text()
    )
    for name, digest in reference["fixture_digests"].items():
        if not (ROOT / name).is_file() or sha(ROOT / name) != digest:
            raise RuntimeError(f"Missing or changed frozen demo fixture: {name}")
    if sha(ROOT / "eval/campaigns/langgraph-demos-v1/tasks.json") != reference["task_digest"]:
        raise RuntimeError("Frozen demo task definitions changed")
    upstream_revision = subprocess.check_output(
        [GIT, "rev-parse", "HEAD"], cwd=upstream, text=True
    ).strip()
    if upstream_revision != "4ffeb7f38178aa250917f29b01355f8b89ba809e":
        raise RuntimeError("Pandas upstream checkout differs from the frozen pin")
    dump(
        output / "fixture-preflight.json",
        dict(
            task_digest=reference["task_digest"],
            fixture_digests=reference["fixture_digests"],
            upstream_revision=upstream_revision,
        ),
    )
    dump(
        output / "model-runtime.json",
        json.load(urllib.request.urlopen("http://127.0.0.1:11434/api/ps", timeout=10)),
    )
    before = sources(upstream)
    dump(output / "source-before.json", before)
    blobs = output / "sources"
    blobs.mkdir()
    for name, digest in before.items():
        (blobs / digest).write_bytes((ROOT / name).read_bytes())
    demos = load("ordinary_baseline_campaign", DEMO_ROOT / "run_campaign.py")
    pandas = load("pandas_baseline_campaign", PANDAS_ROOT / "closed_campaign.py")
    manifest = json.loads((PANDAS_ROOT / "policy/manifest-v22-full.json").read_text())
    framework = pandas.campaign.freeze_framework(output)
    harness = output / "harness"
    shutil.copytree(
        ROOT / "eval/apps/demos",
        harness / "demos",
        ignore=shutil.ignore_patterns("__pycache__", "*.pyc"),
    )
    shutil.copytree(
        PANDAS_ROOT, harness / "pandas", ignore=shutil.ignore_patterns("__pycache__", "*.pyc")
    )
    shutil.copy2(DEMO_ROOT / "run_campaign.py", harness / "demo_campaign.py")
    shutil.copy2(
        ROOT / "eval/remaining/application_campaign.py", harness / "application_campaign.py"
    )
    shutil.copy2(PANDAS_ROOT / "policy/manifest-v22-full.json", harness / "pandas-manifest.json")
    demos.APPS = harness / "demos"
    os.environ["PYTHONPATH"] = os.pathsep.join(
        str(framework / "libs" / lib) for lib in ("prebuilt", "langgraph", "checkpoint")
    )
    os.environ.update(OPENBLAS_NUM_THREADS="1", OMP_NUM_THREADS="1", MPLBACKEND="Agg")
    repetitions = 1 if args.pilot else args.repetitions
    dump(
        output / "configuration.json",
        dict(
            scope="baseline only; no protected application trial or cross-OS performance claim",
            only=args.only,
            repetitions=repetitions,
            pilot=args.pilot,
            expected_demo_trials=(15 if args.pilot else 35) * repetitions
            if args.only != "pandas"
            else 0,
            expected_pandas_trials=(1 if args.pilot else 10) * repetitions
            if args.only != "demos"
            else 0,
            model_digest=MODEL_DIGEST,
            primary_timer="parent subprocess wall time including startup/shutdown",
            demo_shuffle_seed=20261028,
            pandas_shuffle_seed=20261026,
            demo_timeouts_seconds=[180, 300],
            pandas_timeout_seconds=180,
            setup_excluded=True,
            cpu_affinity="uncontrolled; no taskset on macOS",
            framework_revision=subprocess.check_output(
                [GIT, "rev-parse", "HEAD"], text=True
            ).strip(),
            upstream_revision=subprocess.check_output(
                [GIT, "rev-parse", "HEAD"], cwd=upstream, text=True
            ).strip(),
            platform=platform.platform(),
            python=sys.version,
            started_utc=datetime.now(UTC).isoformat(),
            packages=sorted(
                (d.metadata["Name"], d.version) for d in importlib.metadata.distributions()
            ),
            ollama=json.load(
                urllib.request.urlopen("http://127.0.0.1:11434/api/version", timeout=10)
            ),
        ),
    )
    warmup = urllib.request.Request(
        "http://127.0.0.1:11434/v1/chat/completions",
        data=json.dumps(
            dict(
                model="qwen3:8b",
                messages=[dict(role="user", content="Reply only: ready")],
                temperature=0,
                seed=20261005,
                max_tokens=8,
                stream=False,
            )
        ).encode(),
        headers={"Content-Type": "application/json"},
    )
    started = time.perf_counter_ns()
    with urllib.request.urlopen(warmup, timeout=180) as response:
        value = json.load(response)
    dump(
        output / "warmup.json",
        dict(elapsed_ms=(time.perf_counter_ns() - started) / 1e6, response=value),
    )
    records = []
    with (output / "trials.jsonl").open("x") as stream:
        if args.only != "pandas":
            tasks = json.loads((demos.V1 / "tasks.json").read_text())
            for job in jobs(demos, repetitions, args.pilot):
                row = demos.execute(job, output / "demos", tasks)
                records.append(row)
                stream.write(json.dumps(row) + "\n")
                stream.flush()
                print(
                    f"{job.repetition} {job.application}/{job.task}: "
                    f"{row['status']} correct={row['correct']}",
                    flush=True,
                )
        if args.only != "demos":
            for repetition in range(repetitions):
                selected = [pandas.TASKS[5]] if args.pilot else list(pandas.TASKS)
                paired = [(mode, task) for mode in ("Baseline", "slangGraph") for task in selected]
                random.Random(20261026 + repetition).shuffle(paired)
                for mode, task in paired:
                    if mode != "Baseline":
                        continue
                    row = pandas_trial(
                        output, upstream, framework, pandas, manifest, task, repetition
                    )
                    records.append(row)
                    stream.write(json.dumps(row) + "\n")
                    stream.flush()
                    print(
                        f"{repetition} Pandas/{task[0]}: {row['status']} correct={row['correct']}",
                        flush=True,
                    )
    after = sources(upstream)
    dump(output / "source-after.json", after)
    summary = dict(
        total=len(records),
        correct=sum(row["correct"] for row in records),
        status=dict(Counter(row["status"] for row in records)),
        source_unchanged=before == after,
    )
    dump(output / "summary.json", summary)
    print(json.dumps(summary), flush=True)


if __name__ == "__main__":
    main()
