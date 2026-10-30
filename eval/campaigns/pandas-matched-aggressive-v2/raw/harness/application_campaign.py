"""Frozen ten-task Pandas full-workflow cohort using the existing native graph adapter."""

import argparse
import csv
import hashlib
import json
import math
import os
import random
import shutil
import subprocess
import time
import urllib.request
from datetime import UTC, datetime
from pathlib import Path

ROOT = Path(__file__).resolve().parents[2]
UPSTREAM = Path("/data/slanggraph-eval-upstreams/ai-data-science-team")
ROWS = [
    ["2026-01-05", "North", "A", 100],
    ["2026-01-10", "South", "B", 60],
    ["2026-02-05", "North", "A", 80],
    ["2026-02-12", "South", "B", 40],
    ["2026-03-01", "North", "A", 20],
    ["2026-03-08", "South", "B", 100],
    ["2026-01-05", "North", "A", 100],
    ["2026-04-01", "South", "B", None],
]
TASKS = [
    (
        "monthly_total",
        (
            "Return a table of monthly sales totals, with month form"
            "atted YYYY-MM and total sales. Include all months."
        ),
        [["2026-01", 260], ["2026-02", 120], ["2026-03", 120], ["2026-04", 0]],
    ),
    (
        "monthly_mean",
        (
            "Return a table of monthly mean sales, with month format"
            "ted YYYY-MM and mean sales. Include months with only mi"
            "ssing sales as null."
        ),
        [["2026-01", 260 / 3], ["2026-02", 60], ["2026-03", 60], ["2026-04", None]],
    ),
    (
        "regional_totals",
        "Return exactly region and total sales, summed by region.",
        [["North", 300], ["South", 200]],
    ),
    (
        "product_totals",
        "Return exactly product and total sales, summed by product.",
        [["A", 300], ["B", 200]],
    ),
    (
        "top_products",
        "Return the single top product by total sales, with product and total sales.",
        [["A", 300]],
    ),
    (
        "date_filtered_total",
        (
            "Filter dates from 2026-02-01 through 2026-02-28 inclusi"
            "ve and return a table containing only the total sales."
        ),
        [[120]],
    ),
    (
        "grouped_mean",
        "Return exactly region and mean sales, grouped by region, ignoring missing sales.",
        [["North", 75], ["South", 200 / 3]],
    ),
    (
        "missing_count",
        "Return a one-cell table counting missing values in the sales column.",
        [[1]],
    ),
    (
        "duplicate_count",
        "Return a one-cell table counting duplicate rows, keeping the first occurrence.",
        [[1]],
    ),
    (
        "monthly_chart",
        "Produce a bar chart of total sales by month. Format month as YYYY-MM. Include all months.",
        [["2026-01", 260], ["2026-02", 120], ["2026-03", 120], ["2026-04", 0]],
    ),
]


def dump(path, data):
    path.write_text(json.dumps(data, indent=2, default=str) + "\n")


def capture_framework(output, source_root=None):
    """Retain exact source bytes and identities before each prospective trial."""
    identities = {}
    source_root = ROOT if source_root is None else source_root
    blobs = output / "framework-source-blobs"
    blobs.mkdir(exist_ok=True)
    for library in ["prebuilt", "langgraph", "checkpoint"]:
        for path in sorted((source_root / "libs" / library / "langgraph").rglob("*.py")):
            source = path.read_bytes()
            digest = hashlib.sha256(source).hexdigest()
            identities[str(path.relative_to(source_root))] = digest
            target = blobs / digest
            if not target.exists():
                target.write_bytes(source)
    return identities


def freeze_framework(output):
    """Give the cohort its own package sources, independent of later repo edits."""
    destination = output / "framework"
    for library in ["prebuilt", "langgraph", "checkpoint"]:
        shutil.copytree(
            ROOT / "libs" / library / "langgraph",
            destination / "libs" / library / "langgraph",
            ignore=shutil.ignore_patterns("__pycache__", "*.pyc"),
        )
    return destination


def identity_digest(identities):
    return hashlib.sha256(json.dumps(identities, sort_keys=True).encode()).hexdigest()


def capture_lean_worker(output, binary, expected_digest):
    """Copy pinned executable bytes for this new cohort, without claiming a proof."""
    if binary is None and expected_digest is None:
        return None
    if binary is None or expected_digest is None:
        raise ValueError("Select both the Lean worker binary and its SHA-256")
    if (
        type(expected_digest) is not str
        or len(expected_digest) != 64
        or any(character not in "0123456789abcdef" for character in expected_digest)
    ):
        raise ValueError("The selected Lean worker digest must be lowercase SHA-256")
    data = binary.read_bytes()
    if not data or hashlib.sha256(data).hexdigest() != expected_digest:
        raise ValueError("The selected Lean worker bytes do not match the pin")
    target = output / "workerRoute"
    with target.open("xb") as stream:
        stream.write(data)
    target.chmod(0o500)
    return {
        "binary": str(target.resolve()),
        "sha256": expected_digest,
        "protocol": "worker-route-grant-v3",
    }


def oracle(output, expected, chart):
    if not isinstance(output, dict):
        return False
    if chart:
        plot = output.get("plot")
        if isinstance(plot, str):
            try:
                plot = json.loads(plot)
            except ValueError:
                return False
        if not isinstance(plot, dict):
            return False
        if not isinstance(plot.get("data"), list):
            return False
        actual = []
        for series in plot.get("data", []):
            if not isinstance(series, dict):
                return False
            x, y = series.get("x", []), series.get("y", [])
            if not isinstance(x, list) or not isinstance(y, list):
                return False
            if len(x) != len(y):
                return False
            actual.extend([[str(a)[:7], b] for a, b in zip(x, y, strict=True)])
    else:
        table = output.get("table")
        if not isinstance(table, list):
            return False
        if any(not isinstance(row, dict) for row in table):
            return False
        actual = [list(row.values()) for row in table]

    def normalized(rows):
        return sorted(
            [
                sorted(
                    "null"
                    if v is None or (isinstance(v, float) and math.isnan(v))
                    else f"{float(v):.4f}"
                    if isinstance(v, int | float)
                    else str(v)
                    for v in row
                )
                for row in rows
            ]
        )

    return normalized(actual) == normalized(expected)


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--output", type=Path, required=True)
    parser.add_argument("--repetitions", type=int, default=5)
    parser.add_argument(
        "--graph-retries",
        type=int,
        default=3,
        help="Bounded upstream code-repair attempts; every attempt stays in events.jsonl.",
    )
    parser.add_argument("--pilot", action="store_true")
    parser.add_argument("--lean-worker-binary", type=Path)
    parser.add_argument("--lean-worker-sha256")
    parser.add_argument(
        "--live-framework",
        action="store_true",
        help="Development only: execute live checkout sources instead of a cohort snapshot.",
    )
    parser.add_argument(
        "--workflow-contract",
        choices=[
            "original",
            "preserve-request-v1",
            "preserve-request-v2",
            "preserve-request-v3",
            "preserve-request-v4",
            "preserve-request-v5",
        ],
        default="preserve-request-v5",
    )
    parser.add_argument(
        "--sandbox-serialization",
        choices=["original", "recursive-json-v1", "recursive-json-v2"],
        default="recursive-json-v2",
        help="New cohorts use the shared serializer repair; original reproduces the old adapter.",
    )
    args = parser.parse_args()
    if args.graph_retries < 0 or args.repetitions < 1:
        parser.error("graph retries must be nonnegative and repetitions positive")
    out = args.output.resolve()
    out.mkdir(parents=True, exist_ok=False)
    lean_worker = capture_lean_worker(out, args.lean_worker_binary, args.lean_worker_sha256)
    tasks = [TASKS[5]] if args.pilot else TASKS
    serialization = None if args.sandbox_serialization == "original" else args.sandbox_serialization
    manifest_version = 9 if serialization is None else 10
    workflow_contract = None if args.workflow_contract == "original" else args.workflow_contract
    if workflow_contract:
        if serialization is None:
            parser.error("The request-preserving workflow requires recursive JSON serialization")
        manifest_version = 12 if workflow_contract == "preserve-request-v2" else 11
        if manifest_version == 12 and not args.live_framework:
            manifest_version = 13
        if workflow_contract == "preserve-request-v3":
            manifest_version = 15 if args.graph_retries else 14
        if serialization == "recursive-json-v2":
            manifest_version = 16
        if workflow_contract == "preserve-request-v4":
            if serialization != "recursive-json-v2":
                parser.error("The v4 workflow requires recursive-json-v2 serialization")
            manifest_version = 17
    computation_api = (
        "period-aggregation-v1" if workflow_contract == "preserve-request-v5" else None
    )
    if computation_api:
        if serialization != "recursive-json-v2":
            parser.error("The v5 workflow requires recursive-json-v2 serialization")
        manifest_version = 19
    manifest = json.loads(
        (ROOT / f"eval/apps/pandas/policy/manifest-v{manifest_version}.json").read_text()
    )
    tags = json.load(urllib.request.urlopen("http://127.0.0.1:11434/api/tags", timeout=10))
    assert any(
        m["name"] == manifest["model"]["name"] and m["digest"] == manifest["model"]["digest"]
        for m in tags["models"]
    )
    dump(out / "models.json", tags)
    snapshot = out / "harness"
    shutil.copytree(ROOT / "eval/apps/pandas", snapshot / "pandas")
    backend = (ROOT / "eval/apps/backend.py").read_text()
    # A common adaptation across A/B/C: timestamped callbacks. The declared
    # retry budget is passed to the real upstream graph, never hidden reruns.
    backend = backend.replace("import sys\n", "import sys\nimport time\n")
    backend = backend.replace(
        '"kind": "model_start",', '"kind": "model_start", "monotonic": time.perf_counter(),'
    )
    backend = backend.replace(
        '"kind": "model_end",', '"kind": "model_end", "monotonic": time.perf_counter(),'
    )
    (snapshot / "backend.py").write_text(backend)
    (snapshot / "application_campaign.py").write_bytes(Path(__file__).read_bytes())
    sources = {
        str(p.relative_to(snapshot)): hashlib.sha256(p.read_bytes()).hexdigest()
        for p in snapshot.rglob("*.py")
    }
    framework_runtime_root = ROOT if args.live_framework else freeze_framework(out)
    framework_sources = capture_framework(out, framework_runtime_root)
    dump(out / "framework-sources.json", framework_sources)
    framework_digest = identity_digest(framework_sources)
    dump(
        out / "plan.json",
        dict(
            tasks=tasks,
            fixture=ROWS,
            conditions=["A", "B", "C"],
            repetitions=args.repetitions,
            model=manifest["model"],
            graph_retries=args.graph_retries,
            sandbox_serialization=serialization,
            workflow_contract=workflow_contract,
            computation_api=computation_api,
            manifest_version=manifest_version,
            lean_worker=lean_worker,
            lean_worker_configuration="C" if lean_worker else None,
            timeout_s=180,
            seed=20261026,
            timer="subprocess wall time including graph/model/authorization/audit; setup separate",
            sources=sources,
            framework_sources_sha256=framework_digest,
            framework_runtime_root=str(framework_runtime_root),
            frozen_framework=not args.live_framework,
            host_load="uncontrolled shared host",
            upstream_revision=subprocess.check_output(
                ["git", "rev-parse", "HEAD"], cwd=UPSTREAM, text=True
            ).strip(),
        ),
    )
    trials = out / "trials.jsonl"
    for repetition in range(args.repetitions):
        jobs = [(task, mode) for task in tasks for mode in ["A", "B", "C"]]
        random.Random(20261026 + repetition).shuffle(jobs)
        for (case, prompt, expected), mode in jobs:
            run_id = f"{case}-{mode}-{repetition}"
            folder = out / run_id
            folder.mkdir()
            fixture = folder / "fixture"
            fixture.mkdir()
            (fixture / "outputs").mkdir()
            with (fixture / "sales.csv").open("w") as stream:
                writer = csv.writer(stream)
                writer.writerow(["date", "region", "product", "sales"])
                writer.writerows(ROWS)
            template = (ROOT / "eval/apps/pandas/policy/compute-v3.slp.template").read_text()
            for key, value in dict(
                DATASET=str(fixture / "sales.csv"),
                OUTPUT=str(fixture / "outputs"),
                PACKAGES=str(UPSTREAM / ".venv/lib/python3.13/site-packages"),
                EXTRA_TOOL="",
                EXTRA_PRINCIPAL="",
            ).items():
                template = template.replace("@" + key + "@", value)
            (folder / "policy.slp").write_text(template)
            request = dict(
                app="pandas",
                task=prompt,
                model=manifest["model"],
                fixture_root=str(fixture),
                output=str(folder / "output.json"),
                events=str(folder / "events.jsonl"),
                configuration=mode,
                integration=True,
                slanggraph_root=str(framework_runtime_root),
                run_id=run_id,
                effective_policy=str(folder / "policy.slp"),
                sandbox_serialization=serialization,
                workflow_contract=workflow_contract,
                computation_api=computation_api,
                graph_retries=args.graph_retries,
                lean_worker=lean_worker if mode == "C" else None,
            )
            dump(folder / "request.json", request)
            trial_sources = capture_framework(out, framework_runtime_root)
            dump(folder / "framework-sources-before.json", trial_sources)
            started_at = datetime.now(UTC).isoformat()
            start = time.perf_counter()
            status = "error"
            code = None
            command = [
                "taskset",
                "--cpu-list",
                str(min(os.sched_getaffinity(0))),
                str(UPSTREAM / ".venv/bin/python"),
                str(snapshot / "backend.py"),
                str(folder / "request.json"),
            ]
            with (folder / "process.log").open("w") as log:
                try:
                    completed = subprocess.run(
                        command,
                        cwd=UPSTREAM,
                        stdout=log,
                        stderr=subprocess.STDOUT,
                        timeout=180,
                        env={**os.environ, "OPENBLAS_NUM_THREADS": "1", "OMP_NUM_THREADS": "1"},
                    )
                    code = completed.returncode
                    status = "completed" if code == 0 else "error"
                except subprocess.TimeoutExpired:
                    status = "timeout"
            elapsed = (time.perf_counter() - start) * 1000
            trial_sources_after = capture_framework(out, framework_runtime_root)
            dump(folder / "framework-sources-after.json", trial_sources_after)
            result = (
                json.loads((folder / "output.json").read_text())
                if (folder / "output.json").exists()
                else {}
            )
            oracle_match = oracle(result, expected, case == "monthly_chart")
            success = status == "completed" and oracle_match
            events = (
                [json.loads(line) for line in (folder / "events.jsonl").read_text().splitlines()]
                if (folder / "events.jsonl").exists()
                else []
            )
            starts = [x["monotonic"] for x in events if x.get("kind") == "model_start"]
            ends = [x["monotonic"] for x in events if x.get("kind") == "model_end"]
            row = dict(
                schema_version=2,
                application="pandas",
                started_at=started_at,
                finished_at=datetime.now(UTC).isoformat(),
                model=manifest["model"],
                sources=sources,
                framework_sources_sha256=identity_digest(trial_sources),
                framework_sources=trial_sources,
                source_hashes_unchanged_before_after=trial_sources == trial_sources_after,
                policy_sha256=hashlib.sha256(template.encode()).hexdigest(),
                sandbox_serialization=serialization,
                workflow_contract=workflow_contract,
                computation_api=computation_api,
                graph_retries=args.graph_retries,
                manifest_version=manifest_version,
                lean_worker=lean_worker if mode == "C" else None,
                timing_scope="subprocess wall time; setup excluded; shared host",
                missing_phases=["policy", "audit"],
                case_id=case,
                repeat=repetition,
                session=repetition,
                mode=mode,
                concrete_executor="LinuxSandboxExecutor"
                if mode == "C"
                else "upstream subprocess sandbox",
                run_id=run_id,
                status=status,
                exit_status=code,
                legitimate_result=success,
                output_matches_oracle=oracle_match,
                observed_effect="not-tested: clean utility task",
                wall_ms=elapsed,
                model_calls=len(starts),
                model_ms=sum((b - a) * 1000 for a, b in zip(starts, ends, strict=False)),
                computation_calls=sum(x.get("kind") == "computation" for x in events),
                activation_evidence=str(folder / "activation-receipts.json")
                if (folder / "activation-receipts.json").exists()
                else "not-applicable",
                audit=str(folder / "security.sqlite")
                if (folder / "security.sqlite").exists()
                else "not-applicable",
                expected=expected,
            )
            with trials.open("a") as stream:
                stream.write(json.dumps(row) + "\n")
            print(run_id, status, success, round(elapsed), flush=True)


if __name__ == "__main__":
    main()
