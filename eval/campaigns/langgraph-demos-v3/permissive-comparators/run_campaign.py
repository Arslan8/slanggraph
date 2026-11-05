"""Run the fixed 15 applications against permissive NoNo and APF/OpenShell."""

from __future__ import annotations

import argparse
import hashlib
import importlib.util
import json
import random
import subprocess
import sys
import time
from pathlib import Path

CAMPAIGN = Path(__file__).resolve().parent
V3 = CAMPAIGN.parent
ROOT = V3.parents[2]
V1 = ROOT / "eval/campaigns/langgraph-demos-v1"
BASE_RUNNER = V3 / "run_campaign.py"
DEFAULT_NONO = ROOT / "eval/vendor/nono/target/release/nono"
DEFAULT_OPENSHELL = ROOT / "eval/campaigns/remediation-v2/raw/openshell-setup/openshell"
APF_POLICY = CAMPAIGN / "apf-policy.yaml"
APF_PROJECTED_POLICY = CAMPAIGN / "apf-projected-policy.json"
DEFAULT_OPENSHELL_IMAGE_ID = (
    "sha256:82e95e8b7e3bb7ccdcf65c806a0b37435b0e086d36946b596e743a935eef8e19"
)
SEED = 20261028
MODES = ("Baseline", "Argus", "NoNo-permissive", "APF-permissive")


def load_base_runner():
    spec = importlib.util.spec_from_file_location("permissive_comparator_base_runner", BASE_RUNNER)
    if spec is None or spec.loader is None:
        raise RuntimeError(f"cannot load base campaign runner: {BASE_RUNNER}")
    module = importlib.util.module_from_spec(spec)
    sys.modules[spec.name] = module
    spec.loader.exec_module(module)
    return module


base = load_base_runner()


def sha256(path: Path) -> str:
    return hashlib.sha256(path.read_bytes()).hexdigest()


def openshell_prefix(cli: Path, endpoint: str) -> list[str]:
    return [str(cli), "--gateway-endpoint", endpoint]


def openshell_exec(
    cli: Path,
    endpoint: str,
    sandbox: str,
    command: list[str],
    *,
    timeout: int,
    cwd: str | None = "/data/langgraph",
) -> subprocess.CompletedProcess[str]:
    result = [
        *openshell_prefix(cli, endpoint),
        "sandbox",
        "exec",
        sandbox,
        "--no-tty",
        "--no-login-shell",
        "--timeout",
        str(timeout),
    ]
    if cwd is not None:
        result.extend(("--workdir", cwd))
    result.extend(("--", *command))
    return subprocess.run(
        result,
        cwd=ROOT,
        capture_output=True,
        text=True,
        timeout=timeout + 30,
        check=False,
    )


def comparator_command(job, trial: Path, tasks: dict) -> tuple[list[str], int]:
    baseline_job = base.Job(job.application, job.task, job.repetition, "Baseline")
    return base.command(baseline_job, trial, tasks)


def remap_trial_arguments(command: list[str], trial: Path, inner_trial: Path) -> list[str]:
    source = str(trial)
    target = str(inner_trial)
    return [target + item[len(source) :] if item.startswith(source) else item for item in command]


def read_apf_output(
    cli: Path,
    endpoint: str,
    sandbox: str,
    inner_output: Path,
    output: Path,
) -> str:
    completed = openshell_exec(
        cli,
        endpoint,
        sandbox,
        ["/bin/cat", str(inner_output)],
        timeout=30,
        cwd=None,
    )
    if completed.returncode == 0:
        output.write_text(completed.stdout)
        return completed.stderr
    return f"{completed.stderr}\nfailed to retrieve {inner_output}"


def retrieve_d4_artifacts(
    cli: Path,
    endpoint: str,
    sandbox: str,
    inner_trial: Path,
    trial: Path,
) -> str:
    errors = []
    observer_result = openshell_exec(
        cli,
        endpoint,
        sandbox,
        ["/bin/cat", str(inner_trial / "observer.json")],
        timeout=30,
        cwd=None,
    )
    if observer_result.returncode == 0:
        (trial / "observer.json").write_text(observer_result.stdout)
    else:
        errors.append(observer_result.stderr)
    chart_result = subprocess.run(
        [
            *openshell_prefix(cli, endpoint),
            "sandbox",
            "download",
            sandbox,
            str(inner_trial / "chart.png"),
            str(trial / "chart.png"),
        ],
        cwd=ROOT,
        capture_output=True,
        text=True,
        timeout=60,
        check=False,
    )
    if chart_result.returncode != 0:
        errors.append(chart_result.stderr)
    return "\n".join(errors)


def execute_external(
    job,
    root: Path,
    tasks: dict,
    *,
    nono: Path,
    openshell: Path,
    endpoint: str,
    sandbox: str,
) -> dict:
    trial = root / f"rep-{job.repetition}" / job.application / f"task-{job.task}" / job.mode
    trial.mkdir(parents=True, exist_ok=False)
    app_command, timeout = comparator_command(job, trial, tasks)
    output = trial / "output.json"
    retrieval_error = ""
    if job.mode == "NoNo-permissive":
        executed_command = [
            str(nono),
            "run",
            "--allow",
            "/data",
            "--allow",
            "/tmp",
            "--allow",
            "/home/faculty/abk6349/.cache",
            "--allow",
            "/home/faculty/abk6349/.local/share/uv",
            "--no-audit",
            "--no-rollback",
            "--trust-override",
            "--silent",
            "--",
            *app_command,
        ]
    else:
        inner_trial = Path("/workspace/results") / (
            f"rep-{job.repetition}/{job.application}/task-{job.task}/{job.mode}"
        )
        setup = openshell_exec(
            openshell,
            endpoint,
            sandbox,
            ["/bin/rm", "-rf", str(inner_trial)],
            timeout=30,
            cwd=None,
        )
        if setup.returncode != 0:
            raise RuntimeError(f"failed to reset OpenShell trial {inner_trial}: {setup.stderr}")
        setup = openshell_exec(
            openshell,
            endpoint,
            sandbox,
            ["/bin/mkdir", "-p", str(inner_trial)],
            timeout=30,
            cwd=None,
        )
        if setup.returncode != 0:
            raise RuntimeError(f"failed to create OpenShell trial {inner_trial}: {setup.stderr}")
        if job.application == "D1-sql":
            fixture = V1 / tasks["D1"]["fixture"]
            setup = openshell_exec(
                openshell,
                endpoint,
                sandbox,
                ["/bin/cp", str(fixture), str(inner_trial / "Chinook.db")],
                timeout=30,
                cwd=None,
            )
            if setup.returncode != 0:
                raise RuntimeError(f"failed to prepare OpenShell database: {setup.stderr}")
        inner_command = remap_trial_arguments(app_command, trial, inner_trial)
        executed_command = [
            *openshell_prefix(openshell, endpoint),
            "sandbox",
            "exec",
            sandbox,
            "--no-tty",
            "--no-login-shell",
            "--timeout",
            str(timeout),
            "--workdir",
            "/data/langgraph",
            "--",
            *inner_command,
        ]

    started = time.perf_counter()
    timed_out = False
    try:
        completed = subprocess.run(
            executed_command,
            cwd=ROOT,
            capture_output=True,
            text=True,
            timeout=timeout + (30 if job.mode == "APF-permissive" else 0),
            check=False,
        )
        returncode = completed.returncode
        stdout, stderr = completed.stdout, completed.stderr
        process_wall_ms = (time.perf_counter() - started) * 1000
    except subprocess.TimeoutExpired as error:
        timed_out = True
        returncode = None
        stdout = error.stdout or ""
        stderr = error.stderr or ""
        if isinstance(stdout, bytes):
            stdout = stdout.decode(errors="replace")
        if isinstance(stderr, bytes):
            stderr = stderr.decode(errors="replace")
        process_wall_ms = timeout * 1000.0

    if job.mode == "APF-permissive":
        retrieval_error = read_apf_output(
            openshell,
            endpoint,
            sandbox,
            inner_trial / "output.json",
            output,
        )
        if job.application == "D4-multi-agent":
            retrieval_error += retrieve_d4_artifacts(
                openshell,
                endpoint,
                sandbox,
                inner_trial,
                trial,
            )

    inner = json.loads(output.read_text()) if output.exists() else {}
    if timed_out:
        status = "timeout"
    elif returncode != 0:
        status = "compatibility_failed"
    elif inner.get("status") == "execution_error" or inner.get("error"):
        status = "execution_error"
    else:
        status = "completed"
    correct = False
    if status == "completed":
        correct = (
            base.old_correct(job.application, inner)
            if job.application in base.OLD_DEMOS
            else base.new_correct(job, inner, trial, tasks)
        )
    record = {
        "application": job.application,
        "task": job.task,
        "repetition": job.repetition,
        "mode": job.mode,
        "configuration": "deliberately insecure/permissive mechanism-only lower bound",
        "status": status,
        "correct": correct,
        "process_wall_ms": process_wall_ms,
        "timeout_cap_seconds": timeout,
        "censored": timed_out,
        "returncode": returncode,
        "invocation_ms": inner.get("invocation_ms", inner.get("wall_ms")),
        "preparation_ms": inner.get("preparation_ms"),
        "model_time_ms": inner.get("model_time_ms"),
        "model_calls": inner.get("model_calls"),
        "application_route": inner.get("isolation_route"),
        "security_equivalent_to_argus": False,
        "audit_enabled": False,
        "command": executed_command,
        "raw_output": str(output.relative_to(ROOT)) if output.exists() else None,
        "stdout": stdout,
        "stderr": f"{stderr}\n{retrieval_error}".strip(),
        "error": inner.get("error"),
    }
    (trial / "trial.json").write_text(json.dumps(record, indent=2) + "\n")
    return record


def run_negative_probes(
    root: Path,
    *,
    nono: Path,
    openshell: Path,
    endpoint: str,
    sandbox: str,
) -> None:
    secret = "COMPARATOR_POLICY_IS_DELIBERATELY_INSECURE"
    probe = root / "setup-secret.txt"
    probe.write_text(secret)
    nono_result = subprocess.run(
        [
            str(nono),
            "run",
            "--allow",
            "/data",
            "--allow",
            "/tmp",
            "--allow",
            "/home/faculty/abk6349/.cache",
            "--allow",
            "/home/faculty/abk6349/.local/share/uv",
            "--no-audit",
            "--no-rollback",
            "--trust-override",
            "--silent",
            "--",
            "/bin/cat",
            str(probe),
        ],
        cwd=ROOT,
        capture_output=True,
        text=True,
        timeout=30,
        check=False,
    )
    apf_secret = "/workspace/results/setup-secret.txt"
    setup = openshell_exec(
        openshell,
        endpoint,
        sandbox,
        ["/bin/sh", "-c", f"printf %s {secret} > {apf_secret}"],
        timeout=30,
        cwd=None,
    )
    apf_result = openshell_exec(
        openshell,
        endpoint,
        sandbox,
        ["/bin/cat", apf_secret],
        timeout=30,
        cwd=None,
    )
    evidence = {
        "purpose": "prove comparator configurations are insecure and not authority-equivalent",
        "expected": "the unscoped secret read succeeds",
        "nono": {
            "returncode": nono_result.returncode,
            "secret_observed": secret in nono_result.stdout,
        },
        "apf_openshell": {
            "setup_returncode": setup.returncode,
            "returncode": apf_result.returncode,
            "secret_observed": secret in apf_result.stdout,
        },
    }
    if not evidence["nono"]["secret_observed"] or not evidence["apf_openshell"]["secret_observed"]:
        raise RuntimeError(f"permissive negative probes did not succeed: {evidence}")
    (root / "insecure-probes.json").write_text(json.dumps(evidence, indent=2) + "\n")


def main() -> None:
    parser = argparse.ArgumentParser()
    parser.add_argument("--run-id", required=True)
    parser.add_argument("--repetitions", type=int, default=5)
    parser.add_argument("--smoke", action="store_true")
    parser.add_argument("--nono", type=Path, default=DEFAULT_NONO)
    parser.add_argument("--openshell", type=Path, default=DEFAULT_OPENSHELL)
    parser.add_argument("--openshell-endpoint", default="http://127.0.0.1:18080")
    parser.add_argument("--openshell-sandbox", default="apf-permissive-15")
    parser.add_argument("--openshell-image-id", default=DEFAULT_OPENSHELL_IMAGE_ID)
    args = parser.parse_args()
    for executable in (args.nono, args.openshell):
        if not executable.is_file():
            raise RuntimeError(f"missing comparator executable: {executable}")
    root = V3 / "raw" / args.run_id
    root.mkdir(parents=True, exist_ok=False)
    tasks = json.loads((V1 / "tasks.json").read_text())
    sandbox_status = subprocess.run(
        [
            *openshell_prefix(args.openshell, args.openshell_endpoint),
            "sandbox",
            "get",
            args.openshell_sandbox,
            "--output",
            "json",
        ],
        cwd=ROOT,
        capture_output=True,
        text=True,
        timeout=30,
        check=False,
    )
    if sandbox_status.returncode != 0 or json.loads(sandbox_status.stdout)["phase"] != "Ready":
        raise RuntimeError(f"OpenShell sandbox is not ready: {sandbox_status.stderr}")
    metadata = base.common_metadata()
    metadata.update(
        {
            "evaluated_commit": subprocess.run(
                ["git", "rev-parse", "HEAD"],
                cwd=ROOT,
                capture_output=True,
                text=True,
                check=True,
            ).stdout.strip(),
            "run_id": args.run_id,
            "modes": list(MODES),
            "repetitions": 1 if args.smoke else args.repetitions,
            "smoke": args.smoke,
            "comparison_scope": (
                "same fixed 15 applications; comparator policies are deliberately insecure "
                "and are mechanism-only performance lower bounds"
            ),
            "timers": {
                "invocation_ms": "application-reported invocation after application preparation",
                "process_wall_ms": (
                    "parent dispatch through process exit; includes NoNo activation or "
                    "OpenShell exec transport but excludes reusable OpenShell sandbox creation"
                ),
            },
            "nono": {
                "revision": subprocess.run(
                    ["git", "-C", str(ROOT / "eval/vendor/nono"), "rev-parse", "HEAD"],
                    capture_output=True,
                    text=True,
                    check=True,
                ).stdout.strip(),
                "binary": str(args.nono.relative_to(ROOT)),
                "sha256": sha256(args.nono),
                "audit": "disabled",
                "rollback": "disabled",
                "network": "unrestricted",
                "filesystem": "broad writable /data, /tmp, and runtime/cache paths",
                "trust_override": True,
            },
            "apf_openshell": {
                "apf_revision": subprocess.run(
                    ["git", "-C", str(ROOT / "eval/vendor/apf"), "rev-parse", "HEAD"],
                    capture_output=True,
                    text=True,
                    check=True,
                ).stdout.strip(),
                "openshell_revision": subprocess.run(
                    ["git", "-C", str(ROOT / "eval/vendor/openshell"), "rev-parse", "HEAD"],
                    capture_output=True,
                    text=True,
                    check=True,
                ).stdout.strip(),
                "cli_sha256": sha256(args.openshell),
                "endpoint": args.openshell_endpoint,
                "sandbox": args.openshell_sandbox,
                "application_image_id": args.openshell_image_id,
                "sandbox_status": json.loads(sandbox_status.stdout),
                "sandbox_creation": "one-time preparation excluded from both timers",
                "policy_source": "permissive-comparators/apf-policy.yaml",
                "policy_source_sha256": sha256(APF_POLICY),
                "projected_policy_sha256": sha256(APF_PROJECTED_POLICY),
                "policy_semantics": (
                    "official APF compiler/OpenShell projector; broad application-tree access; "
                    "best-effort Landlock; local model relay"
                ),
                "audit": "OpenShell defaults retained; not included in application output",
            },
        }
    )
    (root / "configuration.json").write_text(json.dumps(metadata, indent=2) + "\n")
    run_negative_probes(
        root,
        nono=args.nono,
        openshell=args.openshell,
        endpoint=args.openshell_endpoint,
        sandbox=args.openshell_sandbox,
    )

    records = []
    repetitions = range(1 if args.smoke else args.repetitions)
    applications = (*base.OLD_DEMOS, *base.NEW_DEMOS)
    for repetition in repetitions:
        jobs = []
        for application in applications:
            task_ids = (1,) if application in base.OLD_DEMOS or args.smoke else range(1, 6)
            jobs.extend(
                base.Job(application, task, repetition, mode) for task in task_ids for mode in MODES
            )
        random.Random(SEED + repetition).shuffle(jobs)
        for job in jobs:
            if job.mode in {"Baseline", "Argus"}:
                record = base.execute(job, root, tasks)
                record["configuration"] = "security-equivalent final campaign mode"
                record["security_equivalent_to_argus"] = job.mode == "Argus"
                (
                    root
                    / f"rep-{job.repetition}"
                    / job.application
                    / f"task-{job.task}"
                    / job.mode
                    / "trial.json"
                ).write_text(json.dumps(record, indent=2) + "\n")
            else:
                record = execute_external(
                    job,
                    root,
                    tasks,
                    nono=args.nono,
                    openshell=args.openshell,
                    endpoint=args.openshell_endpoint,
                    sandbox=args.openshell_sandbox,
                )
            records.append(record)
            print(
                f"{job.repetition} {job.application} {job.task} {job.mode}: "
                f"{record['status']} correct={record['correct']} "
                f"process_ms={record['process_wall_ms']:.1f}",
                flush=True,
            )
    (root / "trials.json").write_text(json.dumps(records, indent=2) + "\n")


if __name__ == "__main__":
    main()
