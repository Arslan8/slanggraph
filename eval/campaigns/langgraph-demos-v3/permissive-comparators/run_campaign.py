"""Run the fixed 15 applications under enforceable NoNo and APF policies."""

from __future__ import annotations

import argparse
import contextlib
import hashlib
import importlib.util
import json
import os
import random
import signal
import subprocess
import sys
import time
from dataclasses import dataclass
from pathlib import Path

import yaml

CAMPAIGN = Path(__file__).resolve().parent
V3 = CAMPAIGN.parent
ROOT = V3.parents[2]
V1 = ROOT / "eval/campaigns/langgraph-demos-v1"
BASE_RUNNER = V3 / "run_campaign.py"
DEFAULT_NONO = ROOT / "eval/vendor/nono/target/release/nono"
DEFAULT_OPENSHELL = ROOT / "eval/campaigns/remediation-v2/raw/openshell-setup/openshell"
APF_POLICY = CAMPAIGN / "apf-policy.yaml"
APF_PROJECTED_POLICY = CAMPAIGN / "apf-projected-policy.json"
APF_EXPORTER = ROOT / "eval/remaining/apf_probe/target/debug/export_policy"
DEFAULT_OPENSHELL_IMAGE_ID = (
    "sha256:82e95e8b7e3bb7ccdcf65c806a0b37435b0e086d36946b596e743a935eef8e19"
)
SEED = 20261028
MODES = ("Baseline", "Argus", "NoNo-enforced", "APF-enforced")
APF_IMAGE = "slg-apf-apps:bd035dd06"
MODEL_RELAY = (
    "/data/langgraph/eval/campaigns/langgraph-demos-v3/permissive-comparators/model_relay.py"
)
PYTHON_RUNTIME = "/home/faculty/abk6349/.local/share/uv"
READ_ONLY_CODE = (
    ROOT / "eval/.venv",
    ROOT / "eval/src",
    ROOT / "eval/apps/demos",
    ROOT / "libs",
)


@dataclass(frozen=True)
class ProcessResult:
    returncode: int | None
    stdout: str
    stderr: str
    timed_out: bool
    cleanup_confirmed: bool
    process_group_id: int


def _process_group_exists(process_group_id: int) -> bool:
    try:
        os.killpg(process_group_id, 0)
    except ProcessLookupError:
        return False
    return True


def _terminate_process_group(process: subprocess.Popen[str], grace_seconds: float) -> bool:
    try:
        os.killpg(process.pid, signal.SIGTERM)
    except ProcessLookupError:
        return True

    deadline = time.monotonic() + grace_seconds
    while _process_group_exists(process.pid) and time.monotonic() < deadline:
        time.sleep(0.01)
    if _process_group_exists(process.pid):
        with contextlib.suppress(ProcessLookupError):
            os.killpg(process.pid, signal.SIGKILL)

    with contextlib.suppress(subprocess.TimeoutExpired):
        process.wait(timeout=grace_seconds)

    deadline = time.monotonic() + grace_seconds
    while _process_group_exists(process.pid) and time.monotonic() < deadline:
        time.sleep(0.01)
    return not _process_group_exists(process.pid)


def run_with_process_group_cleanup(
    command: list[str],
    *,
    cwd: Path,
    env: dict[str, str] | None,
    timeout: float,
    cleanup_grace_seconds: float = 5.0,
) -> ProcessResult:
    process = subprocess.Popen(
        command,
        cwd=cwd,
        env=env,
        stdout=subprocess.PIPE,
        stderr=subprocess.PIPE,
        text=True,
        start_new_session=True,
    )
    try:
        stdout, stderr = process.communicate(timeout=timeout)
    except subprocess.TimeoutExpired:
        cleanup_confirmed = _terminate_process_group(process, cleanup_grace_seconds)
        stdout, stderr = process.communicate()
        return ProcessResult(
            returncode=None,
            stdout=stdout,
            stderr=stderr,
            timed_out=True,
            cleanup_confirmed=cleanup_confirmed,
            process_group_id=process.pid,
        )
    return ProcessResult(
        returncode=process.returncode,
        stdout=stdout,
        stderr=stderr,
        timed_out=False,
        cleanup_confirmed=True,
        process_group_id=process.pid,
    )


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


def resource_inputs(job, trial: Path, tasks: dict) -> list[Path]:
    if job.application == "D1-sql":
        return [trial / "Chinook.db"]
    if job.application == "D2-rag":
        return [V1 / item for item in tasks["D2"]["documents"]]
    if job.application == "D3-plan-execute":
        return [V1 / tasks["D3"]["corpus"]]
    if job.application == "D4-multi-agent":
        return [V1 / tasks["D4"]["fixture"]]
    if job.application == "D5-support":
        return [
            V1 / "fixtures/customer-support/travel2.sqlite",
            V1 / "upstream/docs/docs/tutorials/customer-support/customer-support.ipynb",
            V1 / "fixtures/customer-support/swiss_faq.md",
        ]
    return []


def apf_input_bindings(job, trial: Path, tasks: dict) -> list[tuple[Path, Path]]:
    inputs = resource_inputs(job, trial, tasks)
    if job.application == "D1-sql":
        return [(inputs[0], V1 / tasks["D1"]["fixture"])]
    return [(path, path) for path in inputs]


def remap_apf_arguments(
    command: list[str], trial: Path, inner_trial: Path, bindings: list[tuple[Path, Path]]
) -> list[str]:
    input_targets = {str(source): str(target) for source, target in bindings}
    trial_prefix = str(trial)
    result = []
    for item in command:
        if item in input_targets:
            result.append(input_targets[item])
        elif item.startswith(trial_prefix):
            result.append(str(inner_trial) + item[len(trial_prefix) :])
        else:
            result.append(item)
    return result


def project_apf_policy(trial: Path, inputs: list[Path]) -> Path:
    policy = yaml.safe_load(APF_POLICY.read_text())
    policy["spec"]["filesystem"]["read_only"].extend(str(path) for path in inputs)
    source = trial / "apf-policy.yaml"
    projected = trial / "apf-projected-policy.json"
    source.write_text(yaml.safe_dump(policy, sort_keys=False))
    result = subprocess.run(
        [str(APF_EXPORTER), str(source)],
        cwd=ROOT,
        capture_output=True,
        text=True,
        timeout=30,
        check=False,
    )
    if result.returncode != 0:
        raise RuntimeError(f"APF projection failed: {result.stderr}")
    json.loads(result.stdout)
    projected.write_text(result.stdout.rstrip() + "\n")
    return projected


def apf_sandbox_name(root: Path, job) -> str:
    run_digest = hashlib.sha256(root.name.encode()).hexdigest()[:6]
    application = hashlib.sha256(job.application.encode()).hexdigest()[:4]
    return f"a{run_digest}r{job.repetition}{application}t{job.task}"


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
) -> dict:
    trial = root / f"rep-{job.repetition}" / job.application / f"task-{job.task}" / job.mode
    trial.mkdir(parents=True, exist_ok=False)
    app_command, timeout = comparator_command(job, trial, tasks)
    output = trial / "output.json"
    retrieval_error = ""
    sandbox = None
    sandbox_preparation_ms = 0.0
    cleanup_ms = 0.0
    cleanup_confirmed = None
    apf_policy_sha256 = None
    apf_projected_policy_sha256 = None
    execution_cwd = ROOT
    execution_env = None
    inputs = resource_inputs(job, trial, tasks)
    if job.mode == "NoNo-enforced":
        (trial / "tmp").mkdir()
        executed_command = [
            str(nono),
            "run",
            "--allow-cwd",
            "--allow",
            str(trial),
            *[item for path in READ_ONLY_CODE for item in ("--read", str(path))],
            "--read",
            PYTHON_RUNTIME,
            *[item for path in inputs for item in ("--read-file", str(path))],
            "--block-net",
            "--allow-connect-port",
            "11434",
            "--no-audit",
            "--no-rollback",
            "--silent",
            "--",
            *app_command,
        ]
        execution_cwd = trial
        execution_env = {
            **os.environ,
            "TMPDIR": str(trial / "tmp"),
            "MPLCONFIGDIR": str(trial / "tmp/matplotlib"),
            "PYTHONDONTWRITEBYTECODE": "1",
        }
    else:
        inner_trial = Path("/workspace/results")
        sandbox = apf_sandbox_name(root, job)
        subprocess.run(
            [*openshell_prefix(openshell, endpoint), "sandbox", "delete", sandbox],
            cwd=ROOT,
            capture_output=True,
            text=True,
            timeout=60,
            check=False,
        )
        preparation_started = time.perf_counter()
        bindings = apf_input_bindings(job, trial, tasks)
        projected_policy = project_apf_policy(trial, [target for _, target in bindings])
        apf_policy_sha256 = sha256(trial / "apf-policy.yaml")
        apf_projected_policy_sha256 = sha256(projected_policy)
        setup = subprocess.run(
            [
                *openshell_prefix(openshell, endpoint),
                "sandbox",
                "create",
                "--name",
                sandbox,
                "--from",
                APF_IMAGE,
                "--policy",
                str(projected_policy),
                "--no-tty",
                "--detach",
                "--",
                "/data/langgraph/eval/.venv/bin/python",
                MODEL_RELAY,
                "--target-host",
                "host.openshell.internal",
                "--target-port",
                "11435",
                "--rewrite-authority",
                "127.0.0.1:11434",
                "host.openshell.internal:11435",
            ],
            cwd=ROOT,
            capture_output=True,
            text=True,
            timeout=90,
            check=False,
        )
        setup_errors = [setup.stderr]
        inner_command = remap_apf_arguments(app_command, trial, inner_trial, bindings)
        if setup.returncode == 0:
            setup = openshell_exec(
                openshell,
                endpoint,
                sandbox,
                ["/bin/mkdir", "-p", str(inner_trial)],
                timeout=30,
                cwd=None,
            )
            setup_errors.append(setup.stderr)
        sandbox_preparation_ms = (time.perf_counter() - preparation_started) * 1000
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
    timeout_cleanup_confirmed = None
    if job.mode == "APF-enforced" and setup.returncode != 0:
        returncode = setup.returncode
        stdout = setup.stdout
        stderr = "\n".join(setup_errors)
        process_wall_ms = 0.0
    else:
        completed = run_with_process_group_cleanup(
            executed_command,
            cwd=execution_cwd,
            env=execution_env,
            timeout=timeout + (30 if job.mode == "APF-enforced" else 0),
        )
        timed_out = completed.timed_out
        timeout_cleanup_confirmed = completed.cleanup_confirmed
        returncode = completed.returncode
        stdout, stderr = completed.stdout, completed.stderr
        process_wall_ms = timeout * 1000.0 if timed_out else (time.perf_counter() - started) * 1000

    if job.mode == "APF-enforced" and setup.returncode == 0:
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

    if sandbox is not None:
        cleanup_started = time.perf_counter()
        cleanup = subprocess.run(
            [*openshell_prefix(openshell, endpoint), "sandbox", "delete", sandbox],
            cwd=ROOT,
            capture_output=True,
            text=True,
            timeout=60,
            check=False,
        )
        cleanup_ms = (time.perf_counter() - cleanup_started) * 1000
        cleanup_confirmed = cleanup.returncode == 0
        if not cleanup_confirmed:
            retrieval_error += f"\nfailed to delete sandbox {sandbox}: {cleanup.stderr}"

    inner = json.loads(output.read_text()) if output.exists() else {}
    if timed_out:
        status = "timeout"
    elif cleanup_confirmed is False or returncode != 0:
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
        "configuration": "closest enforceable matched-authority host policy",
        "status": status,
        "correct": correct,
        "process_wall_ms": process_wall_ms,
        "timeout_cap_seconds": timeout,
        "censored": timed_out,
        "timeout_cleanup_confirmed": timeout_cleanup_confirmed,
        "returncode": returncode,
        "invocation_ms": inner.get("invocation_ms", inner.get("wall_ms")),
        "preparation_ms": inner.get("preparation_ms"),
        "sandbox_preparation_ms": sandbox_preparation_ms,
        "sandbox_cleanup_ms": cleanup_ms,
        "sandbox_cleanup_confirmed": cleanup_confirmed,
        "end_to_end_wall_ms": sandbox_preparation_ms + process_wall_ms + cleanup_ms,
        "model_time_ms": inner.get("model_time_ms"),
        "model_calls": inner.get("model_calls"),
        "application_route": inner.get("isolation_route"),
        "security_equivalent_to_argus": False,
        "filesystem_and_network_policy_enforced": True,
        "semantic_resource_action_mediation": False,
        "apf_policy_sha256": apf_policy_sha256,
        "apf_projected_policy_sha256": apf_projected_policy_sha256,
        "audit_enabled": False,
        "command": executed_command,
        "raw_output": str(output.relative_to(ROOT)) if output.exists() else None,
        "stdout": stdout,
        "stderr": f"{stderr}\n{retrieval_error}".strip(),
        "error": inner.get("error"),
    }
    (trial / "trial.json").write_text(json.dumps(record, indent=2) + "\n")
    return record


def run_enforcement_probes(
    root: Path,
    *,
    nono: Path,
    openshell: Path,
    endpoint: str,
) -> None:
    probe_work = root / "probe-work"
    probe_work.mkdir()
    protected_fixture = V1 / "fixtures/sql/Chinook.db"
    nono_denied = subprocess.run(
        [
            str(nono),
            "run",
            "--allow-cwd",
            "--allow",
            str(probe_work),
            "--block-net",
            "--no-audit",
            "--no-rollback",
            "--silent",
            "--",
            "/bin/cat",
            str(protected_fixture),
        ],
        cwd=probe_work,
        capture_output=True,
        text=True,
        timeout=30,
        check=False,
    )
    nono_source_write = subprocess.run(
        [
            str(nono),
            "run",
            "--allow-cwd",
            "--allow",
            str(probe_work),
            "--read",
            str(ROOT / "eval/apps/demos"),
            "--block-net",
            "--no-audit",
            "--no-rollback",
            "--silent",
            "--",
            "/bin/sh",
            "-c",
            "printf denied > /data/langgraph/eval/apps/demos/.write-probe",
        ],
        cwd=probe_work,
        capture_output=True,
        text=True,
        timeout=30,
        check=False,
    )
    network_command = [
        str(nono),
        "run",
        "--allow-cwd",
        "--allow",
        str(probe_work),
        "--read",
        PYTHON_RUNTIME,
        "--block-net",
        "--allow-connect-port",
        "11434",
        "--no-audit",
        "--no-rollback",
        "--silent",
        "--",
        f"{PYTHON_RUNTIME}/python/cpython-3.11.14-linux-x86_64-gnu/bin/python3.11",
    ]
    nono_model = subprocess.run(
        [
            *network_command,
            "-c",
            "import urllib.request; print(urllib.request.urlopen("
            "'http://127.0.0.1:11434/api/tags', timeout=5).status)",
        ],
        cwd=probe_work,
        capture_output=True,
        text=True,
        timeout=30,
        check=False,
    )
    nono_wrong_port = subprocess.run(
        [
            *network_command,
            "-c",
            'import socket; socket.create_connection(("127.0.0.1", 11435), 2)',
        ],
        cwd=probe_work,
        capture_output=True,
        text=True,
        timeout=30,
        check=False,
    )
    sandbox = f"apf-{hashlib.sha256(root.name.encode()).hexdigest()[:8]}-probe"
    subprocess.run(
        [*openshell_prefix(openshell, endpoint), "sandbox", "delete", sandbox],
        cwd=ROOT,
        capture_output=True,
        text=True,
        timeout=60,
        check=False,
    )
    apf_create = subprocess.run(
        [
            *openshell_prefix(openshell, endpoint),
            "sandbox",
            "create",
            "--name",
            sandbox,
            "--from",
            APF_IMAGE,
            "--policy",
            str(APF_PROJECTED_POLICY),
            "--no-tty",
            "--detach",
            "--",
            "/data/langgraph/eval/.venv/bin/python",
            MODEL_RELAY,
            "--target-host",
            "host.openshell.internal",
            "--target-port",
            "11435",
            "--rewrite-authority",
            "127.0.0.1:11434",
            "host.openshell.internal:11435",
        ],
        cwd=ROOT,
        capture_output=True,
        text=True,
        timeout=90,
        check=False,
    )
    if apf_create.returncode != 0:
        raise RuntimeError(f"failed to create APF enforcement probe: {apf_create.stderr}")
    apf_denied = openshell_exec(
        openshell, endpoint, sandbox, ["/bin/cat", str(protected_fixture)], timeout=30, cwd=None
    )
    apf_source_write = openshell_exec(
        openshell,
        endpoint,
        sandbox,
        ["/bin/sh", "-c", "printf denied > /data/langgraph/eval/apps/demos/.write-probe"],
        timeout=30,
        cwd=None,
    )
    apf_wrong_port = openshell_exec(
        openshell,
        endpoint,
        sandbox,
        [
            "/data/langgraph/eval/.venv/bin/python",
            "-c",
            'import socket; socket.create_connection(("host.openshell.internal", 11434), 2)',
        ],
        timeout=30,
        cwd=None,
    )
    apf_model = openshell_exec(
        openshell,
        endpoint,
        sandbox,
        [
            "/data/langgraph/eval/.venv/bin/python",
            "-c",
            "import urllib.request; print(urllib.request.urlopen("
            "'http://127.0.0.1:11434/api/tags', timeout=5).status)",
        ],
        timeout=30,
        cwd=None,
    )
    apf_delete = subprocess.run(
        [*openshell_prefix(openshell, endpoint), "sandbox", "delete", sandbox],
        cwd=ROOT,
        capture_output=True,
        text=True,
        timeout=60,
        check=False,
    )
    evidence = {
        "purpose": "verify every host-level control the comparators can enforce",
        "expected": "ungranted resource and network probes fail; the model endpoint succeeds",
        "nono": {
            "ungranted_fixture_read_denied": nono_denied.returncode != 0,
            "source_write_denied": nono_source_write.returncode != 0,
            "model_endpoint_allowed": nono_model.returncode == 0 and "200" in nono_model.stdout,
            "other_port_denied": nono_wrong_port.returncode != 0,
        },
        "apf_openshell": {
            "ungranted_fixture_read_denied": apf_denied.returncode != 0,
            "source_write_denied": apf_source_write.returncode != 0,
            "model_endpoint_allowed": apf_model.returncode == 0 and "200" in apf_model.stdout,
            "other_port_denied": apf_wrong_port.returncode != 0,
            "sandbox_cleanup_confirmed": apf_delete.returncode == 0,
        },
    }
    if not all(evidence["nono"].values()) or not all(evidence["apf_openshell"].values()):
        raise RuntimeError(f"comparator enforcement probes failed: {evidence}")
    (root / "enforcement-probes.json").write_text(json.dumps(evidence, indent=2) + "\n")


def main() -> None:
    parser = argparse.ArgumentParser()
    parser.add_argument("--run-id", required=True)
    parser.add_argument("--repetitions", type=int, default=5)
    parser.add_argument("--smoke", action="store_true")
    parser.add_argument("--nono", type=Path, default=DEFAULT_NONO)
    parser.add_argument("--openshell", type=Path, default=DEFAULT_OPENSHELL)
    parser.add_argument("--openshell-endpoint", default="http://127.0.0.1:18080")
    parser.add_argument("--openshell-image-id", default=DEFAULT_OPENSHELL_IMAGE_ID)
    args = parser.parse_args()
    for executable in (args.nono, args.openshell, APF_EXPORTER):
        if not executable.is_file():
            raise RuntimeError(f"missing comparator executable: {executable}")
    root = V3 / "raw" / args.run_id
    root.mkdir(parents=True, exist_ok=False)
    tasks = json.loads((V1 / "tasks.json").read_text())
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
                "same fixed 15 applications; each comparator enforces every filesystem, "
                "process, and network restriction it can express for the invocation"
            ),
            "residual_comparator_gap": (
                "NoNo and APF/OpenShell do not mediate typed library operations as Cedar "
                "resource/action terminals; APF and NoNo input path grants are "
                "therefore host-resource approximations, not Argus semantic equivalence"
            ),
            "timers": {
                "invocation_ms": "application-reported invocation after application preparation",
                "process_wall_ms": (
                    "parent dispatch through process exit; includes NoNo activation or "
                    "OpenShell exec transport; excludes APF sandbox creation and cleanup"
                ),
                "sandbox_preparation_ms": (
                    "APF projection, fresh sandbox creation, policy admission, and output setup"
                ),
                "end_to_end_wall_ms": (
                    "sandbox preparation plus dispatch/process plus confirmed sandbox deletion"
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
                "audit": "disabled to match final Argus configuration",
                "rollback": "disabled because Argus does not claim rollback",
                "network": "deny by default; direct TCP permitted only on port 11434",
                "network_residual": "the port grant cannot restrict destination host",
                "filesystem": (
                    "code/runtime read-only; exact external inputs read-only; only the fresh "
                    "trial directory writable"
                ),
                "trust_override": False,
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
                "application_image_id": args.openshell_image_id,
                "sandbox_lifecycle": "fresh sandbox per invocation; deletion confirmed",
                "input_binding": (
                    "each projected policy grants only the current invocation's read-only inputs"
                ),
                "policy_source": "permissive-comparators/apf-policy.yaml",
                "policy_source_sha256": sha256(APF_POLICY),
                "projected_policy_sha256": sha256(APF_PROJECTED_POLICY),
                "policy_semantics": (
                    "official APF compiler/OpenShell projector; code/runtime read-only; "
                    "private workspace writable; best-effort Landlock; local model relay only"
                ),
                "audit": "OpenShell defaults retained; not included in application output",
            },
        }
    )
    (root / "configuration.json").write_text(json.dumps(metadata, indent=2) + "\n")
    run_enforcement_probes(
        root,
        nono=args.nono,
        openshell=args.openshell,
        endpoint=args.openshell_endpoint,
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
