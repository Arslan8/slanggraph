"""Source-bound native macOS component campaign, separate from Linux headline results.

Run with the prebuilt venv: python eval/remaining/macos_portability_campaign.py
--output NEW_DIRECTORY [--pilot]. Each session executes in a fresh controller.
"""

from __future__ import annotations

import argparse
import dataclasses
import enum
import hashlib
import importlib.metadata
import importlib.util
import json
import os
import platform
import socket
import subprocess
import sys
import time
from collections.abc import Mapping
from contextlib import contextmanager
from dataclasses import replace
from datetime import UTC, datetime
from pathlib import Path
from unittest.mock import patch

from langgraph.prebuilt.security import (
    ForbidConstraint,
    MacOSNativeLauncher,
    MacOSSandboxExecutor,
    MacOSToolSpec,
    Principal,
    RulePredicate,
    SqliteAuditSink,
    ToolCall,
    Verdict,
    parse_profiles,
)
from langgraph.prebuilt.security import macos as native
from langgraph.prebuilt.security.enforcement import (
    AuthorityDomain,
    Grant,
    GrantRule,
    compile_obligations,
)
from langgraph.prebuilt.security.execution import HostExecutionDenied, HostExecutionError
from langgraph.prebuilt.security.types import AuditRecord, Tool, ToolDac

ROOT = Path(__file__).resolve().parents[2]
HERE = Path(__file__).resolve().parent
WORKER = HERE / "macos_portability_worker.py"
UTILITY = {"left": 17, "right": 24, "sum": 41, "equal": False}
PHASES = ("first_use", "warmup", "measured")
ATTACKS = (
    "allowed_exact",
    "denied_exact",
    "alias_allowed",
    "alias_denied",
    "symlink_escape",
    "hardlink_inside",
    "hardlink_outside",
    "write",
    "fork",
    "raw_fork",
    "spawn",
    "exec",
    "network",
    "signal",
    "descriptors",
    "cpu",
    "wall",
    "policy_forbid",
    "wrong_principal",
    "artifact_changed",
    "unsupported_minimal",
    "nonfinite_frame",
    "receipt_grant",
    "receipt_context",
    "receipt_nonce",
    "receipt_coverage",
)


def plain(value):
    if isinstance(value, enum.Enum):
        return value.value
    if dataclasses.is_dataclass(value):
        return {
            field.name: plain(getattr(value, field.name)) for field in dataclasses.fields(value)
        }
    if isinstance(value, Mapping):
        return {key: plain(item) for key, item in value.items()}
    if isinstance(value, (tuple, list)):
        return [plain(item) for item in value]
    if isinstance(value, (set, frozenset)):
        return sorted(plain(item) for item in value)
    if value is None or type(value) in {str, int, float, bool}:
        return value
    raise TypeError(type(value).__name__)


def dump(path, value):
    path.write_text(json.dumps(plain(value), sort_keys=True, indent=2, allow_nan=False) + "\n")


def append(stream, row):
    stream.write(json.dumps(plain(row), sort_keys=True, allow_nan=False) + "\n")
    stream.flush()


def sha(path):
    return hashlib.sha256(path.read_bytes()).hexdigest()


def source_inventory():
    files = {Path(__file__), WORKER, HERE / "verify_macos_portability.py"}
    for library in ("prebuilt", "langgraph", "checkpoint"):
        files.update((ROOT / "libs" / library / "langgraph").rglob("*.py"))
    files.update((ROOT / "libs/prebuilt/langgraph/prebuilt/security/native").glob("*.c"))
    files.update((ROOT / "proofs/worker-route").glob("*.lean"))
    files.add(ROOT / "libs/prebuilt/uv.lock")
    files.update((ROOT / "libs/prebuilt/tests/security").rglob("*.py"))
    files.add(ROOT / "eval/tests/test_macos_portability.py")
    return {str(path.relative_to(ROOT)): sha(path) for path in sorted(files)}


def archive_sources(output, inventory):
    (output / "sources").mkdir()
    for name, digest in inventory.items():
        (output / "sources" / digest).write_bytes((ROOT / name).read_bytes())


def launcher_from(output):
    value = json.loads((output / "native/manifest.json").read_text())
    return MacOSNativeLauncher(
        Path(value["launcher"]),
        value["launcher_digest"],
        Path(value["library"]),
        value["library_digest"],
        Path(value["stdlib"]),
        Path(value["dynload"]),
    )


def profiles(public, *, minimal=False):
    text = f"""tool read_pair {{
 owner reader
 grant reader: call
 runs macos
 fs read {public}/** need
}}
principal alice {{
 roles reader
 fs read {public}/**
}}"""
    document = parse_profiles(text, source="macos-evaluation.slp")
    if not minimal:
        document = replace(
            document,
            tools={"read_pair": replace(document.tools["read_pair"], syscall_sets=frozenset())},
        )
    return document, text


def call(session, call_id, args, index=0):
    return Principal("alice", frozenset({"reader"}), frozenset(), session), ToolCall(
        Tool("read_pair", ToolDac("reader", {"reader": "x"}), frozenset(), ()),
        args,
        {},
        call_id,
        index,
    )


def build_executor(output, folder, *, limits=None, minimal=False, artifact=None):
    document, text = profiles(output / "fixture/public", minimal=minimal)
    source = artifact or output / "fixture/worker.py"
    return MacOSSandboxExecutor(
        document,
        {"read_pair": MacOSToolSpec("campaign_worker:run", source, sha(source))},
        launcher=launcher_from(output),
        experimental=True,
        recovery_directory=folder / "recovery",
        default_limits=limits,
    ), text


def load_worker(output):
    spec = importlib.util.spec_from_file_location(
        "unconfined_control_worker", output / "fixture/worker.py"
    )
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module.run


class Trace:
    """Observer wrappers delegate to unchanged production functions."""

    def __init__(self, executor, sink=None):
        self.executor, self.sink = executor, sink
        self.row = None

    @contextmanager
    def observe(self):
        original_run = self.executor._run
        original_arm = self.executor._arm
        original_ready = self.executor._ready
        original_validate = self.executor._coordinator.validate_receipt
        original_reap = native._reap
        original_clear = self.executor._clear_recovery
        original_frame = native._read_frame

        def run(request, grant, host, plan):
            self.row.update(
                run_started_ns=time.perf_counter_ns(),
                grant=plain(grant),
                grant_digest=grant.digest,
                plan=plain(plan),
                plan_digest=plan.digest,
                host=plain(host),
            )
            return original_run(request, grant, host, plan)

        def arm(process):
            value = original_arm(process)
            self.row["go_ns"] = time.perf_counter_ns()
            return value

        def ready(process, request):
            identity = original_ready(process, request)
            self.row.update(
                worker_pid=process.pid,
                worker_start=identity,
                guardian_pid=process.guardian.pid,
                startup_ports=plain(process.startup_ports),
            )
            return identity

        def validate(receipt, grant, plan, host, context):
            accepted = original_validate(receipt, grant, plan, host, context)
            self.row.update(
                receipt=plain(receipt.canonical()),
                receipt_validated=accepted,
                context=plain(context),
            )
            if accepted and self.sink:
                started = time.perf_counter_ns()
                self.sink.write(
                    AuditRecord(
                        self.row["index"],
                        grant.tool_name,
                        grant.principal_id,
                        grant.normalized_intent_digest,
                        "activation",
                        "macos-component-evaluation",
                        Verdict.ALLOW,
                        receipt.audit_reason(),
                        session_id=grant.session_id,
                    )
                )
                self.row["audit_ns"] += time.perf_counter_ns() - started
            return accepted

        def reap(process):
            started = time.perf_counter_ns()
            confirmed = original_reap(process)
            self.row["cleanup_ns"] += time.perf_counter_ns() - started
            self.row["cleanup_confirmed"] = confirmed
            return confirmed

        def clear(recovery):
            started = time.perf_counter_ns()
            try:
                return original_clear(recovery)
            finally:
                self.row["cleanup_ns"] += time.perf_counter_ns() - started

        def frame(process, timeout):
            try:
                value = original_frame(process, timeout)
            except Exception as exc:
                if self.row.get("go_ns") and hasattr(process, "guardian"):
                    self.row.update(
                        result_received_ns=time.perf_counter_ns(), protocol_error=type(exc).__name__
                    )
                raise
            if value.get("status") == "error":
                self.row["worker_error_type"] = value.get("error_type")
            if value.get("status") == "reaped":
                self.row["wait_status"] = value["wait_status"]
            elif self.row.get("go_ns") and hasattr(process, "guardian"):
                self.row["result_received_ns"] = time.perf_counter_ns()
            return value

        with (
            patch.object(self.executor, "_run", run),
            patch.object(self.executor, "_arm", arm),
            patch.object(self.executor, "_ready", ready),
            patch.object(self.executor._coordinator, "validate_receipt", validate),
            patch.object(native, "_reap", reap),
            patch.object(self.executor, "_clear_recovery", clear),
            patch.object(native, "_read_frame", frame),
        ):
            yield

    def invoke(self, session, call_id, args, index=0, constraints=(), principal=None):
        p, request = call(session, call_id, args, index)
        self.row = {
            "call_id": call_id,
            "index": index,
            "audit_ns": 0,
            "cleanup_ns": 0,
            "receipt_validated": False,
            "cleanup_confirmed": False,
        }
        started = time.perf_counter_ns()
        with self.observe():
            try:
                result = self.executor.invoke(principal or p, request, constraints)
                self.row.update(status="success", value=plain(result.value))
            except (HostExecutionDenied, HostExecutionError) as exc:
                self.row.update(
                    status="refusal" if isinstance(exc, HostExecutionDenied) else "execution_error",
                    error={"type": type(exc).__name__, "reason": str(exc)},
                    termination_confirmed=getattr(exc, "termination_confirmed", None),
                )
            except Exception as exc:
                self.row.update(
                    status="activation_failure",
                    error={"type": type(exc).__name__, "reason": str(exc)},
                )
        self.row["elapsed_ms"] = (time.perf_counter_ns() - started) / 1e6
        run_start = self.row.get("run_started_ns", time.perf_counter_ns())
        go = self.row.get("go_ns", run_start)
        received = self.row.get("result_received_ns", go)
        phases = {
            "preparation_authorization_negotiation_ms": (run_start - started) / 1e6,
            "activation_ms": (go - run_start - self.row["audit_ns"]) / 1e6,
            "execution_ms": (received - go) / 1e6,
            "audit_ms": self.row["audit_ns"] / 1e6,
            "cleanup_ms": self.row["cleanup_ns"] / 1e6,
        }
        self.row.update(
            phases=phases, framework_residual_ms=self.row["elapsed_ms"] - sum(phases.values())
        )
        if "worker_pid" in self.row:
            self.row["worker_absent"] = (
                native._process_identity(self.row["worker_pid"]) != self.row["worker_start"]
            )
        self.row["recovery_records"] = len(list(self.executor.recovery_directory.glob("*.json")))
        self.row["unresolved"] = len(self.executor.unresolved_terminations())
        return self.row


def session(output, number, config):
    folder = output / f"session-{number}"
    folder.mkdir()
    started = time.perf_counter_ns()
    executor, text = build_executor(output, folder)
    setup_ms = (time.perf_counter_ns() - started) / 1e6
    sink = SqliteAuditSink(folder / "audit.sqlite")
    observer = Trace(executor, sink)
    direct = load_worker(output)
    args = {
        "left": str(output / "fixture/public/left"),
        "right": str(output / "fixture/public/right"),
    }
    with (folder / "trials.jsonl").open("x") as stream:
        append(
            stream,
            {
                "kind": "setup",
                "session": number,
                "pid": os.getpid(),
                "executor_setup_ms": setup_ms,
                "profile": text,
                "profile_syscall_override": "empty syscall set through immutable profile type",
                "closed_admission": False,
                "lean": None,
                "cedar": None,
                "cpu_affinity": None,
            },
        )
        for index in range(1 + config["warmups"] + config["measured"]):
            phase = (
                "first_use"
                if index == 0
                else "warmup"
                if index <= config["warmups"]
                else "measured"
            )
            row = observer.invoke(
                f"session-{number}", f"session-{number}-call-{index}", args, index
            )
            row.update(
                kind="call", route="macos-native-typed-audited-pilot", session=number, phase=phase
            )
            row["valid"] = (
                row["status"] == "success"
                and row["value"] == UTILITY
                and row["receipt_validated"]
                and row["cleanup_confirmed"]
                and row["worker_absent"]
                and row["recovery_records"] == 0
            )
            append(stream, row)
            begin = time.perf_counter_ns()
            value = direct(**args)
            append(
                stream,
                {
                    "kind": "call",
                    "route": "direct-primitive",
                    "session": number,
                    "phase": phase,
                    "index": index,
                    "call_id": row["call_id"],
                    "elapsed_ms": (time.perf_counter_ns() - begin) / 1e6,
                    "value": value,
                    "valid": value == UTILITY,
                },
            )
    dump(folder / "audit-records.json", sink.records())
    dump(
        folder / "audit-verification.json", {"chain": sink.verify(), "records": len(sink.records())}
    )
    sink.close()


def attack_matrix(output, config):
    direct = load_worker(output)
    folder = output / "attacks"
    folder.mkdir()
    public = output / "fixture/public"
    secret = output / "fixture/secret"
    (public / "escape").symlink_to(secret)
    os.link(secret, public / "hardlink-inside")
    os.link(public / "left", output / "fixture/hardlink-outside")
    base = {"left": str(public / "left"), "right": str(public / "right")}
    with (folder / "trials.jsonl").open("x") as stream:
        for repeat in range(config["sessions"]):
            for case in ATTACKS:
                case_folder = folder / f"{repeat}-{case}"
                case_folder.mkdir()
                limits = {
                    "cpu_ms": 1000,
                    "nofile": 64,
                    "wall_ms": 5000 if case == "cpu" else 100 if case == "wall" else 3000,
                }
                artifact = None
                if case == "artifact_changed":
                    artifact = case_folder / "worker.py"
                    artifact.write_bytes((output / "fixture/worker.py").read_bytes())
                executor, _ = build_executor(
                    output,
                    case_folder,
                    limits=limits,
                    minimal=case == "unsupported_minimal",
                    artifact=artifact,
                )
                observer = Trace(executor)
                if case == "unsupported_minimal":
                    clean, _ = build_executor(
                        output, case_folder / "positive-control", limits=limits
                    )
                    control = Trace(clean).invoke("attacks", f"control-{repeat}-{case}", base)
                else:
                    control = observer.invoke("attacks", f"control-{repeat}-{case}", base)
                args = dict(base)
                target = secret
                operation = "read"
                if case in {"allowed_exact", "alias_allowed"}:
                    target = public / "left"
                if case.startswith("alias_"):
                    target = Path(str(target).removeprefix("/private"))
                if case == "symlink_escape":
                    target = public / "escape"
                if case == "hardlink_inside":
                    target = public / "hardlink-inside"
                if case == "hardlink_outside":
                    target = output / "fixture/hardlink-outside"
                if case in {
                    "write",
                    "fork",
                    "raw_fork",
                    "spawn",
                    "exec",
                    "network",
                    "signal",
                    "descriptors",
                    "cpu",
                    "nonfinite_frame",
                }:
                    operation = case
                if case == "wall":
                    operation = "sleep"
                args.update(operation=operation, target=str(target))
                listener = None
                if case == "network":
                    listener = socket.socket()
                    listener.bind(("127.0.0.1", 0))
                    listener.listen(2)
                    listener.settimeout(1)
                    args["port"] = listener.getsockname()[1]
                if case == "signal":
                    args["port"] = os.getpid()
                direct_control = None
                if case not in {
                    "policy_forbid",
                    "wrong_principal",
                    "artifact_changed",
                    "unsupported_minimal",
                    "nonfinite_frame",
                } and not case.startswith("receipt_"):
                    if case == "exec":
                        completed = subprocess.run(
                            ["/usr/bin/true"], check=False, capture_output=True
                        )
                        direct_control = {"exec_returncode": completed.returncode}
                    else:
                        before = secret.read_text()
                        direct_control = direct(**args)
                        if case == "write":
                            secret.write_text(before)
                    if listener:
                        connection, _ = listener.accept()
                        connection.close()
                constraints = ()
                principal = None
                if case == "policy_forbid":
                    constraints = (
                        ForbidConstraint(
                            "deny-fs",
                            RulePredicate(domain="filesystem"),
                            "campaign restriction",
                            module="campaign-policy",
                        ),
                    )
                if case == "wrong_principal":
                    principal = Principal("mallory", frozenset({"reader"}), frozenset(), "attacks")
                if case == "artifact_changed":
                    artifact.write_text("raise RuntimeError('substituted')\n")
                if case.startswith("receipt_"):
                    validate = executor._coordinator.validate_receipt

                    def corrupted(receipt, *rest, _case=case, _validate=validate, **kwargs):
                        field, value = {
                            "receipt_grant": ("grant_digest", "0" * 64),
                            "receipt_context": ("context_digest", "0" * 64),
                            "receipt_nonce": ("nonce", "wrong"),
                            "receipt_coverage": ("activated_obligations", frozenset()),
                        }[_case]
                        return _validate(replace(receipt, **{field: value}), *rest, **kwargs)

                    executor._coordinator.validate_receipt = corrupted
                result = observer.invoke(
                    "attacks",
                    f"attack-{repeat}-{case}",
                    args,
                    constraints=constraints,
                    principal=principal,
                )
                connected_after = False
                if listener:
                    listener.settimeout(0.03)
                    try:
                        connection, _ = listener.accept()
                        connection.close()
                        connected_after = True
                    except TimeoutError:
                        pass
                    listener.close()
                append(
                    stream,
                    {
                        "case": case,
                        "repeat": repeat,
                        "control": control,
                        "direct_control": direct_control,
                        "trial": result,
                        "network_effect": connected_after,
                        "fixture_after": {
                            "left": (public / "left").read_text(),
                            "right": (public / "right").read_text(),
                            "secret": secret.read_text(),
                        },
                    },
                )


def census(output):
    executor, _ = build_executor(output, output / "census")
    cases = [
        GrantRule(
            "read",
            AuthorityDomain.FILESYSTEM,
            "read",
            str(output / "fixture/public/left"),
            {"subtree": False},
        ),
        GrantRule(
            "write",
            AuthorityDomain.FILESYSTEM,
            "write",
            str(output / "fixture/public/left"),
            {"subtree": False},
        ),
        GrantRule("syscalls", AuthorityDomain.PROCESS, "syscall_set", "minimal"),
        GrantRule(
            "memory", AuthorityDomain.RESOURCE_LIMIT, "limit", "memory_bytes", {"maximum": 1048576}
        ),
        GrantRule("network", AuthorityDomain.NETWORK, "connect", "443", {"protocol": "tcp"}),
        GrantRule("cpu", AuthorityDomain.RESOURCE_LIMIT, "limit", "cpu_ms", {"maximum": 1000}),
        GrantRule(
            "fractional_cpu", AuthorityDomain.RESOURCE_LIMIT, "limit", "cpu_ms", {"maximum": 1500}
        ),
        GrantRule(
            "descriptors", AuthorityDomain.RESOURCE_LIMIT, "limit", "nofile", {"maximum": 64}
        ),
        GrantRule("wall", AuthorityDomain.RESOURCE_LIMIT, "limit", "wall_ms", {"maximum": 1000}),
        GrantRule("delegation", AuthorityDomain.DELEGATION, "delegate", "child"),
        GrantRule("service", AuthorityDomain.SERVICE, "invoke", "http"),
        GrantRule(
            "exclusion",
            AuthorityDomain.FILESYSTEM,
            "read",
            str(output / "fixture/public"),
            {"subtree": True, "exclude_paths": (str(output / "fixture/public/left"),)},
        ),
    ]
    grant = Grant(
        "alice",
        "census",
        "read_pair",
        sha(output / "fixture/worker.py"),
        "census-call",
        "intent",
        "policy",
        tuple(cases),
    )
    obligations = compile_obligations(grant)
    dump(
        output / "lowering-census.json",
        [
            {"obligation": plain(item), "assessment": plain(assessment)}
            for item, assessment in zip(obligations, executor.assess_grant(grant), strict=True)
        ],
    )


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--output", type=Path, required=True)
    parser.add_argument("--pilot", action="store_true")
    parser.add_argument("--session", type=int)
    args = parser.parse_args()
    output = args.output.resolve()
    if args.session is not None:
        session(output, args.session, json.loads((output / "plan.json").read_text()))
        return
    output.mkdir(parents=True, exist_ok=False)
    config = {
        "schema_version": 1,
        "pilot": args.pilot,
        "sessions": 1 if args.pilot else 5,
        "warmups": 1 if args.pilot else 10,
        "measured": 2 if args.pilot else 20,
        "attacks": list(ATTACKS),
        "utility": UTILITY,
        "scope": (
            "experimental native component; not closed/admitted, "
            "Cedar/Lean certified, or an LLM application"
        ),
        "comparison": "paired direct primitive; ratios are not application overhead",
        "instrumentation": (
            "controller observation wrappers delegate to original functions; overhead is included"
        ),
        "phase_boundary": (
            "preparation includes profile evaluation, grant compilation, typed mandatory policy "
            "and negotiation; activation excludes separately measured durable audit; execution "
            "begins at guardian ARM acknowledgement before GO write; cleanup includes guardian "
            "reaping and recovery-ledger fsync"
        ),
        "linux_execution": "not_run_this_host",
        "lean": "blocked: Linux-only memfd transport; no lake installed",
        "pandas": "not_run: dependencies absent and closed/native-extension route unqualified",
        "cpu_affinity": "uncontrolled; macOS session processes not CPU-pinned",
        "started_utc": datetime.now(UTC).isoformat(),
    }
    dump(output / "plan.json", config)
    before = source_inventory()
    archive_sources(output, before)
    dump(output / "source-before.json", before)
    revision = subprocess.run(
        ["/Library/Developer/CommandLineTools/usr/bin/git", "rev-parse", "HEAD"],
        cwd=ROOT,
        capture_output=True,
        text=True,
        check=True,
    ).stdout.strip()
    dump(
        output / "host.json",
        {
            "base_revision": revision,
            "dirty_source_snapshot": True,
            "platform": platform.platform(),
            "machine": platform.machine(),
            "os_build": native._sysctl_text("kern.osversion"),
            "cpu": native._sysctl_text("machdep.cpu.brand_string"),
            "python": sys.version,
            "executable": sys.executable,
            "packages": sorted(
                (distribution.metadata["Name"], distribution.version)
                for distribution in importlib.metadata.distributions()
            ),
        },
    )
    fixture = output / "fixture"
    (fixture / "public").mkdir(parents=True)
    (fixture / "public/left").write_text("17")
    (fixture / "public/right").write_text("24")
    (fixture / "secret").write_text("PRIVATE_CANARY")
    (fixture / "worker.py").write_bytes(WORKER.read_bytes())
    start = time.perf_counter_ns()
    MacOSNativeLauncher.build(output / "native")
    dump(
        output / "native-build.json",
        {
            "elapsed_ms": (time.perf_counter_ns() - start) / 1e6,
            "launcher": json.loads((output / "native/manifest.json").read_text()),
        },
    )
    gate_paths = [
        "libs/prebuilt/tests/security/test_macos_execution.py",
        "libs/prebuilt/tests/security/test_enforcement.py",
        "libs/prebuilt/tests/security/test_profile.py",
        "libs/prebuilt/tests/security/test_host_router.py",
        "libs/prebuilt/tests/security/test_lean_grant.py",
        "libs/prebuilt/tests/security/test_admission.py",
        "eval/tests/test_macos_portability.py",
    ]
    command = [
        sys.executable,
        "-m",
        "pytest",
        "-q",
        *gate_paths,
        "--junitxml",
        str(output / "gates.xml"),
    ]
    completed = subprocess.run(
        command, cwd=ROOT, capture_output=True, text=True, timeout=240, check=False
    )
    (output / "gates.stdout").write_text(completed.stdout)
    (output / "gates.stderr").write_text(completed.stderr)
    dump(output / "gates.json", {"command": command, "returncode": completed.returncode})
    with (output / "session-processes.jsonl").open("x") as processes:
        for number in range(config["sessions"]):
            completed = subprocess.run(
                [
                    sys.executable,
                    str(Path(__file__).resolve()),
                    "--output",
                    str(output),
                    "--session",
                    str(number),
                ],
                cwd=ROOT,
                capture_output=True,
                text=True,
                timeout=180,
                check=False,
            )
            (output / f"session-{number}.stdout").write_text(completed.stdout)
            (output / f"session-{number}.stderr").write_text(completed.stderr)
            append(processes, {"session": number, "returncode": completed.returncode})
    attack_matrix(output, config)
    census(output)
    dump(output / "source-after.json", source_inventory())
    print(str(output))


if __name__ == "__main__":
    main()
