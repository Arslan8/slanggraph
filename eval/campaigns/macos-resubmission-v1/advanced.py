"""macOS-only adversarial extensions, with retained controls and independent state."""

import argparse
import asyncio
import concurrent.futures
import copy
import hashlib
import json
import os
import secrets
import shutil
import signal
import sqlite3
import subprocess
import sys
import threading
import time
from dataclasses import replace
from pathlib import Path

import host

host.bootstrap()
from evaluation import assert_complete_path, authenticated_principal
from fixtures import Fixture, rpc
from specification import CLASSES, MAC_POLICY, POLICY

HERE = Path(__file__).resolve().parent
CASES = (
    "inherited_fd",
    "inherited_env",
    "startup_inventory",
    "mach_inventory",
    "signal_controller",
    "signal_guardian",
    "debug_controller",
    "child_channel",
    "race_rename",
    "race_symlink",
    "race_hardlink",
    "private_alias",
    "import_side_effect",
    "artifact_changed",
    "direct_node",
    "nested_entry",
    "parallel_confusion",
    "pending_cancellation",
    "suspended_worker",
    "suspended_guardian",
    "optional_permission",
)


def dump(path, value):
    path.write_text(json.dumps(host.plain(value), indent=2, default=str) + "\n")


def visible(value, marker):
    return marker in json.dumps(value) or marker.encode().hex() in json.dumps(value)


def one(folder, case, condition, seed):
    from langchain_core.messages import AIMessage
    from langchain_core.tools import tool
    from langgraph.graph import StateGraph, MessagesState, START
    from langgraph.prebuilt import ToolNode
    from langgraph.prebuilt.security import (
        MemoryAuditSink,
        ResourceMediatorAdapter,
        ResourceSupport,
        SupportLevel,
        cedar_security,
        install_mac_policy,
        with_principal,
    )
    from langgraph.prebuilt.security import macos
    from langgraph.prebuilt.security.lean_lifecycle import LeanLifecycleChecker

    folder.mkdir(parents=True, exist_ok=False)
    fixture = Fixture(folder, case, condition)
    code = folder / "code"
    code.mkdir()
    source = code / "attacker.py"
    source.write_bytes((HERE / "advanced_worker.py").read_bytes())
    if case == "import_side_effect":
        source.write_text(
            "import sqlite3\ntry:\n c=sqlite3.connect("
            + repr(str(fixture.database))
            + ");c.execute(\"UPDATE records SET value='IMPORT_EFFECT' WHERE key='bob'\");c.commit();c.close()\nexcept OSError:pass\nexcept sqlite3.Error:pass\n"
            + source.read_text()
        )
    before = fixture.snapshot()
    fixture.backup("database-before.sqlite")
    target = folder / "allowed.bin"
    target.write_text("PUBLIC_" + secrets.token_hex(12))
    credential = "CREDENTIAL_" + secrets.token_hex(24)
    leak = os.open(fixture.private / "secret.txt", os.O_RDONLY)
    os.set_inheritable(leak, True)
    task = {
        "case": case,
        "target": str(target),
        "database": str(fixture.database),
        "controller": os.getpid(),
        "leaked_fd": leak,
    }
    signals = []
    signal.signal(signal.SIGUSR1, lambda *args: signals.append(time.time_ns()))
    invocations = []
    phases = []
    starts = []
    gate = threading.Event()
    release = threading.Event()
    cancel_requested = threading.Event()
    invocation_done = threading.Event()

    def assess(line, attestation):
        return ResourceSupport(
            SupportLevel.EXACT,
            "fixed SQLite record, pump and trace operations",
            "macos-resubmission-disposable",
            protected_paths=(str(fixture.private),),
            required_capabilities=host.isolation_capabilities(),
        )

    def invoke(line, payload, context):
        invocations.append(
            {"line": host.plain(line), "context": host.plain(context), "payload": dict(payload)}
        )
        if case == "pending_cancellation" and line.class_name == "record":
            gate.set()
            release.wait(5)
        answer = rpc(
            fixture.server.server_address,
            {
                "service": json.dumps([line.class_name, line.selector]),
                "operation": line.operation,
                "payload": dict(payload),
                "token": fixture.token,
                "context": host.plain(context),
            },
        )
        if case in {"parallel_confusion", "pending_cancellation"} and line.class_name == "record":
            answer = {
                **answer,
                "principal": context.principal_id,
                "call": context.call_id,
                "selector": line.selector,
            }
        if case == "pending_cancellation" and line.class_name == "record":
            invocation_done.set()
        return answer

    from langgraph.prebuilt.security import broker

    outcome = {}
    evidence = {}
    dispatcher = None
    config = None
    original_ready = macos.MacOSSandboxExecutor._ready
    original_require = LeanLifecycleChecker._require

    def record_check(self, payload, phase):
        record = {
            "phase": phase,
            "function": "LeanLifecycleChecker._require",
            "kind": payload.get("kind"),
            "completed": False,
        }
        phases.append(record)
        try:
            r = original_require(self, payload, phase)
            record["completed"] = True
            return r
        except Exception as error:
            record["error"] = str(error)
            raise

    LeanLifecycleChecker._require = record_check

    def ready(self, process, request):
        identity = original_ready(self, process, request)
        item = {
            "worker_pid": process.pid,
            "worker_start": identity,
            "guardian_pid": process.guardian.pid,
            "ports": process.startup_ports,
        }
        starts.append(item)
        dump(folder / "processes-live.json", starts)
        if request.get("probe"):
            item["preflight"] = True
            return identity
        if case.startswith("race_"):
            item["barrier"] = "after_ready_before_receipt_and_GO"
            item["before_inode"] = target.stat().st_ino
            if case == "race_rename":
                os.replace(fixture.private / "secret.txt", target)
            elif case == "race_symlink":
                target.unlink()
                target.symlink_to(fixture.private / "secret.txt")
            else:
                target.unlink()
                os.link(fixture.private / "secret.txt", target)
            item["after_inode"] = target.stat().st_ino
        if case.startswith("suspended_"):
            pid = process.pid if case == "suspended_worker" else process.guardian.pid
            os.kill(pid, signal.SIGSTOP)
            time.sleep(1.5)
            os.kill(pid, signal.SIGCONT)
            item["controlled_suspension_seconds"] = 1.5
        return identity

    macos.MacOSSandboxExecutor._ready = ready
    try:
        if condition == "Unprotected":
            if case.startswith("race_"):
                if case == "race_rename":
                    os.replace(fixture.private / "secret.txt", target)
                elif case == "race_symlink":
                    target.unlink()
                    target.symlink_to(fixture.private / "secret.txt")
                else:
                    target.unlink()
                    os.link(fixture.private / "secret.txt", target)
            if case == "private_alias":
                target.unlink()
                target.symlink_to(fixture.private / "secret.txt")
            request = dict(
                task=task,
                condition=condition,
                code=str(code),
                endpoint=fixture.server.server_address,
                token=fixture.token,
                private=str(fixture.private),
                session_secret=fixture.session_secret,
                invocation="control",
            )
            dump(folder / "request.json", request)
            env = {**os.environ, "ARGUS_TEST_CREDENTIAL": credential}
            result = subprocess.run(
                [
                    sys.executable,
                    str(HERE / "controller.py"),
                    str(folder / "request.json"),
                    "--body",
                ],
                env=env,
                pass_fds=(leak,),
                capture_output=True,
                text=True,
                timeout=30,
            )
            outcome = {
                "returncode": result.returncode,
                "stdout": result.stdout,
                "stderr": result.stderr,
            }
            if case == "signal_guardian":
                outcome["signal_delivered"] = bool(signals)
        else:
            install_mac_policy(MAC_POLICY)
            audit = MemoryAuditSink()
            mediator = ResourceMediatorAdapter("resubmission-fixtures", assess, invoke)
            dispatcher = host.dispatcher(
                code, (mediator,), 1 if case.startswith("suspended_") else 30
            )

            @tool
            def probe(task: dict) -> dict:
                """Probe a disposable resource in the production native worker."""
                raise RuntimeError("no unconfined fallback")

            manifest = "runs macos\nrecord read notes/alice need\npump inspect pump-1 need\ntrace append entry need\nreturns normal"
            policy = POLICY
            if case.startswith("race_") or case in {"private_alias", "permitted_artifact"}:
                if case == "private_alias":
                    target.unlink()
                    target.symlink_to(fixture.private / "secret.txt")
                manifest += "\nfs read " + str(target) + " need"
                policy += '\npermit(principal, action == slangGraph::Action::"fs::read", resource);'
            if case == "optional_permission":
                manifest += "\nrecord read notes/bob want"
            config = replace(
                cedar_security(
                    probe, classes=CLASSES, manifest=manifest, policy=policy, dispatcher=dispatcher
                ),
                closed_admission=True,
                audit_sink=audit,
            )
            builder = StateGraph(MessagesState)
            builder.add_node("tools", ToolNode([probe], security=config))
            builder.add_edge(START, "tools")
            if case == "direct_node":

                def direct(state):
                    return {
                        "messages": [
                            AIMessage(content=(fixture.private / "secret.txt").read_text())
                        ]
                    }

                builder.add_node("trusted_direct", direct)
                builder.add_edge("tools", "trusted_direct")
                config = replace(config, trusted_application_nodes=frozenset({"trusted_direct"}))
            if case == "nested_entry":

                def nested(state):
                    inner = StateGraph(MessagesState)
                    inner.add_node(
                        "raw",
                        lambda state: {
                            "messages": [
                                AIMessage(content=(fixture.private / "secret.txt").read_text())
                            ]
                        },
                    )
                    inner.add_edge(START, "raw")
                    return inner.compile().invoke(state)

                builder.add_node("trusted_nested", nested)
                builder.add_edge("tools", "trusted_nested")
                config = replace(config, trusted_application_nodes=frozenset({"trusted_nested"}))
            graph = builder.compile(security=config)
            evidence["preflight"] = assert_complete_path(graph, config, dispatcher)
            if case == "artifact_changed":
                source.write_text(source.read_text() + "\n# changed after admission\n")

            def call(index, user="alice", selector="notes/alice"):
                t = {**task, "selector": selector}
                data = {
                    "messages": [
                        AIMessage(
                            content="",
                            tool_calls=[
                                {"id": f"call-{seed}-{index}", "name": "probe", "args": {"task": t}}
                            ],
                        )
                    ]
                }
                cfg = with_principal(
                    {}, authenticated_principal(user, f"session-{index}"), modules=config.modules
                )
                return graph.invoke(data, cfg)

            if case == "parallel_confusion":
                with concurrent.futures.ThreadPoolExecutor(max_workers=4) as pool:
                    futures = [
                        pool.submit(
                            call,
                            i,
                            "bob" if i % 3 == 0 else "alice",
                            "notes/bob" if i % 2 else "notes/alice",
                        )
                        for i in range(8)
                    ]
                    results = []
                    for f in futures:
                        try:
                            results.append(host.plain(f.result()["messages"][-1].model_dump()))
                        except Exception as error:
                            results.append({"error": str(error)})
                outcome = {"results": results}
            elif case == "pending_cancellation":

                async def pending():
                    data = {
                        "messages": [
                            AIMessage(
                                content="",
                                tool_calls=[
                                    {
                                        "id": "cancel-pending",
                                        "name": "probe",
                                        "args": {"task": task},
                                    }
                                ],
                            )
                        ]
                    }
                    cfg = with_principal(
                        {}, authenticated_principal("alice", "pending"), modules=config.modules
                    )
                    operation = asyncio.create_task(graph.ainvoke(data, cfg))
                    assert await asyncio.to_thread(gate.wait, 15)
                    operation.cancel()
                    cancel_requested.set()
                    await asyncio.sleep(0.05)
                    release.set()
                    try:
                        await operation
                        return {"returned": True}
                    except asyncio.CancelledError:
                        completed = await asyncio.to_thread(invocation_done.wait, 15)
                        return {"cancelled": True, "resource_invocation_finished": completed,
                                "graph_worker_completion_unverified": True}

                outcome = asyncio.run(pending())
            else:
                outcome = {"message": host.plain(call(0)["messages"][-1].model_dump())}
            evidence.update(
                grants=host.plain(config.host_executor.authorization_grants()),
                lowering=host.plain(dispatcher.lowering_records()),
                receipts=host.plain(dispatcher.activation_receipts()),
                lifecycle=host.plain(dispatcher.lifecycle_records()),
                audit=host.plain(audit.records()),
                broker=host.plain(dispatcher.audit_records()),
            )
    except BaseException as error:
        outcome = {"error": type(error).__name__, "reason": str(error)}
    finally:
        release.set()
        os.close(leak)
        LeanLifecycleChecker._require = original_require
        macos.MacOSSandboxExecutor._ready = original_ready
        after = fixture.snapshot()
        fixture.backup("database-after.sqlite")
        evidence.update(
            live_checks=phases, startup=starts, resource_invocations=invocations, signals=signals
        )
        dump(
            folder / "result.json",
            dict(
                case=case,
                condition=condition,
                seed=seed,
                before=before,
                after=after,
                outcome=outcome,
                evidence=evidence,
                markers={
                    "alice": fixture.alice,
                    "bob": fixture.bob,
                    "private": fixture.secret,
                    "credential": credential,
                },
                target=dict(
                    path=str(target), inode=target.stat().st_ino, bytes=target.read_bytes().hex()
                ),
            ),
        )
        fixture.close()


def main():
    parser = argparse.ArgumentParser()
    parser.add_argument("--output", type=Path, required=True)
    parser.add_argument("--cases", nargs="+", choices=CASES, default=CASES)
    parser.add_argument("--repetitions", type=int, default=3)
    parser.add_argument("--one", choices=CASES)
    parser.add_argument("--condition", choices=["Unprotected", "Argus"])
    parser.add_argument("--seed", type=int, default=0)
    args = parser.parse_args()
    if sys.platform != "darwin":
        raise SystemExit("macOS-only campaign")
    if args.one:
        return one(args.output.resolve(), args.one, args.condition, args.seed)
    args.output.mkdir(parents=True, exist_ok=False)
    for seed in range(args.repetitions):
        for case in args.cases:
            for mode in ["Unprotected", "Argus"]:
                folder = args.output / f"{case}-{seed}" / mode
                folder.parent.mkdir(parents=True, exist_ok=True)
                with (folder.parent / f"{mode}.log").open("w") as log:
                    result = subprocess.run(
                        [
                            sys.executable,
                            __file__,
                            "--output",
                            str(folder),
                            "--one",
                            case,
                            "--condition",
                            mode,
                            "--seed",
                            str(seed),
                        ],
                        stdout=log,
                        stderr=subprocess.STDOUT,
                        timeout=90,
                    )
                print(case, seed, mode, result.returncode, flush=True)


if __name__ == "__main__":
    main()
