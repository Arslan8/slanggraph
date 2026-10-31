"""Real admitted graph controller, or explicitly unconfined positive control."""

import argparse
import asyncio
import copy
import json
import secrets
import socketserver
import subprocess
import sys
import threading
import time
from contextlib import suppress
from dataclasses import replace
from pathlib import Path

import host
from specification import MAC_POLICY, POLICY, manifest

from fixtures import Server, rpc

host.bootstrap()


def write(path, value):
    temporary = path.with_suffix(".tmp")
    temporary.write_text(json.dumps(host.plain(value), default=str, indent=2) + "\n")
    temporary.replace(path)


def main():
    parser = argparse.ArgumentParser()
    parser.add_argument("request", type=Path)
    parser.add_argument("--body", action="store_true")
    args = parser.parse_args()
    request = json.loads(args.request.read_text())
    folder = args.request.parent
    task, condition = request["task"], request["condition"]
    case = task["case"]
    sys.path.insert(0, request["code"])
    if args.body:
        import attacker
        from langgraph.prebuilt.security import broker

        broker._pipe_transport = lambda frame: rpc(request["endpoint"], frame)
        print(json.dumps(attacker.run(task)), flush=True)
        return

    sessions = {}
    api = None
    if case.startswith("session_"):
        for name in ("session-a", "session-b"):
            sessions[name] = host.persistent_backend(
                Path(request["private"]) / name / "chart.png", protected=condition == "Argus"
            )
        sessions["session-a"].execute(f"PRIVATE_SESSION_VALUE = {request['session_secret']!r}")
        session_token = request["token"]

        class Handler(socketserver.StreamRequestHandler):
            def handle(self):
                try:
                    frame = json.loads(self.rfile.readline(1_048_577))
                    if not secrets.compare_digest(frame["token"], session_token):
                        raise PermissionError("session connection credential")
                    result = sessions[frame["selector"]].execute(frame["code"])
                    answer = {"status": "ok", "result": result}
                except Exception as error:
                    answer = {"status": "denied", "error": str(error)}
                with suppress(OSError):
                    self.wfile.write(json.dumps(answer).encode() + b"\n")

        api = Server(("127.0.0.1", 0), Handler)
        threading.Thread(target=api.serve_forever, daemon=True).start()
        rpc(
            request["endpoint"],
            {
                "service": '["setup","sessions"]',
                "operation": "register",
                "token": request["token"],
                "payload": {
                    "endpoint": api.server_address,
                    "pids": [
                        {"pid": backend.process.pid, "start": host.identity(backend.process.pid)}
                        for backend in sessions.values()
                    ],
                },
            },
        )

    reports, dispatchers, configs, faults, audits = [], [], [], [], []
    outcome = {"graph_compiled": False, "condition": condition, "case": case}
    stop = threading.Event()

    def snapshot():
        value = {
            "faults": list(faults),
            "stages": list(reports),
            "dispatchers": [],
            "authorization_audits": [host.plain(audit.records()) for audit in audits],
        }
        for dispatcher, config in zip(dispatchers, configs, strict=True):
            value["dispatchers"].append(
                {
                    "type": type(dispatcher).__name__,
                    "authorization_grants": host.plain(config.host_executor.authorization_grants()),
                    "lowering": host.plain(dispatcher.lowering_records())
                    + host.plain(
                        dispatcher.lowering_refusals()
                        if hasattr(dispatcher, "lowering_refusals")
                        else ()
                    ),
                    "broker_audit": host.plain(dispatcher.audit_records()),
                    "receipts": host.plain(dispatcher.activation_receipts())
                    if hasattr(dispatcher, "activation_receipts")
                    else [],
                    "lifecycle": host.plain(dispatcher.lifecycle_records())
                    if hasattr(dispatcher, "lifecycle_records")
                    else [],
                }
            )
        return value

    def heartbeat():
        while not stop.wait(0.2):
            with suppress(Exception):
                write(folder / "evidence-live.json", snapshot())

    threading.Thread(target=heartbeat, daemon=True).start()
    child = None
    try:
        if condition == "Unprotected":
            if case == "old_invocation_reuse":
                first_request = {**request, "task": {**task, "case": "capture_old"}}
                capture_path = folder / "capture-request.json"
                write(capture_path, first_request)
                captured = subprocess.run(
                    [
                        sys.executable,
                        "-u",
                        str(Path(__file__).resolve()),
                        str(capture_path),
                        "--body",
                    ],
                    capture_output=True,
                    text=True,
                    timeout=15,
                    check=True,
                )
                task = {**task, "captured_frame": json.loads(captured.stdout)["frame"]}
                rpc(
                    request["endpoint"],
                    {
                        "service": '["record","notes/alice"]',
                        "operation": "reset",
                        "payload": {},
                        "token": request["token"],
                    },
                )
                request = {**request, "task": task}
                replay_path = folder / "replay-request.json"
                write(replay_path, request)
                args.request = replay_path
            child = subprocess.Popen(
                [sys.executable, "-u", str(Path(__file__).resolve()), str(args.request), "--body"],
                stdout=subprocess.PIPE,
                stderr=subprocess.PIPE,
                text=True,
                start_new_session=True,
            )
            write(
                folder / "body-process.json", {"pid": child.pid, "start": host.identity(child.pid)}
            )
            if case in {"timeout", "cancellation", "session_timeout", "session_cancellation"}:
                time.sleep(3)
                outcome.update(logical_termination_requested=True, termination_confirmed=False)
                return
            stdout, stderr = child.communicate(timeout=45)
            outcome.update(body_returncode=child.returncode, stdout=stdout, stderr=stderr)
            try:
                outcome["result"] = json.loads(stdout)
            except ValueError:
                outcome["result"] = None
            return

        from langchain_core.messages import AIMessage
        from langchain_core.tools import tool
        from langgraph.graph import START, MessagesState, StateGraph
        from langgraph.prebuilt import ToolNode
        from langgraph.prebuilt.security import (
            MemoryAuditSink,
            Principal,
            ResourceMediatorAdapter,
            ResourceSupport,
            SupportLevel,
            cedar_security,
            install_mac_policy,
            with_principal,
        )
        from langgraph.prebuilt.security.admission import describe
        from langgraph.prebuilt.security.lean_lifecycle import LeanLifecycleChecker

        install_mac_policy(MAC_POLICY)
        if case in {"missing_obligation", "altered_obligation"}:
            original = LeanLifecycleChecker.require_grant

            def damaged(self, captured, obligations, **kwargs):
                changed = copy.deepcopy(obligations)
                index = next(i for i, item in enumerate(changed) if item["id"].endswith(":bypass"))
                previous = copy.deepcopy(changed[index])
                if case == "missing_obligation":
                    changed.pop(index)
                else:
                    changed[index]["selector"] = "different-resource"
                faults.append({"kind": case, "original": previous, "submitted": changed})
                return original(self, captured, changed, **kwargs)

            LeanLifecycleChecker.require_grant = damaged

        required = host.isolation_capabilities()

        def assess(line, attestation):
            supported = (
                line.class_name in {"record", "pump", "trace", "session"} and not line.attributes
            )
            return ResourceSupport(
                SupportLevel.EXACT if supported else SupportLevel.UNSUPPORTED,
                "parameterized records, typed device commands, invocation-bound private channel",
                witness="cross-host-security-v1:resource-observer",
                protected_paths=(request["private"],),
                required_capabilities=required,
            )

        def invoke(line, payload, context):
            if context.principal_id != "alice":
                raise PermissionError("resource principal")
            expected = {
                "record": {"read": set(), "write": {"value"}},
                "pump": {"inspect": set(), "set_flow": {"flow"}},
                "trace": {"append": {"event", "pid"}},
                "session": {"execute": {"code"}},
            }
            if (
                line.operation not in expected[line.class_name]
                or set(payload) != expected[line.class_name][line.operation]
            ):
                raise PermissionError("resource command payload")
            return rpc(
                request["endpoint"],
                {
                    "service": json.dumps([line.class_name, line.selector], separators=(",", ":")),
                    "operation": line.operation,
                    "payload": dict(payload),
                    "token": request["token"],
                    "context": host.plain(context),
                },
            )

        mediator = ResourceMediatorAdapter("cross-host-fixtures-v1", assess, invoke)

        def build(narrow=False):
            @tool("narrow" if narrow else "probe")
            def schema(task: dict) -> dict:
                """Execute a deterministic fixture operation in the native worker."""
                raise AssertionError("unconfined schema body executed")

            dispatcher = host.dispatcher(
                request["code"],
                (mediator,),
                3 if case in {"timeout", "cancellation", "controller_termination"} else 40,
            )
            audit = MemoryAuditSink()
            audits.append(audit)
            classes, selected_manifest = manifest(case, host.HOST, narrow=narrow)
            reports.append(
                {"stage": "configuration", "manifest": selected_manifest, "classes": classes}
            )
            config = cedar_security(
                schema,
                manifest=selected_manifest,
                classes=classes,
                policy=POLICY,
                dispatcher=dispatcher,
            )
            config = replace(config, closed_admission=True, audit_sink=audit)
            dispatchers.append(dispatcher)
            configs.append(config)
            builder = StateGraph(MessagesState)
            builder.add_node("tools", ToolNode([schema], security=config))
            builder.add_edge(START, "tools")
            graph = builder.compile(security=config)
            reports.append(
                {
                    "stage": "admission",
                    "descriptors": [describe(item) for item in graph.builder._security_admission],
                }
            )
            outcome["graph_compiled"] = True
            return graph, config, schema.name, dispatcher

        graph, config, name, selected = build()
        if case == "admission_mutation":
            selected.runtime_roots += (Path(request["private"]),)

        def inputs(body, name, config):
            return {
                "messages": [
                    AIMessage(
                        content="",
                        tool_calls=[
                            {
                                "name": name,
                                "args": {"task": body},
                                "id": request["invocation"]
                                + ("-narrow" if name == "narrow" else ""),
                            }
                        ],
                    )
                ]
            }, with_principal(
                {},
                Principal("alice", frozenset(), frozenset(), "security-campaign"),
                modules=config.modules,
            )

        if case == "old_invocation_reuse":
            first, cfg = inputs({**task, "case": "capture_old"}, name, config)
            captured = graph.invoke(first, cfg)["messages"][-1]
            frame = json.loads(captured.content)["frame"]
            rpc(
                request["endpoint"],
                {
                    "service": '["record","notes/alice"]',
                    "operation": "reset",
                    "payload": {},
                    "token": request["token"],
                },
            )
            graph, config, name, selected = build(narrow=True)
            task = {**task, "captured_frame": frame}

        data, principal = inputs(task, name, config)
        if case in {"cancellation", "session_cancellation"}:

            async def cancel():
                operation = asyncio.create_task(graph.ainvoke(data, principal))
                await asyncio.sleep(3)
                operation.cancel()
                try:
                    await operation
                except asyncio.CancelledError:
                    outcome["cancelled"] = True

            asyncio.run(cancel())
        else:
            result = graph.invoke(data, principal)
            message = result["messages"][-1]
            outcome.update(message_status=getattr(message, "status", None), result=message.content)
    except BaseException as error:
        outcome["error"] = {
            "type": type(error).__name__,
            "message": str(error),
            "termination_confirmed": getattr(error, "termination_confirmed", None),
            "receipt": host.plain(getattr(error, "receipt", None)),
        }
    finally:
        stop.set()
        write(folder / "evidence.json", snapshot())
        # Unprotected cleanup controls deliberately demonstrate an orphaned
        # operation. The independent harness kills owned PIDs after observing.
        leave_control = condition == "Unprotected" and case in {
            "timeout",
            "cancellation",
            "session_timeout",
            "session_cancellation",
        }
        if not leave_control:
            for backend in sessions.values():
                try:
                    backend.close()
                except Exception as error:
                    outcome.setdefault("session_close_errors", []).append(str(error))
        write(folder / "outcome.json", outcome)


if __name__ == "__main__":
    main()
