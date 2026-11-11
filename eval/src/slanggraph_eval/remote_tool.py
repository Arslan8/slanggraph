"""Evaluate a toy tool deployed behind a remote HTTP service.

The service is deliberately local and deterministic: this experiment measures the
remote deployment shape without depending on a live third-party system.  The
controller performs the real Cedar authorization, then delegates exactly one
request-bound capability to the service.  The service verifies that capability
before running the tool.
"""

from __future__ import annotations

import argparse
import hashlib
import hmac
import json
import multiprocessing
import threading
import time
import urllib.error
import urllib.request
import uuid
from dataclasses import dataclass, field
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from pathlib import Path
from typing import Any

from langchain_core.messages import AIMessage
from langchain_core.tools import tool
from langgraph.graph import START, MessagesState, StateGraph
from langgraph.prebuilt import ToolNode
from langgraph.prebuilt.security import (
    ActivationReceipt,
    EnforcementKind,
    EnforcementMode,
    HostExecutionDenied,
    HostExecutionResult,
    ObjectClass,
    ObjectGrant,
    ObjectGrantLine,
    Principal,
    RuleEnforcement,
    SupportLevel,
    cedar_security,
    with_principal,
)

CLASSES = """class remote_weather {
  operations invoke
  object city
  normalizer identity
  attrs
  enforced_by broker
  lowering toy.http.hmac.v1
}"""
MANIFEST = """runs broker
remote_weather invoke @{city} need
returns normal"""
POLICY = """permit(
  principal == slangGraph::User::"alice",
  action == slangGraph::Action::"remote_weather::invoke",
  resource
) when { resource.selector == "paris" };"""


def _canonical(value: dict[str, Any]) -> bytes:
    return json.dumps(value, sort_keys=True, separators=(",", ":")).encode()


@dataclass
class _ServiceState:
    secret: bytes
    requests: list[dict[str, Any]] = field(default_factory=list)
    used_nonces: set[str] = field(default_factory=set)
    lock: threading.Lock = field(default_factory=threading.Lock)


def _handler(state: _ServiceState) -> type[BaseHTTPRequestHandler]:
    class Handler(BaseHTTPRequestHandler):
        def do_GET(self) -> None:  # noqa: N802
            if self.path != "/control/observations":
                self._reply(404, {"error": "not_found"})
                return
            with state.lock:
                self._reply(200, {"remote_executions": len(state.requests)})

        def do_POST(self) -> None:  # noqa: N802
            if self.path == "/control/shutdown":
                self._reply(200, {"ok": True})
                threading.Thread(target=self.server.shutdown, daemon=True).start()
                return
            if self.path != "/tools/weather/invoke":
                self._reply(404, {"error": "not_found"})
                return
            try:
                length = int(self.headers.get("Content-Length", "0"))
                envelope = json.loads(self.rfile.read(length))
                body = envelope["body"]
                signature = envelope["signature"]
                expected = hmac.new(state.secret, _canonical(body), hashlib.sha256).hexdigest()
                if not hmac.compare_digest(signature, expected):
                    raise PermissionError("invalid_signature")
                if set(body) != {
                    "args",
                    "call_id",
                    "grant_digest",
                    "line",
                    "nonce",
                    "principal",
                    "tool",
                }:
                    raise PermissionError("invalid_scope")
                line = body["line"]
                if (
                    body["principal"] != "alice"
                    or body["tool"] != "remote_weather"
                    or set(body["args"]) != {"city"}
                    or line["class"] != "remote_weather"
                    or line["operation"] != "invoke"
                    or line["selector"] != body["args"]["city"]
                ):
                    raise PermissionError("invalid_scope")
                with state.lock:
                    if body["nonce"] in state.used_nonces:
                        self._reply(409, {"error": "replayed_capability"})
                        return
                    state.used_nonces.add(body["nonce"])
                    state.requests.append(body)
                self._reply(
                    200,
                    {
                        "city": body["args"]["city"],
                        "forecast": "clear",
                        "source": "toy-remote-weather-v1",
                    },
                )
            except (KeyError, TypeError, ValueError, PermissionError) as exc:
                self._reply(401, {"error": str(exc)})

        def _reply(self, status: int, value: dict[str, Any]) -> None:
            payload = json.dumps(value, sort_keys=True).encode()
            self.send_response(status)
            self.send_header("Content-Type", "application/json")
            self.send_header("Content-Length", str(len(payload)))
            self.end_headers()
            self.wfile.write(payload)

        def log_message(self, *args: Any) -> None:
            return

    return Handler


def _serve(secret: bytes, connection: Any) -> None:
    """Run the toy tool service in a separate process."""
    state = _ServiceState(secret)
    server = ThreadingHTTPServer(("127.0.0.1", 0), _handler(state))
    connection.send(server.server_port)
    connection.close()
    try:
        server.serve_forever()
    finally:
        server.server_close()


class RemoteToolDispatcher:
    """Evaluation-only dispatcher for a request-scoped HTTP tool call."""

    enforcer_id = "toy-remote-http-v1"

    def __init__(self, endpoint: str, secret: bytes) -> None:
        self.endpoint = endpoint
        self.secret = secret
        self.envelopes: list[dict[str, Any]] = []

    def supports(self, object_class: ObjectClass, line: ObjectGrantLine) -> bool:
        return (
            object_class.name == "remote_weather"
            and object_class.enforced_by is EnforcementKind.BROKER
            and line.operation == "invoke"
            and line.lowering == "toy.http.hmac.v1"
        )

    def validate_tools(self, tool_names: list[str] | tuple[str, ...]) -> None:
        if set(tool_names) != {"remote_weather"}:
            raise ValueError("toy remote dispatcher only implements remote_weather")

    def invoke(self, principal: Principal, call: Any, grant: ObjectGrant) -> HostExecutionResult:
        if (
            grant.principal_id != principal.user_id
            or grant.tool_name != call.tool.name
            or grant.call_id != call.call_id
            or len(grant.lines) != 1
        ):
            raise HostExecutionDenied("toy_remote:grant_binding")
        line = grant.lines[0]
        body = {
            "args": dict(call.args),
            "call_id": call.call_id,
            "grant_digest": grant.digest,
            "line": {
                "class": line.class_name,
                "operation": line.operation,
                "selector": line.selector,
            },
            "nonce": uuid.uuid4().hex,
            "principal": principal.user_id,
            "tool": call.tool.name,
        }
        envelope = {
            "body": body,
            "signature": hmac.new(self.secret, _canonical(body), hashlib.sha256).hexdigest(),
        }
        self.envelopes.append(envelope)
        request = urllib.request.Request(
            self.endpoint,
            data=_canonical(envelope),
            headers={"Content-Type": "application/json"},
            method="POST",
        )
        try:
            with urllib.request.urlopen(request, timeout=2) as response:
                result = json.load(response)
        except (OSError, urllib.error.HTTPError) as exc:
            raise HostExecutionDenied(f"toy_remote:{type(exc).__name__}") from exc
        receipt = ActivationReceipt(
            grant_digest=grant.digest,
            plan_digest="toy-remote-http-plan-v1",
            host_digest="toy-remote-service",
            context_digest=hashlib.sha256(_canonical(body)).hexdigest(),
            nonce=body["nonce"],
            mode=EnforcementMode.ENFORCED,
            evidence=(),
            activated_obligations=frozenset(),
            valid_until=time.time() + 60,
            rule_enforcement=(RuleEnforcement(line.line_id, SupportLevel.EXACT, self.enforcer_id),),
        )
        return HostExecutionResult(result, receipt)

    async def ainvoke(
        self, principal: Principal, call: Any, grant: ObjectGrant
    ) -> HostExecutionResult:
        return self.invoke(principal, call, grant)

    def confirm_termination(self, recovery: Any) -> bool:
        return True


@tool("remote_weather")
def remote_weather(city: str) -> dict[str, str]:
    """Get a deterministic forecast from the toy remote weather service."""
    raise RuntimeError("the remote tool has no in-process implementation")


def _post(endpoint: str, envelope: dict[str, Any]) -> tuple[int, dict[str, Any]]:
    request = urllib.request.Request(
        endpoint,
        data=_canonical(envelope),
        headers={"Content-Type": "application/json"},
        method="POST",
    )
    try:
        with urllib.request.urlopen(request, timeout=2) as response:
            return response.status, json.load(response)
    except urllib.error.HTTPError as exc:
        return exc.code, json.load(exc)


def _invoke(graph: Any, principal: str, city: str, call_id: str) -> Any:
    config = with_principal(
        {}, Principal(principal, frozenset(), frozenset(), "toy-remote-session")
    )
    result = graph.invoke(
        {
            "messages": [
                AIMessage(
                    content="",
                    tool_calls=[
                        {
                            "name": "remote_weather",
                            "args": {"city": city},
                            "id": call_id,
                            "type": "tool_call",
                        }
                    ],
                )
            ]
        },
        config=config,
    )
    return result["messages"][-1]


def _observations(service_url: str) -> int:
    with urllib.request.urlopen(service_url + "/control/observations", timeout=2) as response:
        return int(json.load(response)["remote_executions"])


def run(output: Path) -> dict[str, Any]:
    """Run the deterministic remote-deployment cases and retain their evidence."""
    output.mkdir(parents=True, exist_ok=False)
    secret = hashlib.sha256(b"argus-toy-remote-tool-v1").digest()
    context = multiprocessing.get_context("spawn")
    parent_connection, child_connection = context.Pipe()
    process = context.Process(target=_serve, args=(secret, child_connection))
    process.start()
    child_connection.close()
    port = parent_connection.recv()
    parent_connection.close()
    service_url = f"http://127.0.0.1:{port}"
    endpoint = service_url + "/tools/weather/invoke"
    dispatcher = RemoteToolDispatcher(endpoint, secret)
    security = cedar_security(
        remote_weather,
        classes=CLASSES,
        manifest=MANIFEST,
        policy=POLICY,
        dispatcher=dispatcher,
    )
    builder = StateGraph(MessagesState)
    builder.add_node("tools", ToolNode([remote_weather], security=security))
    builder.add_edge(START, "tools")
    graph = builder.compile(security=security)
    trials: list[dict[str, Any]] = []
    try:
        for case_id, principal, city, should_allow in (
            ("allowed_remote_call", "alice", "paris", True),
            ("denied_principal", "bob", "paris", False),
            ("denied_selector", "alice", "berlin", False),
        ):
            before = _observations(service_url)
            result = None
            error = None
            try:
                message = _invoke(graph, principal, city, f"{case_id}-call")
                if getattr(message, "status", "success") == "error":
                    error = {"type": "ToolMessageError", "message": str(message.content)}
                else:
                    result = json.loads(message.content)
            except Exception as exc:
                error = {"type": type(exc).__name__, "message": str(exc)}
            after = _observations(service_url)
            trials.append(
                {
                    "case_id": case_id,
                    "principal": principal,
                    "city": city,
                    "allowed": error is None,
                    "expected_allowed": should_allow,
                    "remote_executions": after - before,
                    "result": result,
                    "error": error,
                }
            )

        allowed_envelope = dispatcher.envelopes[0]
        before = _observations(service_url)
        status, response = _post(endpoint, allowed_envelope)
        after = _observations(service_url)
        trials.append(
            {
                "case_id": "replayed_capability",
                "allowed": status == 200,
                "expected_allowed": False,
                "remote_executions": after - before,
                "http_status": status,
                "result": response,
            }
        )
        tampered = json.loads(json.dumps(allowed_envelope))
        tampered["body"]["args"]["city"] = "berlin"
        before = _observations(service_url)
        status, response = _post(endpoint, tampered)
        after = _observations(service_url)
        trials.append(
            {
                "case_id": "tampered_arguments",
                "allowed": status == 200,
                "expected_allowed": False,
                "remote_executions": after - before,
                "http_status": status,
                "result": response,
            }
        )
    finally:
        try:
            _post(service_url + "/control/shutdown", {})
        finally:
            process.join(5)
            if process.is_alive():
                process.terminate()
                process.join(5)

    passed = all(row["allowed"] == row["expected_allowed"] for row in trials)
    remote_executions = sum(row["remote_executions"] for row in trials)
    passed = passed and remote_executions == 1 and process.exitcode == 0
    summary = {
        "passed": passed,
        "deployment": "toy remote HTTP service",
        "live_external_system": False,
        "cases": len(trials),
        "allowed_cases": sum(row["allowed"] for row in trials),
        "remote_executions": remote_executions,
        "separate_service_process": process.pid != multiprocessing.current_process().pid,
        "service_process_exitcode": process.exitcode,
        "scope": (
            "call authorization and request-bound delegation only; the remote service "
            "and its tool implementation are trusted and not locally confined"
        ),
    }
    (output / "plan.json").write_text(
        json.dumps(
            {
                "classes": CLASSES,
                "manifest": MANIFEST,
                "policy": POLICY,
                "cases": [row["case_id"] for row in trials],
                "transport": "loopback HTTP to a separate service process",
                "external_dependencies": [],
                "evaluator_sha256": hashlib.sha256(Path(__file__).read_bytes()).hexdigest(),
            },
            indent=2,
            sort_keys=True,
        )
        + "\n"
    )
    (output / "trials.jsonl").write_text(
        "".join(json.dumps(row, sort_keys=True) + "\n" for row in trials)
    )
    (output / "summary.json").write_text(json.dumps(summary, indent=2, sort_keys=True) + "\n")
    return summary


def main() -> None:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--output", type=Path, required=True)
    args = parser.parse_args()
    summary = run(args.output)
    print(json.dumps(summary, indent=2, sort_keys=True))
    if not summary["passed"]:
        raise SystemExit(1)


if __name__ == "__main__":
    main()
