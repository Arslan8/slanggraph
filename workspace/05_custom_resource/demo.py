"""Example 5: authorize device operations independently of socket access.

Start `simulator.py` in this directory in another terminal before running this file.
Tool code runs in a Landlock/seccomp worker. Only the parent-owned
`PumpSocketAdapter` can contact the device; the broker checks every request
against the exact Cedar-authorized object grant.
"""

from __future__ import annotations

import argparse
import hashlib
import json
import socket
import sys
from dataclasses import dataclass
from pathlib import Path
from typing import Any

from langchain_core.messages import AIMessage
from langchain_core.tools import tool
from langgraph.graph import START, MessagesState, StateGraph

from langgraph.prebuilt import ToolNode
from langgraph.prebuilt.security import (
    CedarObjectAuthorizer,
    CedarPolicySet,
    DacOverrides,
    Effect,
    EnforcementKind,
    HostExecutionDenied,
    ObjectPolicyHostExecutor,
    Principal,
    ResourceArg,
    ResourceMediatorAdapter,
    ResourceSupport,
    SecurityConfig,
    SupportLevel,
    ToolDac,
    effects,
    parse_security_manifest,
    with_principal,
)
from langgraph.prebuilt.security.linux import LinuxToolSpec
from langgraph.prebuilt.security.object_broker import ObjectBrokerDispatcher

DEVICE_ID = "pump-1"
OPERATIONS = frozenset({"inspect", "start", "stop", "set_flow", "calibrate"})
PRINCIPAL_OPERATIONS = {
    "alice": frozenset({"inspect", "start", "stop", "set_flow"}),
    "bob": frozenset({"inspect", "calibrate"}),
    "charlie": frozenset({"inspect"}),
}
# This table is only a review display for the example. Cedar policy below is
# authoritative; the integration test keeps the displayed coverage and actual
# decisions aligned.

# This is an SLP object-class declaration, not Cedar policy. It extends the
# manifest vocabulary and causes slangGraph to generate the corresponding Cedar
# actions and resource entity type used by the policy below.
CLASSES = """
class pump {
  # The complete set of operations manifests may request for this class.
  operations inspect start stop set_flow calibrate

  # The kind of resource named by a selector such as "pump-1". Together with
  # the class name, this produces the Cedar entity type PumpDevice.
  object device

  # Convert a raw selector into its canonical identity. "identity" is safe here
  # because pump IDs are already canonical; production classes can register a
  # trusted domain-specific normalizer instead.
  normalizer identity

  # Resource attributes exposed to Cedar policies. This demo needs none, so the
  # list is empty; a real device class might declare site, owner, or risk_level.
  attrs

  # The parent broker enforces the exact grant. Isolated tool code cannot
  # contact the device socket directly.
  enforced_by broker
  lowering pump.socket.v1
}
"""

# `map` is a closed dispatch table. The argument selects among fixed manifest
# lines; it never becomes a Cedar action, entity type, or policy fragment.
MANIFEST = """
runs linux
map operation=inspect   pump inspect   @{device_id} need
map operation=start     pump start     @{device_id} need
map operation=stop      pump stop      @{device_id} need
map operation=set_flow  pump set_flow  @{device_id} need
map operation=calibrate pump calibrate @{device_id} need
returns sensitive
"""

POLICY = """
// There is deliberately no caller-side Action::"call" permit here. For this
// resource-bearing tool, permission to invoke is derived from whether the
// selected manifest operation is authorized for the principal.

// Alice: inspect, start, stop, and set flow.
permit (
  principal == slangGraph::User::"alice",
  action in [
    slangGraph::Action::"pump::inspect",
    slangGraph::Action::"pump::start",
    slangGraph::Action::"pump::stop",
    slangGraph::Action::"pump::set_flow"
  ],
  resource
) when {
  resource.selector == "pump-1"
};

// Bob: inspect and calibrate.
permit (
  principal == slangGraph::User::"bob",
  action in [
    slangGraph::Action::"pump::inspect",
    slangGraph::Action::"pump::calibrate"
  ],
  resource
) when {
  resource.selector == "pump-1"
};

// Charlie: inspect only.
permit (
  principal == slangGraph::User::"charlie",
  action == slangGraph::Action::"pump::inspect",
  resource
) when {
  resource.selector == "pump-1"
};
"""


class PumpSocketAdapter:
    """Trusted adapter that validates and sends an authorized pump command."""

    def __init__(self, socket_path: Path) -> None:
        self.socket_path = socket_path

    def execute(
        self, device_id: str, operation: str, value: float | None
    ) -> dict[str, Any]:
        # These checks defend the adapter even though the manifest already uses
        # a fixed action map and Cedar restricts the resource to pump-1.
        if device_id != DEVICE_ID:
            raise ValueError(f"unknown device: {device_id}")
        if operation not in OPERATIONS:
            raise ValueError(f"unknown operation: {operation}")
        if operation in {"inspect", "start", "stop"} and value is not None:
            raise ValueError(f"{operation} does not accept a value")
        if operation == "set_flow":
            value = _bounded_number(value, "flow rate", 0.0, 100.0)
        elif operation == "calibrate":
            value = _bounded_number(value, "calibration offset", -10.0, 10.0)

        request = {
            "device_id": device_id,
            "operation": operation,
            "value": value,
        }
        try:
            with socket.socket(socket.AF_UNIX, socket.SOCK_STREAM) as connection:
                connection.settimeout(3.0)
                connection.connect(str(self.socket_path))
                connection.sendall((json.dumps(request) + "\n").encode())
                response = _read_json_line(connection)
        except OSError as exc:
            raise RuntimeError(
                f"cannot reach pump simulator at {self.socket_path}"
            ) from exc
        if response.get("ok") is not True:
            raise RuntimeError(f"pump rejected command: {response.get('error')}")
        return response


def _bounded_number(
    value: float | None, label: str, minimum: float, maximum: float
) -> float:
    if type(value) not in {int, float}:
        raise ValueError(f"{label} requires a numeric value")
    numeric = float(value)
    if not minimum <= numeric <= maximum:
        raise ValueError(f"{label} must be between {minimum:g} and {maximum:g}")
    return numeric


def _read_json_line(connection: socket.socket) -> dict[str, Any]:
    chunks = bytearray()
    while not chunks.endswith(b"\n"):
        chunk = connection.recv(4096)
        if not chunk:
            raise RuntimeError("pump simulator closed the connection")
        chunks.extend(chunk)
        if len(chunks) > 64 * 1024:
            raise RuntimeError("pump simulator response is too large")
    response = json.loads(chunks)
    if not isinstance(response, dict):
        raise TypeError("pump simulator returned a non-object response")
    return response


@dataclass(frozen=True)
class InvocationResult:
    allowed: bool
    dispatched: bool
    operation: str
    response: dict[str, Any] | None


def build_demo(socket_path: Path, cedar: str) -> tuple[Any, Any]:
    """Build the graph and security configuration around one trusted adapter."""
    adapter = PumpSocketAdapter(socket_path)

    @tool
    @effects(
        Effect.WRITE,
        resources=[ResourceArg("device_id", "pump")],
        sensitivity="critical",
    )
    def control_pump(
        device_id: str, operation: str, value: float | None = None
    ) -> dict[str, Any]:
        """Perform one operation on a simulated pump."""
        raise RuntimeError("tool must execute in the confined worker")

    worker_path = Path(__file__).with_name("worker.py").resolve()

    def assess(line, host):
        if (
            line.class_name != "pump"
            or line.enforcer is not EnforcementKind.BROKER
            or line.selector != DEVICE_ID
            or line.operation not in OPERATIONS
            or line.attributes
            or line.lowering != "pump.socket.v1"
        ):
            return ResourceSupport(
                SupportLevel.UNSUPPORTED, "unsupported pump semantics"
            )
        return ResourceSupport(
            SupportLevel.EXACT,
            "fixed pump identity and operation; payload validated by PumpSocketAdapter",
            witness="tests/security/test_pump_example.py",
            protected_paths=(str(socket_path.resolve()),),
            required_capabilities=frozenset({"broker:spawn-bound", "seccomp:minimal"}),
        )

    def dispatch(line, payload, context):
        if set(payload) != {"value"}:
            raise ValueError("unexpected pump payload fields")
        try:
            return adapter.execute(line.selector, line.operation, payload["value"])
        except ValueError as exc:
            # Explicit public validation response, not arbitrary broker exceptions.
            return {"ok": False, "error": str(exc)}

    dispatcher = ObjectBrokerDispatcher(
        {
            "control_pump": LinuxToolSpec(
                "pump_worker:control_pump",
                worker_path,
                hashlib.sha256(worker_path.read_bytes()).hexdigest(),
            )
        },
        mediators=(ResourceMediatorAdapter("pump.socket.v1", assess, dispatch),),
        # These are trusted code roots. Never include credential directories.
        runtime_roots=tuple(
            Path(path).resolve() for path in sys.path if path and Path(path).is_dir()
        ),
    )
    manifest = parse_security_manifest(
        CLASSES + "\ntool control_pump {\n" + MANIFEST + "\n}",
        enforcers={EnforcementKind.BROKER: dispatcher},
    )
    owner_policy = 'permit(principal, action == slangGraph::Action::"call", resource == slangGraph::Tool::"control_pump");\n'
    owner_policy += "\n".join(
        f'permit(principal, action == slangGraph::Action::"pump::{operation}", resource) '
        'when { context.tool == slangGraph::Tool::"control_pump" };'
        for operation in sorted(OPERATIONS)
    )
    authorizer = CedarObjectAuthorizer(
        manifest,
        CedarPolicySet({"control_pump": owner_policy}, POLICY),
        executable=cedar,
        # This diagnostics demo prints and inspects every Cedar input bundle.
        # Production invocation paths leave artifact retention disabled.
        retain_authorization_artifacts=True,
    )
    security = SecurityConfig(
        host_executor=ObjectPolicyHostExecutor(
            authorizer,
            dispatcher,
            tool_owners={"control_pump": "application"},
        ),
        dac_overrides=DacOverrides({"control_pump": ToolDac("__cedar__", {"*": "x"})}),
    )
    builder = StateGraph(MessagesState)
    builder.add_node("tools", ToolNode([control_pump]))
    builder.add_edge(START, "tools")
    return builder.compile(security=security), security


def invoke(
    graph: Any,
    security: Any,
    principal_id: str,
    operation: str,
    value: float | None,
    call_number: int,
) -> InvocationResult:
    """Invoke once and print the complete derivation and decision."""
    allowed_operations = PRINCIPAL_OPERATIONS.get(principal_id, frozenset())
    if allowed_operations == OPERATIONS:
        coverage = "full"
    elif allowed_operations.isdisjoint(OPERATIONS):
        coverage = "none"
    else:
        coverage = "partial"
    principal = Principal(principal_id, frozenset(), frozenset(), "demo-session")
    config = with_principal({}, principal, modules=security.modules)
    executor = security.host_executor
    assert isinstance(executor, ObjectPolicyHostExecutor)
    grants_before = len(executor.authorization_grants())
    artifacts_before = len(executor.authorizer.authorization_artifacts())

    print(f"\nPrincipal: {principal_id}")
    print(
        f"Manifest coverage: {coverage} "
        f"({len(allowed_operations)}/{len(OPERATIONS)} operations)"
    )
    print(f"Request: device={DEVICE_ID} operation={operation} value={value!r}")
    if operation in OPERATIONS:
        print(
            f'Derived: action=slangGraph::Action::"pump::{operation}" '
            f"resource={DEVICE_ID}"
        )
    else:
        print("Derived: rejected; operation is not in the manifest's closed map")

    message = None
    dispatch_error: str | None = None
    try:
        result = graph.invoke(
            {
                "messages": [
                    AIMessage(
                        content="",
                        tool_calls=[
                            {
                                "name": "control_pump",
                                "args": {
                                    "device_id": DEVICE_ID,
                                    "operation": operation,
                                    "value": value,
                                },
                                "id": f"call-{call_number}",
                            }
                        ],
                    )
                ]
            },
            config=config,
        )
        message = result["messages"][-1]
        if getattr(message, "status", None) != "error":
            device_result = json.loads(str(message.content))
            if device_result.get("ok") is False:
                dispatch_error = device_result.get("error", "adapter rejected request")
    except HostExecutionDenied as exc:
        # A manifest or Cedar denial happens before a grant exists.
        dispatch_error = str(exc)
    except ValueError as exc:
        # The operation was authorized, but trusted-adapter validation rejected
        # malformed device data before it could reach the socket.
        dispatch_error = str(exc)
    grants = executor.authorization_grants()
    allowed = len(grants) > grants_before
    dispatched = (
        allowed
        and dispatch_error is None
        and message is not None
        and getattr(message, "status", None) != "error"
    )
    print(f"Authorization: {'ALLOW' if allowed else 'DENY'}")
    if allowed:
        grant = grants[-1]
        for line in grant.lines:
            print(
                f"Surviving grant: {line.class_name}::{line.operation} {line.selector}"
            )
    else:
        print("Surviving grant: none")

    response: dict[str, Any] | None = None
    if dispatched:
        assert message is not None
        response = json.loads(str(message.content))
        print(f"Device response: {json.dumps(response, sort_keys=True)}")
    elif allowed:
        detail = dispatch_error or getattr(message, "content", "unknown error")
        print(f"Dispatch rejected: {detail}")
    else:
        print("Device response: not dispatched")

    artifacts = executor.authorizer.authorization_artifacts()
    if len(artifacts) > artifacts_before:
        print(f"Cedar artifacts: {artifacts[-1]}")
    return InvocationResult(allowed, dispatched, operation, response)


def run_automated_demo(graph: Any, security: Any, log_path: Path) -> None:
    """Exercise the permission matrix and prove denials never reached the pump."""
    before = _read_log(log_path)
    cases = [
        ("alice", "set_flow", 25.0, True, True),
        ("alice", "calibrate", 1.5, False, False),
        ("bob", "calibrate", 1.5, True, True),
        ("bob", "start", None, False, False),
        ("charlie", "inspect", None, True, True),
        ("charlie", "stop", None, False, False),
        # No manifest-operation coverage means immediate pre-dispatch denial.
        ("mallory", "inspect", None, False, False),
        # Input validation is a separate gate after operation authorization.
        ("alice", "set_flow", 1000.0, True, False),
        # This string cannot become a Cedar action because it is not mapped.
        ("alice", "pump::calibrate", 1.0, False, False),
    ]
    for number, (
        principal,
        operation,
        value,
        expected_allowed,
        expected_dispatched,
    ) in enumerate(cases, 1):
        result = invoke(graph, security, principal, operation, value, number)
        assert result.allowed is expected_allowed
        assert result.dispatched is expected_dispatched

    new_entries = _read_log(log_path)[len(before) :]
    assert [entry["operation"] for entry in new_entries] == [
        "set_flow",
        "calibrate",
        "inspect",
    ]
    final_state = new_entries[-1]["after"]
    assert final_state == {
        "running": False,
        "flow_rate": 25.0,
        "calibration_offset": 1.5,
    }
    print("\nAutomated assertions passed:")
    print("  denied commands created no simulator log entries")
    print("  denied commands caused no pump state changes")
    print("  set_flow and calibrate used the same socket but different permissions")


def _read_log(path: Path) -> list[dict[str, Any]]:
    if not path.exists():
        return []
    return [json.loads(line) for line in path.read_text(encoding="utf-8").splitlines()]


def run_interactive(graph: Any, security: Any) -> None:
    print("Principal selection is a demo substitute for real authentication.")
    principal = input("Principal [alice, bob, charlie, or mallory]: ").strip().lower()
    print("Commands: inspect, start, stop, set_flow NUMBER, calibrate NUMBER")
    print("Also: principal NAME, help, quit")
    call_number = 1
    while True:
        raw = input(f"pump({principal})> ").strip()
        if not raw:
            continue
        if raw in {"quit", "exit"}:
            return
        if raw == "help":
            print("inspect | start | stop | set_flow NUMBER | calibrate NUMBER")
            continue
        if raw.startswith("principal "):
            principal = raw.split(maxsplit=1)[1].strip().lower()
            continue
        words = raw.split()
        operation = words[0]
        if len(words) > 2:
            print("Rejected: expected OPERATION [NUMBER]")
            continue
        try:
            value = float(words[1]) if len(words) == 2 else None
        except ValueError:
            print("Rejected: value must be numeric")
            continue
        invoke(graph, security, principal, operation, value, call_number)
        call_number += 1


def main() -> None:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument(
        "--socket", type=Path, default=Path("/tmp/slanggraph-pump.sock")
    )
    parser.add_argument(
        "--log", type=Path, default=Path("/tmp/slanggraph-pump-commands.jsonl")
    )
    parser.add_argument("--cedar", default="cedar")
    parser.add_argument("--demo", action="store_true")
    args = parser.parse_args()
    graph, security = build_demo(args.socket, args.cedar)
    if args.demo:
        run_automated_demo(graph, security, args.log)
    else:
        run_interactive(graph, security)


if __name__ == "__main__":
    main()
