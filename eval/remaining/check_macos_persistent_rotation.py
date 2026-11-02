"""Alternate principals and grants around two persistent native Python sessions."""

from __future__ import annotations

import argparse
import gc
import hashlib
import json
import secrets
import sys
from pathlib import Path

CAMPAIGN = Path(__file__).resolve().parents[1] / "campaigns/macos-resubmission-v1"
sys.path.insert(0, str(CAMPAIGN))
import host  # noqa: E402

host.bootstrap()


def main() -> None:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--output", type=Path, required=True)
    args = parser.parse_args()
    if sys.platform != "darwin":
        parser.error("macOS-only session check")
    from langgraph.prebuilt.security import ResourceMediatorAdapter, ResourceSupport, SupportLevel
    from langgraph.prebuilt.security.object_policy import (
        EnforcementKind,
        ObjectGrant,
        ObjectGrantLine,
    )
    from langgraph.prebuilt.security.profile import Requirement
    from langgraph.prebuilt.security.types import Principal, Tool, ToolCall, ToolDac

    output = args.output.resolve()
    output.mkdir(parents=True, exist_ok=False)
    private = output / "private"
    private.mkdir()
    code = output / "code"
    code.mkdir()
    source = code / "attacker.py"
    source.write_text(
        "from langgraph.prebuilt.security.object_broker import object_request\n"
        "def run(selector='session-a', code=''):\n"
        " try: return object_request('session','execute',selector,{'code':code})\n"
        " except PermissionError as error: return {'denied':str(error)}\n"
    )
    markers = {"alice": "ALICE_" + secrets.token_hex(24), "bob": "BOB_" + secrets.token_hex(24)}
    backends = {}
    session_identities = {}
    invocations = []
    dispatcher = None
    results = []
    try:
        for selector in ("session-a", "session-b"):
            directory = private / selector
            directory.mkdir()
            backends[selector] = host.persistent_backend(directory / "chart.png", protected=True)
            pid = backends[selector].process.pid
            session_identities[selector] = (pid, host.identity(pid))

        def assess(line, attestation):
            if line.class_name != "session" or line.operation != "execute":
                return ResourceSupport(SupportLevel.UNSUPPORTED, "unknown session operation")
            return ResourceSupport(
                SupportLevel.EXACT,
                "one persistent interpreter",
                "macos-session-rotation",
                protected_paths=(str(private),),
                required_capabilities=host.isolation_capabilities(),
            )

        def invoke(line, payload, context):
            invocations.append(
                {
                    "principal": context.principal_id,
                    "selector": line.selector,
                    "call": context.call_id,
                }
            )
            return backends[line.selector].execute(payload["code"])

        mediator = ResourceMediatorAdapter("session-rotation-v1", assess, invoke)
        dispatcher = host.dispatcher(code, (mediator,), 30)

        def run(principal_name, permitted, requested, command):
            call_id = secrets.token_hex(12)
            principal = Principal(
                principal_name, frozenset(), frozenset(), principal_name + "-session"
            )
            call = ToolCall(
                Tool("probe", ToolDac("owner", {"*": "x"}), frozenset(), ()),
                {"selector": requested, "code": command},
                {},
                call_id,
                0,
            )
            grant = ObjectGrant(
                principal_name,
                "probe",
                call_id,
                "session-rotation-policy",
                (
                    ObjectGrantLine(
                        "session:0",
                        "session",
                        "execute",
                        permitted,
                        {},
                        Requirement.NEED,
                        EnforcementKind.BROKER,
                    ),
                ),
            )
            value = dispatcher.invoke(principal, call, grant).value
            decoded = json.loads(value) if isinstance(value, str) else value
            results.append(
                {
                    "principal": principal_name,
                    "permitted": permitted,
                    "requested": requested,
                    "result": decoded,
                    "call": call_id,
                }
            )
            return decoded

        alice_file = private / "session-a/temp.txt"
        bob_file = private / "session-b/temp.txt"
        alice_setup = run(
            "alice",
            "session-a",
            "session-a",
            f"SECRET={markers['alice']!r}; HANDLE=open({str(alice_file)!r},'w+'); "
            "HANDLE.write(SECRET); HANDLE.flush(); print(SECRET)",
        )
        assert markers["alice"] in alice_setup["stdout"]
        bob_setup = run(
            "bob",
            "session-b",
            "session-b",
            f"SECRET={markers['bob']!r}; open({str(bob_file)!r},'w').write(SECRET); "
            "print('HANDLE' in globals())",
        )
        assert bob_setup["stdout"].strip() == "False"
        bob_probe = run(
            "bob",
            "session-b",
            "session-b",
            "print('ALICE_SECRET' in globals()); print('HANDLE' in globals())",
        )
        assert bob_probe["stdout"].splitlines() == ["False", "False"]
        bob_direct = run(
            "bob", "session-b", "session-b", f"print(open({str(alice_file)!r}).read())"
        )
        assert "PermissionError" in bob_direct.get("error", "")
        bob_wrong_grant = run("bob", "session-b", "session-a", "print(SECRET)")
        assert "not_granted" in bob_wrong_grant.get("denied", "")
        alice_wrong_grant = run("alice", "session-a", "session-b", "print(SECRET)")
        assert "not_granted" in alice_wrong_grant.get("denied", "")
        alice_resume = run(
            "alice", "session-a", "session-a", "HANDLE.seek(0); print(HANDLE.read()); print(SECRET)"
        )
        assert alice_resume["stdout"].splitlines() == [markers["alice"], markers["alice"]]
        assert alice_file.read_text() == markers["alice"]
        assert bob_file.read_text() == markers["bob"]
        assert not any(
            item["principal"] == "bob" and item["selector"] == "session-a" for item in invocations
        )
    finally:
        for backend in backends.values():
            backend.close()
    live = [pid for pid, identity in session_identities.values() if host.identity(pid) == identity]
    report = {
        "passed": not live,
        "results": results,
        "mediator_invocations": invocations,
        "surviving_sessions": live,
        "artifact_sha256": {
            name: hashlib.sha256((private / name / "temp.txt").read_bytes()).hexdigest()
            for name in ("session-a", "session-b")
        },
        "scope": (
            "object dispatcher plus persistent Python backends; Cedar policy checked separately"
        ),
    }
    (output / "result.json").write_text(json.dumps(report, indent=2) + "\n")
    backends.clear()
    gc.collect()
    print(json.dumps({"passed": report["passed"], "surviving_sessions": live}))
    if not report["passed"]:
        raise SystemExit(1)


if __name__ == "__main__":
    main()
