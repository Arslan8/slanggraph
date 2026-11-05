"""Verify the repaired production translator against the real Cedar CLI.

Run with libs/prebuilt/.venv/bin/python from the repository root.
No production functions are replaced or mocked. Cedar must be installed.
"""

from __future__ import annotations

import argparse
import hashlib
import json
import shutil
import subprocess
from pathlib import Path

from langgraph.prebuilt.security import Principal
from langgraph.prebuilt.security import object_policy as op

MANIFEST = """class record {
  operations read
  object item
  normalizer identity
  attrs owner
  enforced_by broker
}
tool lookup {
  runs broker
  record read public need
  returns normal
}
"""
PERMIT = "permit(principal, action, resource);"


class Broker:
    """Support witness only: this experiment does not execute a tool."""

    enforcer_id = "translation-counterexample"

    def supports(self, object_class, line):
        return object_class.enforced_by is op.EnforcementKind.BROKER


def run(command):
    result = subprocess.run(
        command, capture_output=True, text=True, timeout=60, check=False
    )
    return {
        "returncode": result.returncode,
        "stdout": result.stdout,
        "stderr": result.stderr,
    }


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--output", type=Path, required=True)
    args = parser.parse_args()
    cedar = shutil.which("cedar")
    if cedar is None:
        raise SystemExit("Real Cedar CLI is required")
    output = args.output.resolve()
    output.mkdir(parents=True, exist_ok=True)
    manifest = op.parse_security_manifest(
        MANIFEST, enforcers={op.EnforcementKind.BROKER: Broker()}
    )
    source = Path(op.__file__).resolve()
    expected_source = Path(__file__).resolve().parents[2] / (
        "libs/prebuilt/langgraph/prebuilt/security/object_policy.py"
    )
    if source != expected_source:
        raise SystemExit(
            f"Expected repository implementation {expected_source}, got {source}"
        )
    evidence = {
        "source_sha256": hashlib.sha256(source.read_bytes()).hexdigest(),
        "cedar_version": run([cedar, "--version"]),
        "manifest": MANIFEST,
        "cases": [],
    }
    for principal in ("alice", "josé", "jose\u0301", "使用者", "😀"):
        # Check that the authenticated identity type accepts this principal.
        Principal(principal, frozenset(), frozenset(), "proof-session")
        authorizer = op.CedarObjectAuthorizer(
            manifest,
            op.CedarPolicySet({"lookup": PERMIT}, PERMIT),
            executable=cedar,
            retain_authorization_artifacts=True,
        )
        case = {"principal": principal}
        try:
            grant = authorizer.authorize(
                principal_id=principal,
                roles=(),
                tool_name="lookup",
                tool_owner="owner",
                call_id="translation-counterexample",
                arguments={},
            )
            case["outcome"] = "ALLOW"
            case["lines"] = [dict(line.canonical()) for line in grant.lines]
        except op.ObjectPolicyDenied as exc:
            case["outcome"] = "ERROR"
            case["error"] = str(exc)
        case_dir = output / principal
        shutil.copytree(
            authorizer.authorization_artifacts()[0], case_dir, dirs_exist_ok=True
        )
        requests = list(case_dir.glob("owner-call-*.request.json"))
        if len(requests) != 1:
            raise AssertionError("Expected exactly one production owner-call request")
        request_path = requests[0]
        command = [
            cedar,
            "authorize",
            "--policies",
            str(
                request_path.with_name(
                    request_path.name.replace(".request.json", ".cedar")
                )
            ),
            "--entities",
            str(case_dir / "entities.json"),
            "--request-json",
            str(request_path),
        ]
        case["production_request_replay"] = run(command)
        # Change only the principal entity literal to valid, raw Unicode Cedar
        # syntax. Keep the real entity set and policy byte-for-byte identical.
        request = json.loads(request_path.read_text())
        assert request["principal"] == (
            'slangGraph::User::"' + op._cedar(principal) + '"'
        )
        request["principal"] = f'slangGraph::User::"{principal}"'
        corrected_path = case_dir / "unicode-control.request.json"
        corrected_path.write_text(json.dumps(request, ensure_ascii=False))
        case["unicode_control_replay"] = run(command[:-1] + [str(corrected_path)])
        case["emitted_escape"] = op._cedar(principal)
        case["generated_candidate_permit"] = op._candidate_permit(
            principal, manifest.expand("lookup", {})[0]
        )
        evidence["cases"].append(case)

    for case in evidence["cases"]:
        assert case["outcome"] == "ALLOW", case
        assert case["production_request_replay"]["returncode"] == 0, case
        assert case["production_request_replay"]["stdout"].strip() == "ALLOW", case
        assert case["unicode_control_replay"]["stdout"].strip() == "ALLOW", case
        assert case["emitted_escape"] == case["principal"], case
    evidence["scope"] = (
        "Real-Cedar regression of production authorization and emitted requests; "
        "not a formal translation-refinement proof."
    )
    (output / "evidence.json").write_text(
        json.dumps(evidence, indent=2, ensure_ascii=False) + "\n"
    )
    print("PASS: all five identities authorize and replay with the real Cedar CLI.")
    print(f"Evidence: {output / 'evidence.json'}")


if __name__ == "__main__":
    main()
