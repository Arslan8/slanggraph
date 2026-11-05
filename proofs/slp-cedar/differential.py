"""Compare official Cedar Lean semantics with Argus's production Cedar path."""

from __future__ import annotations

import argparse
import json
import os
import shutil
import subprocess
from dataclasses import dataclass
from pathlib import Path
from typing import Any, Mapping

from langgraph.prebuilt.security import mac
from langgraph.prebuilt.security import object_policy as op

ROOT = Path(__file__).resolve().parents[2]
PROOF = Path(__file__).resolve().parent

MANIFEST = """class db {
  operations select
  object table
  normalizer identity
  attrs owner
  enforced_by broker
}
class secret {
  operations read
  object item
  normalizer identity
  attrs owner
  enforced_by broker
}
tool run {
  runs broker
  db select db need
  secret read secret want
  returns normal
}
"""

LINE_ACTIONS = """[
  slangGraph::Action::"db::select",
  slangGraph::Action::"secret::read"
]"""


class Broker:
    enforcer_id = "cedar-differential"

    def supports(self, object_class: Any, line: Any) -> bool:
        return object_class.enforced_by is op.EnforcementKind.BROKER


class TracingAuthorizer(op.CedarObjectAuthorizer):
    def __init__(self, *args: Any, **kwargs: Any) -> None:
        super().__init__(*args, **kwargs)
        self.trace: list[str] = []

    def _allows(
        self,
        executable: str,
        engine: tuple[str, int, int, int, int, int],
        bundle: Any,
        entities_json: str,
        name: str,
        source: str,
        request: Mapping[str, object],
    ) -> bool:
        try:
            allowed = super()._allows(
                executable,
                engine,
                bundle,
                entities_json,
                name,
                source,
                request,
            )
        except op.ObjectPolicyDenied as exc:
            self.trace.append(f"{name}=ERROR:cli")
            raise exc
        self.trace.append(f"{name}={'ALLOW' if allowed else 'DENY'}:0")
        return allowed


@dataclass(frozen=True)
class Case:
    name: str
    roles: tuple[str, ...] = ("analyst",)
    db_owner: str = "finance"
    secret_owner: str = "platform"
    owner_tool: str = "run"
    resource_mismatch: bool = False
    evaluation_error: bool = False


CASES = (
    Case("allowed"),
    Case("optional_forbid", secret_owner="blocked"),
    Case("mandatory_forbid", db_owner="blocked"),
    Case("role_denied", roles=()),
    Case("resource_mismatch", resource_mismatch=True),
    Case("context_mismatch", owner_tool="wrong"),
    Case("evaluation_error", evaluation_error=True),
)


def owner_policy(tool: str) -> str:
    return f"""permit(principal, action == slangGraph::Action::"call", resource);
permit(principal, action in {LINE_ACTIONS}, resource) when {{
  context.tool == slangGraph::Tool::"{tool}"
}};
"""


def envelope_policy(case: Case) -> str:
    if case.resource_mismatch:
        return """permit(
  principal,
  action == slangGraph::Action::"db::select",
  resource == slangGraph::DbTable::"wrong"
);
"""
    return f"""permit(principal, action in {LINE_ACTIONS}, resource) when {{
  principal.roles.contains("analyst")
}};
"""


def blocked_forbid(attribute: str = "owner") -> str:
    return f"""forbid(principal, action in {LINE_ACTIONS}, resource) when {{
  resource.{attribute} == "{"x" if attribute != "owner" else "blocked"}"
}};
"""


def parse_lean(output: str) -> dict[str, dict[str, Any]]:
    parsed: dict[str, dict[str, Any]] = {}
    for line in output.splitlines():
        if "|" not in line:
            continue
        name, trace, outcome = line.split("|", 2)
        parsed[name] = {"trace": trace.split(",") if trace else [], "outcome": outcome}
    expected = {case.name for case in CASES}
    if set(parsed) != expected:
        raise RuntimeError(f"Lean differential cases drifted: {sorted(parsed)}")
    return parsed


def production_case(case: Case, cedar: str) -> dict[str, Any]:
    manifest = op.parse_security_manifest(
        MANIFEST, enforcers={op.EnforcementKind.BROKER: Broker()}
    )
    operator_forbids = (
        blocked_forbid("attribute_that_does_not_exist") if case.evaluation_error else ""
    )
    policy_forbids = "" if case.evaluation_error else blocked_forbid()
    authorizer = TracingAuthorizer(
        manifest,
        op.CedarPolicySet(
            {"run": owner_policy(case.owner_tool)},
            envelope_policy(case),
            mac_forbids=policy_forbids,
        ),
        executable=cedar,
    )
    original = mac.runtime_mac_forbids
    mac.runtime_mac_forbids = lambda: operator_forbids
    try:
        try:
            grant = authorizer.authorize(
                principal_id="1",
                roles=case.roles,
                tool_name="run",
                tool_owner="reporting",
                call_id=case.name,
                arguments={},
                labels={
                    ("db", "db"): {"owner": case.db_owner},
                    ("secret", "secret"): {"owner": case.secret_owner},
                },
            )
            outcome = "GRANT:" + ",".join(
                line.line_id.rsplit(":", 1)[-1] for line in grant.lines
            )
            refusal = None
        except op.ObjectPolicyDenied as exc:
            outcome = "REFUSE"
            refusal = str(exc)
    finally:
        mac.runtime_mac_forbids = original
    return {"trace": authorizer.trace, "outcome": outcome, "refusal": refusal}


def compare_case(
    case: Case, lean: dict[str, Any], production: dict[str, Any]
) -> dict[str, Any]:
    if not case.evaluation_error:
        matched = (
            lean["trace"] == production["trace"]
            and lean["outcome"] == production["outcome"]
        )
        kind = "exact"
    else:
        lean_prefix = lean["trace"][:4]
        production_prefix = production["trace"][:4]
        boundary = (
            len(lean["trace"]) >= 5
            and len(production["trace"]) == 5
            and lean["trace"][4] == "mac-eval=ALLOW:1"
            and production["trace"][4] == "mac-eval=ERROR:cli"
            and lean["outcome"].startswith("GRANT:")
            and production["outcome"] == "REFUSE"
            and production["refusal"] == "cedar:evaluation:mac-eval"
        )
        matched = lean_prefix == production_prefix and boundary
        kind = "documented_error_boundary"
    return {
        "name": case.name,
        "comparison": kind,
        "matched": matched,
        "lean": lean,
        "production": production,
    }


def run(command: list[str], cwd: Path) -> subprocess.CompletedProcess[str]:
    result = subprocess.run(
        command, cwd=cwd, capture_output=True, text=True, timeout=3600, check=False
    )
    if result.returncode != 0:
        raise RuntimeError(result.stdout + result.stderr)
    return result


def main() -> None:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--output", type=Path, required=True)
    parser.add_argument(
        "--lake", default=os.environ.get("LAKE", str(Path.home() / ".elan/bin/lake"))
    )
    args = parser.parse_args()
    cedar = shutil.which("cedar")
    if cedar is None:
        raise SystemExit("Cedar CLI is required")
    lean_run = run([args.lake, "exe", "argusCedarDifferential"], PROOF)
    lean_cases = parse_lean(lean_run.stdout)
    comparisons = [
        compare_case(case, lean_cases[case.name], production_case(case, cedar))
        for case in CASES
    ]
    report = {
        "schema_version": 1,
        "passed": all(item["matched"] for item in comparisons),
        "official_evaluator": "Cedar.Spec.isAuthorized",
        "production_evaluator": run([cedar, "--version"], ROOT).stdout.strip(),
        "cases": comparisons,
    }
    args.output.write_text(json.dumps(report, indent=2) + "\n", encoding="utf-8")
    if not report["passed"]:
        raise SystemExit(json.dumps(report, indent=2))
    print(json.dumps(report, indent=2))


if __name__ == "__main__":
    main()
