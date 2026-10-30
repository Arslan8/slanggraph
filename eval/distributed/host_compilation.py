"""Reuse one parsed policy/tool representation across host capability compilers."""

from __future__ import annotations

import argparse
import hashlib
import json
import sys
import tempfile
import uuid
from dataclasses import dataclass
from pathlib import Path

from langchain_core.tools import tool
from langgraph.prebuilt.security import (
    CedarObjectAuthorizer,
    CedarPolicySet,
    DacOverrides,
    EnforcementKind,
    LinuxObjectDispatcher,
    LinuxToolSpec,
    ObjectClass,
    ObjectClassRegistry,
    ObjectPolicyHostExecutor,
    Principal,
    SecurityConfig,
    SecurityManifest,
    Tool,
    ToolCall,
    ToolDac,
    ToolManifest,
    parse_security_manifest,
)
from langgraph.prebuilt.security.container import DockerObjectDispatcher
from langgraph.prebuilt.security.object_policy import (
    ObjectGrant,
    ObjectGrantLine,
    _language_sandbox_owner_policy,
)

ROOT = Path(__file__).resolve().parents[2]
sys.path.insert(0, str(ROOT / "eval/scripts"))
from mechanism_evidence_plugin import serial  # noqa: E402

IMAGE = "sha256:3bcfa1622e24814afee022c71236dadd92e31a5fff41ad99a23925bc98311504"
MANIFEST = "runs linux\nfs read @{path} need"
POLICY = 'permit(principal == slangGraph::User::"alice", action, resource);'
SOURCE = """from pathlib import Path

def run(path, other=None):
    result = {"allowed": Path(path).read_text()}
    if other is not None:
        try:
            result["forbidden"] = Path(other).read_text()
        except OSError as error:
            result["forbidden_blocked"] = type(error).__name__
    return result
"""
FS_CLASS = ObjectClass(
    "fs",
    frozenset({"read", "write", "truncate"}),
    "path",
    "fs.realpath",
    frozenset(),
    EnforcementKind.KERNEL,
)


@tool("common_read")
def common_read(path: str, other: str | None = None) -> dict:
    """Read one policy-selected file and probe an undeclared path."""
    raise RuntimeError("unconfined fallback is forbidden")


@dataclass(frozen=True)
class PreparedPolicy:
    """Host-independent, parsed tool policy reused by every host compiler."""

    tool: ToolManifest
    policies: CedarPolicySet
    artifact_sha256: str

    def canonical(self) -> dict:
        return {
            "tool": {
                "name": self.tool.name,
                "runs": self.tool.runs,
                "returns": self.tool.returns,
                "rules": [
                    {
                        "class": rule.class_name,
                        "operation": rule.operation,
                        "pattern": rule.pattern,
                        "requirement": rule.requirement.value,
                        "source": rule.source,
                    }
                    for rule in self.tool.rules
                ],
            },
            "policies": {
                "owners": dict(self.policies.owner_permits),
                "principal": self.policies.principal_permits,
                "share": self.policies.share_permits,
                "mac": self.policies.mac_forbids,
                "digest": self.policies.digest,
            },
            "artifact_sha256": self.artifact_sha256,
        }

    @property
    def digest(self) -> str:
        encoded = json.dumps(self.canonical(), sort_keys=True, separators=(",", ":")).encode()
        return hashlib.sha256(encoded).hexdigest()


class MissingFileCapability:
    """Host profile that explicitly lacks filesystem enforcement support."""

    requires_host_negotiation = False

    def __init__(self, delegate) -> None:
        self.delegate = delegate

    def supports(self, object_class: ObjectClass, line: ObjectGrantLine) -> bool:
        del object_class, line
        return False

    def validate_tools(self, tool_names) -> None:
        self.delegate.validate_tools(tool_names)

    def invoke(self, principal, call, grant: ObjectGrant):
        del principal, call, grant
        raise AssertionError("missing-capability host must refuse before dispatch")

    async def ainvoke(self, principal, call, grant: ObjectGrant):
        return self.invoke(principal, call, grant)

    def confirm_termination(self, recovery) -> bool:
        del recovery
        return True


def prepare(artifact_sha256: str) -> PreparedPolicy:
    # Parsing happens exactly once without a host enforcer. Host compilation
    # below reuses this exact ToolManifest and CedarPolicySet object.
    parsed = parse_security_manifest(
        f"tool common_read {{\n{MANIFEST}\n}}",
        classes=(FS_CLASS,),
    )
    tool_manifest = parsed.tools["common_read"]
    policies = CedarPolicySet(
        {"common_read": _language_sandbox_owner_policy(tool_manifest)},
        POLICY,
    )
    return PreparedPolicy(tool_manifest, policies, artifact_sha256)


def compile_for_host(prepared: PreparedPolicy, dispatcher) -> SecurityConfig:
    registry = ObjectClassRegistry(
        enforcers={EnforcementKind.KERNEL: dispatcher},
        classes=(FS_CLASS,),
    )
    host_manifest = SecurityManifest(registry, {"common_read": prepared.tool})
    authorizer = CedarObjectAuthorizer(host_manifest, prepared.policies)
    executor = ObjectPolicyHostExecutor(
        authorizer,
        dispatcher,
        tool_owners={"common_read": "application"},
    )
    executor.validate_tools(("common_read",))
    assert authorizer.manifest.tools["common_read"] is prepared.tool
    assert authorizer.policies is prepared.policies
    return SecurityConfig(
        host_executor=executor,
        dac_overrides=DacOverrides({"common_read": ToolDac("__cedar__", {"*": "x"})}),
        closed_admission=True,
    )


def _call(path: Path, other: Path | None) -> ToolCall:
    return ToolCall(
        Tool("common_read", ToolDac("owner", {"*": "x"}), frozenset(), ()),
        {"path": str(path), "other": str(other) if other else None},
        {},
        uuid.uuid4().hex,
        0,
    )


def run(output: Path) -> None:
    output.mkdir(parents=True, exist_ok=False)
    with tempfile.TemporaryDirectory(prefix="slg-host-compile-") as folder:
        root = Path(folder)
        tool_root = root / "trusted-tool"
        data_root = root / "data"
        tool_root.mkdir()
        data_root.mkdir()
        source = tool_root / "common_worker.py"
        allowed = data_root / "allowed.txt"
        forbidden = data_root / "forbidden.txt"
        source.write_text(SOURCE)
        allowed.write_text("PORTABLE_ALLOWED")
        forbidden.write_text("PORTABLE_FORBIDDEN")
        artifact = hashlib.sha256(source.read_bytes()).hexdigest()
        prepared = prepare(artifact)
        (output / "prepared.json").write_text(
            json.dumps({**prepared.canonical(), "sha256": prepared.digest}, indent=2) + "\n"
        )
        profiles = {
            "linux": {
                "dispatcher": "LinuxObjectDispatcher",
                "enforcement": "bubblewrap+Landlock+seccomp",
            },
            "container": {
                "dispatcher": "DockerObjectDispatcher",
                "image": IMAGE,
            },
            "linux-missing-filesystem": {
                "dispatcher": "MissingFileCapability(LinuxObjectDispatcher)",
                "filesystem": False,
            },
        }
        (output / "host-profiles.json").write_text(json.dumps(profiles, indent=2) + "\n")
        linux = LinuxObjectDispatcher(
            {"common_read": LinuxToolSpec("common_worker:run", source, artifact)},
            runtime_roots=(tool_root,),
            integrity_recheck="preflight-only",
        )
        container = DockerObjectDispatcher(
            {"common_read": LinuxToolSpec("common_worker:run", source, artifact)},
            image=IMAGE,
            private_roots=(root,),
        )
        dispatchers = {"linux": linux, "container": container}
        principal = Principal("alice", frozenset(), frozenset(), "portable-session")
        rows = []
        try:
            for host, dispatcher in dispatchers.items():
                security = compile_for_host(prepared, dispatcher)
                for case, other in (("allowed", None), ("forbidden_probe", forbidden)):
                    result = security.host_executor.invoke(principal, _call(allowed, other), ())
                    rows.append(
                        {
                            "host": host,
                            "case_id": case,
                            "prepared_sha256": prepared.digest,
                            "prepared_tool_object_reused": (
                                security.host_executor.authorizer.manifest.tools["common_read"]
                                is prepared.tool
                            ),
                            "prepared_policy_object_reused": (
                                security.host_executor.authorizer.policies is prepared.policies
                            ),
                            "grant": serial(security.host_executor.authorization_grants()[-1]),
                            "generated_restrictions": serial(
                                dispatcher.lowering_records()
                                if hasattr(dispatcher, "lowering_records")
                                else dispatcher.execution_records()
                            ),
                            "activation": serial(result.receipt),
                            "result": result.value,
                            "allowed_succeeded": (
                                result.value.get("allowed") == "PORTABLE_ALLOWED"
                            ),
                            "forbidden_blocked": (
                                "PORTABLE_FORBIDDEN" not in json.dumps(result.value)
                            ),
                        }
                    )
            missing = MissingFileCapability(linux)
            missing_error = None
            try:
                missing_security = compile_for_host(prepared, missing)
                missing_security.host_executor.invoke(principal, _call(allowed, None), ())
            except Exception as exc:
                missing_error = {"type": type(exc).__name__, "message": str(exc)}
            rows.append(
                {
                    "host": "linux-missing-filesystem",
                    "case_id": "missing_capability",
                    "prepared_sha256": prepared.digest,
                    "prepared_tool_object_reused": True,
                    "prepared_policy_object_reused": True,
                    "explicit_refusal": missing_error,
                    "silently_weakened": False,
                }
            )
        finally:
            container.close()
        (output / "trials.jsonl").write_text(
            "".join(json.dumps(row, sort_keys=True) + "\n" for row in rows)
        )


if __name__ == "__main__":
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--output", required=True, type=Path)
    arguments = parser.parse_args()
    run(arguments.output)
