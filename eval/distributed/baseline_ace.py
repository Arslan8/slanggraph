"""Probe ACE's pinned ToolExecutionSandbox configuration surface.

ACE's published tool container exposes no volume or resource-policy settings.
The runner therefore records a benign in-container control and one repeated
host-file availability probe. It does not relabel that probe as multiple
resource attacks. A failed legitimate operation is not counted as protection.
"""

from __future__ import annotations

import argparse
import base64
import hashlib
import importlib.util
import json
import subprocess
import sys
import tempfile
import types
from pathlib import Path

CASE = "host_file_availability"


class SourceTool:
    def __init__(self, source: str) -> None:
        self.source = source

    def generate_source(self) -> str:
        return self.source


def _load_sandbox(source: Path):
    package_root = source / "src/ace"
    for name, path in (
        ("ace", package_root),
        ("ace.schema", package_root / "schema"),
        ("ace.execute", package_root / "execute"),
    ):
        package = types.ModuleType(name)
        package.__path__ = [str(path)]
        sys.modules[name] = package

    def load(name: str, path: Path):
        spec = importlib.util.spec_from_file_location(name, path)
        if spec is None or spec.loader is None:
            raise RuntimeError(f"cannot load pinned ACE module {name}")
        module = importlib.util.module_from_spec(spec)
        sys.modules[name] = module
        spec.loader.exec_module(module)
        return module

    load("ace.schema.permissions", package_root / "schema/permissions.py")
    load("ace.schema.abstract", package_root / "schema/abstract.py")
    load("ace.schema.concrete", package_root / "schema/concrete.py")
    load("ace.execute.helper", package_root / "execute/helper.py")
    return load("ace.execute.sandbox", package_root / "execute/sandbox.py").ToolExecutionSandbox


def _run_control(sandbox_type) -> dict:
    source = "def main(value):\n    return {'value': value}\n"
    sandbox = sandbox_type(SourceTool(source))
    try:
        sandbox.launch(args=["ACE_CONTROL"])
        sandbox.wait_for_result(timeout=30)
        logs = sandbox.container.logs().decode(errors="replace")
        marker = "RESULT:"
        encoded = logs.split(marker, 1)[1].split()[0] if marker in logs else None
        result = json.loads(base64.b64decode(encoded)) if encoded else None
        return {
            "tool_executed": sandbox.container.attrs["State"]["ExitCode"] == 0,
            "result": result,
            "logs": logs,
        }
    finally:
        sandbox.kill()


def _run_host_file_probe(sandbox_type, database: Path) -> dict:
    source = """def main(path):
    from pathlib import Path
    return {'bytes': len(Path(path).read_bytes())}
"""
    sandbox = sandbox_type(SourceTool(source))
    try:
        sandbox.launch(args=[str(database)])
        sandbox.wait_for_result(timeout=30)
        logs = sandbox.container.logs().decode(errors="replace")
        sandbox.container.reload()
        return {
            "tool_executed": True,
            "exit_code": sandbox.container.attrs["State"]["ExitCode"],
            "logs": logs,
        }
    finally:
        sandbox.kill()


def run(output: Path, source: Path, repetitions: int) -> None:
    output.mkdir(parents=True, exist_ok=False)
    revision = subprocess.check_output(["git", "rev-parse", "HEAD"], cwd=source, text=True).strip()
    sandbox_file = source / "src/ace/execute/sandbox.py"
    sandbox_type = _load_sandbox(source)
    plan = {
        "baseline": "ACE",
        "revision": revision,
        "sandbox_sha256": hashlib.sha256(sandbox_file.read_bytes()).hexdigest(),
        "cases": [CASE],
        "comparison_kind": "sandbox_configuration_probe",
        "scope": (
            "ACE ToolExecutionSandbox only; planner and information-flow analysis are not executed"
        ),
        "repetitions": repetitions,
        "configuration": "published ToolExecutionSandbox/tool-runner-image",
        "supported_settings": ["image", "environment", "detached", "port"],
        "missing_settings": [
            "volume mount",
            "record selector policy",
            "operation policy",
            "sealed operator policy",
            "principal-scoped invocation grant",
        ],
    }
    (output / "plan.json").write_text(json.dumps(plan, indent=2) + "\n")
    with (output / "trials.jsonl").open("w") as stream:
        for repetition in range(repetitions):
            control = _run_control(sandbox_type)
            with tempfile.TemporaryDirectory(prefix="ace-resource-") as folder:
                database = Path(folder) / "records.sqlite"
                database.write_bytes(b"ALICE_ALLOWED BOB_ACE_SYNTHETIC_SECRET")
                probe = _run_host_file_probe(sandbox_type, database)
            stream.write(
                json.dumps(
                    {
                        "baseline": "ACE",
                        "case_id": CASE,
                        "repeat": repetition,
                        "comparison_kind": "sandbox_configuration_probe",
                        "baseline_scope": "ToolExecutionSandbox only",
                        "full_system_comparison": False,
                        "fixed_invocation": True,
                        "tool_executed": probe["tool_executed"],
                        "legitimate_result": False,
                        "unauthorized_effect": False,
                        "classification": "configuration_could_not_execute",
                        "reason": (
                            "the published ToolExecutionSandbox has no volume or "
                            "resource-policy configuration; the host fixture is absent "
                            "from the container"
                        ),
                        "benign_container_control": control,
                        "resource_probe": probe,
                        "not_counted_as_security_success": True,
                    },
                    sort_keys=True,
                )
                + "\n"
            )


if __name__ == "__main__":
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--output", required=True, type=Path)
    parser.add_argument("--source", required=True, type=Path)
    parser.add_argument("--repetitions", default=5, type=int)
    arguments = parser.parse_args()
    run(arguments.output, arguments.source, arguments.repetitions)
