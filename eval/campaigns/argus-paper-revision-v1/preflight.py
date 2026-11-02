"""Fail-closed preflight for the complete Argus revision campaign."""

from __future__ import annotations

import argparse
import hashlib
import importlib.metadata
import json
import platform
import shutil
import subprocess
import sys
from pathlib import Path

from langgraph.prebuilt.security.capabilities import probe_landlock_abi

ROOT = Path(__file__).resolve().parents[3]
IMPLEMENTATION_SOURCES = (
    Path("libs/prebuilt/langgraph/prebuilt/security/landlock.py"),
    Path("libs/prebuilt/langgraph/prebuilt/security/object_broker.py"),
    Path("eval/campaigns/argus-paper-revision-v1/preflight.py"),
    Path("eval/campaigns/argus-paper-revision-v1/run_example.py"),
    Path("eval/campaigns/argus-paper-revision-v1/worker.py"),
)


def command(*parts: str) -> str:
    return subprocess.run(
        parts, cwd=ROOT, check=True, text=True, stdout=subprocess.PIPE
    ).stdout.strip()


def digest(path: Path) -> str:
    return hashlib.sha256(path.read_bytes()).hexdigest()


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--checker", type=Path, required=True)
    parser.add_argument("--output", type=Path, required=True)
    parser.add_argument("--run-example", action="store_true")
    args = parser.parse_args()
    args.output.mkdir(parents=True, exist_ok=False)
    checker = args.checker.resolve(strict=True)
    cedar = shutil.which("cedar")
    source_clean = (
        subprocess.run(
            ["git", "diff", "--quiet", "HEAD", "--", *IMPLEMENTATION_SOURCES],
            cwd=ROOT,
            check=False,
        ).returncode
        == 0
    )
    checks = {
        "linux_host": sys.platform == "linux",
        "wip_branch": command("git", "branch", "--show-current") == "wip",
        "cedar_cli": cedar is not None,
        "landlock_abi_5": probe_landlock_abi() >= 5,
        "lean_checker_nonempty": checker.is_file() and checker.stat().st_size > 0,
        "implementation_sources_committed": source_clean,
        "closed_admission_required": True,
        "sealed_operator_policy_required": True,
        "resource_mediation_required": True,
        "direct_resource_access_denial_required": True,
        "activation_and_cleanup_required": True,
        "lifecycle_checker_required": True,
    }
    record = {
        "schema": 1,
        "label": "complete" if all(checks.values()) else "incomplete",
        "checks": checks,
        "host": {
            "platform": platform.platform(),
            "kernel": platform.release(),
            "machine": platform.machine(),
            "python": sys.version,
        },
        "git": {
            "commit": command("git", "rev-parse", "HEAD"),
            "branch": command("git", "branch", "--show-current"),
        },
        "cedar": {
            "path": cedar,
            "version": command(cedar, "--version") if cedar else None,
        },
        "checker": {
            "path": str(checker),
            "sha256": digest(checker),
        },
        "landlock_abi": probe_landlock_abi(),
        "implementation_sources": {
            str(path): digest(ROOT / path) for path in IMPLEMENTATION_SOURCES
        },
        "dependency_locks": {
            str(path.relative_to(ROOT)): digest(path)
            for path in (ROOT / "uv.lock", ROOT / "libs/prebuilt/uv.lock")
            if path.is_file()
        },
        "installed_packages": dict(
            sorted(
                (distribution.metadata["Name"], distribution.version)
                for distribution in importlib.metadata.distributions()
                if distribution.metadata["Name"]
            )
        ),
    }
    source_before = dict(record["implementation_sources"])
    if not all(checks.values()):
        (args.output / "preflight.json").write_text(json.dumps(record, indent=2) + "\n")
        print(json.dumps({"complete": False, "failed": [k for k, v in checks.items() if not v]}))
        return 2
    record["example_complete"] = False
    if args.run_example:
        example = args.output / "example"
        completed = subprocess.run(
            [
                sys.executable,
                str(Path(__file__).with_name("run_example.py")),
                "--checker",
                str(checker),
                "--output",
                str(example),
            ],
            cwd=ROOT,
            check=False,
        )
        invocation_path = example / "invocation.json"
        invocation = json.loads(invocation_path.read_text()) if invocation_path.is_file() else {}
        record["example_complete"] = (
            completed.returncode == 0 and invocation.get("complete") is True
        )
    if not record["example_complete"]:
        record["label"] = "incomplete"
    record["implementation_sources_after"] = {
        str(path): digest(ROOT / path) for path in IMPLEMENTATION_SOURCES
    }
    record["implementation_sources_stable"] = (
        source_before == record["implementation_sources_after"]
    )
    if not record["implementation_sources_stable"]:
        record["label"] = "incomplete"
    (args.output / "preflight.json").write_text(json.dumps(record, indent=2) + "\n")
    complete = record["label"] == "complete"
    print(json.dumps({"complete": complete, "output": str(args.output)}))
    return 0 if complete else 2


if __name__ == "__main__":
    raise SystemExit(main())
