"""Run the frozen host-security case manifest on the external macOS machine."""

from __future__ import annotations

import argparse
import json
import os
import platform
import subprocess
import sys
from pathlib import Path
from typing import Any

from campaign import HERE, ROOT, config_id, load_config, write_json

UPSTREAM = ROOT / "eval/campaigns/cross-host-security-v2/run.py"


def applicable_cases(manifest: dict[str, Any], backend: str = "macos") -> list[str]:
    """Return the frozen ordered case list for one backend."""
    return [case["id"] for case in manifest["cases"] if case.get(backend) is True]


def build_command(
    output: Path,
    *,
    repetitions: int,
    jobs: int,
    manifest: dict[str, Any],
) -> list[str]:
    """Build the exact upstream security-runner invocation."""
    return [
        sys.executable,
        str(UPSTREAM),
        "--output",
        str(output),
        "--repetitions",
        str(repetitions),
        "--jobs",
        str(jobs),
        "--cases",
        *applicable_cases(manifest),
    ]


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--output", type=Path, required=True)
    parser.add_argument(
        "--native-configuration",
        type=Path,
        required=True,
        help="Frozen MacOSNativeLauncher and Lean checker configuration JSON.",
    )
    parser.add_argument("--jobs", type=int, default=1)
    parser.add_argument("--allow-non-tahoe-test-host", action="store_true")
    args = parser.parse_args()
    if sys.platform != "darwin":
        parser.error("the macOS security runner must execute on the macOS student host")
    version = platform.mac_ver()[0]
    if version != "26.7.2" and not args.allow_non_tahoe_test_host:
        parser.error(f"expected Tahoe 26.7.2, observed macOS {version}")
    configuration = args.native_configuration.resolve(strict=True)
    config = load_config()
    manifest = json.loads((HERE / config["evaluations"][1]["manifest"]).read_text())
    cases = applicable_cases(manifest)
    command = build_command(
        args.output.resolve(),
        repetitions=config["evaluations"][1]["repetitions_per_case"],
        jobs=args.jobs,
        manifest=manifest,
    )
    request = {
        "schema_version": 1,
        "campaign_id": config["campaign_id"],
        "config_id": config_id(config),
        "backend": "macos",
        "platform": platform.platform(),
        "macos_version": version,
        "cases": cases,
        "repetitions": config["evaluations"][1]["repetitions_per_case"],
        "native_configuration": str(configuration),
        "command": command,
    }
    request_path = args.output.resolve().with_name(args.output.name + "-request.json")
    write_json(request_path, request)
    environment = {"ARGUS_MACOS_CONFIGURATION": str(configuration)}
    completed = subprocess.run(
        command,
        cwd=ROOT,
        env={**os.environ, **environment},
        check=False,
    )
    return completed.returncode


if __name__ == "__main__":
    raise SystemExit(main())
