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

from campaign import HERE, ROOT, config_id, load_config, sha256_file, write_json

UPSTREAM = ROOT / "eval/campaigns/cross-host-security-v2/run.py"
MANDATORY_REFUSAL_PROBES = frozenset({"required_syscall_filter", "extensible_required_syscalls"})


def applicable_cases(manifest: dict[str, Any], backend: str = "macos") -> list[str]:
    """Return the frozen ordered case list for one backend."""
    selected = [case["id"] for case in manifest["cases"] if case.get(backend) is True]
    if backend == "macos":
        excluded = {
            case["id"]
            for case in manifest["cases"]
            if case.get("macos") is False
            and case.get("linux") is True
            and case.get("kind") == "gate"
            and case.get("macos_reason")
        }
        if excluded != MANDATORY_REFUSAL_PROBES:
            raise ValueError(f"unexpected macOS mandatory gate inventory: {sorted(excluded)}")
        selected = [case["id"] for case in manifest["cases"]]
    if len(selected) != 45 or len(set(selected)) != 45:
        raise ValueError("expected 45 distinct shared security cases")
    return selected


def check_native_configuration(path: Path) -> dict[str, Any]:
    """Validate the launcher and checker identities consumed by native_host.py."""
    native = json.loads(path.read_text())
    for section, file_field, digest_field in (
        ("launcher", "launcher", "launcher_digest"),
        ("launcher", "library", "library_digest"),
        ("lean", "library", "sha256"),
        ("lean", "native_runtime", "native_runtime_sha256"),
    ):
        item = native[section]
        actual = sha256_file(Path(item[file_field]).resolve(strict=True))
        if actual != item[digest_field]:
            raise ValueError(f"{section}.{file_field} digest differs from native configuration")
    return native


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
    parser.add_argument("--repetitions", type=int, choices=(1, 5), default=None)
    parser.add_argument("--allow-non-tahoe-test-host", action="store_true")
    args = parser.parse_args()
    if sys.platform != "darwin":
        parser.error("the macOS security runner must execute on the macOS student host")
    version = platform.mac_ver()[0]
    if version != "26.7.2" and not args.allow_non_tahoe_test_host:
        parser.error(f"expected Tahoe 26.7.2, observed macOS {version}")
    configuration = args.native_configuration.resolve(strict=True)
    check_native_configuration(configuration)
    config = load_config()
    manifest = json.loads((HERE / config["evaluations"][1]["manifest"]).read_text())
    cases = applicable_cases(manifest)
    repetitions = args.repetitions or config["evaluations"][1]["repetitions_per_case"]
    command = build_command(
        args.output.resolve(),
        repetitions=repetitions,
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
        "repetitions": repetitions,
        "mandatory_refusal_probes_included": sorted(MANDATORY_REFUSAL_PROBES),
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
