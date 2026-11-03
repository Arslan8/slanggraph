"""Fail-closed Cedar proof, encoder, and production-engine drift check."""

from __future__ import annotations

import argparse
import json
import os
import re
import shutil
import subprocess
import sys
import tempfile
from pathlib import Path

ROOT = Path(__file__).resolve().parents[2]
PROOF = Path(__file__).resolve().parent
COMPOSITION = ROOT / "proofs/composition-route"
PREBUILT = ROOT / "libs/prebuilt"
CEDAR_SPEC_COMMIT = "8aa1a2a67f62d824abead35a9aef757ad3a35595"
LEAN_TOOLCHAIN = "leanprover/lean4:v4.33.1"
CEDAR_VERSION = "4.13.0"


def run(command: list[str], *, cwd: Path) -> dict[str, object]:
    completed = subprocess.run(
        command,
        cwd=cwd,
        capture_output=True,
        text=True,
        timeout=3600,
        check=False,
    )
    result = {
        "command": command,
        "returncode": completed.returncode,
        "stdout": completed.stdout,
        "stderr": completed.stderr,
    }
    if completed.returncode != 0:
        raise RuntimeError(json.dumps(result, indent=2, ensure_ascii=False))
    return result


def main() -> None:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--output", type=Path)
    parser.add_argument("--clean-build", action="store_true")
    args = parser.parse_args()
    lake = Path(os.environ.get("LAKE", Path.home() / ".elan/bin/lake"))
    if not lake.is_file():
        raise SystemExit(f"Lake executable is missing: {lake}")
    cedar = shutil.which("cedar")
    if cedar is None:
        raise SystemExit("Cedar CLI is required for the differential check")
    if PROOF.joinpath("lean-toolchain").read_text().strip() != LEAN_TOOLCHAIN:
        raise SystemExit("Lean toolchain pin drifted")
    manifest = json.loads(PROOF.joinpath("lake-manifest.json").read_text())
    cedar_package = next(
        (package for package in manifest["packages"] if package["name"] == "Cedar"),
        None,
    )
    if cedar_package is None or cedar_package.get("rev") != CEDAR_SPEC_COMMIT:
        raise SystemExit("cedar-spec commit pin drifted")
    version = run([cedar, "--version"], cwd=ROOT)
    if CEDAR_VERSION not in str(version["stdout"]):
        raise SystemExit(f"Expected Cedar {CEDAR_VERSION}: {version['stdout']}")

    if args.clean_build:
        run([str(lake), "clean"], cwd=PROOF)
        run([str(lake), "clean"], cwd=COMPOSITION)
    proof_build = run([str(lake), "build"], cwd=PROOF)
    composition_build = run(
        [str(lake), "build", "AuthorityPreservation"], cwd=COMPOSITION
    )
    proof_output = "\n".join(
        str(value)
        for result in (proof_build, composition_build)
        for value in (result["stdout"], result["stderr"])
    )
    if "sorryAx" in proof_output:
        raise SystemExit("Lean build introduced sorryAx")

    with tempfile.TemporaryDirectory(prefix="slp-cedar-regression-") as temp:
        temp_path = Path(temp)
        encoder = run(
            [
                sys.executable,
                str(PROOF / "check_translation.py"),
                "--output",
                temp,
            ],
            cwd=ROOT,
        )
        differential_result = run(
            [
                sys.executable,
                str(PROOF / "differential.py"),
                "--output",
                str(temp_path / "differential.json"),
                "--lake",
                str(lake),
            ],
            cwd=ROOT,
        )
        differential_report = json.loads(
            (temp_path / "differential.json").read_text(encoding="utf-8")
        )
    differential = run(
        [
            sys.executable,
            "-m",
            "pytest",
            "-q",
            "tests/security/test_cedar_strings.py",
            "tests/security/test_object_policy.py",
        ],
        cwd=PREBUILT,
    )
    test_summary = next(
        (
            line.strip()
            for line in reversed(str(differential["stdout"]).splitlines())
            if " passed" in line and "=" in line
        ),
        "summary unavailable",
    )
    count_match = re.search(r"(\d+) passed", test_summary)
    test_count = int(count_match.group(1)) if count_match else None
    theorem_axioms = list(
        dict.fromkeys(
            line.strip()
            for line in proof_output.splitlines()
            if any(
                theorem in line
                for theorem in (
                    "candidate_query_authorized_iff_no_forbid",
                    "argus_authorization_official_sound_complete",
                    "slp_to_cedar_sound_complete",
                    "complete_authority_preservation",
                )
            )
            and "depends on axioms" in line
        )
    )
    revision = run(["git", "rev-parse", "HEAD"], cwd=ROOT)["stdout"].strip()
    report = {
        "schema_version": 2,
        "passed": True,
        "tested_revision": revision,
        "clean_build": args.clean_build,
        "cedar_spec_commit": CEDAR_SPEC_COMMIT,
        "lean_toolchain": LEAN_TOOLCHAIN,
        "cedar_version": CEDAR_VERSION,
        "proof_build": {
            "command": proof_build["command"],
            "passed": True,
            "sorry_ax_present": False,
        },
        "composition_build": {
            "command": composition_build["command"],
            "passed": True,
            "sorry_ax_present": False,
        },
        "theorem_axioms": theorem_axioms,
        "encoder_regression": {"command": encoder["command"], "passed": True},
        "lean_production_differential": {
            "command": differential_result["command"],
            "passed": differential_report["passed"],
            "case_count": len(differential_report["cases"]),
            "cases": differential_report["cases"],
        },
        "production_regressions": {
            "command": differential["command"],
            "passed": True,
            "test_count": test_count,
            "summary": test_summary,
        },
    }
    if args.output:
        args.output.write_text(json.dumps(report, indent=2) + "\n", encoding="utf-8")
    print(json.dumps(report, indent=2))


if __name__ == "__main__":
    main()
