"""Check shared attacker, fixture, and permitted-operation oracle source."""

from __future__ import annotations

import ast
import hashlib
import json
import subprocess
from pathlib import Path

HERE = Path(__file__).resolve().parent
ROOT = HERE.parents[2]
LINUX = "caded83cf4e8ef83d3df1065f6acf3d808a4abb3"
LINUX_DIR = "eval/campaigns/cross-host-security-v2"


def linux(name: str) -> bytes:
    return subprocess.check_output(["git", "show", f"{LINUX}:{LINUX_DIR}/{name}"], cwd=ROOT)


def sha(data: bytes) -> str:
    return hashlib.sha256(data).hexdigest()


def function(source: bytes, name: str) -> str:
    for node in ast.parse(source).body:
        if isinstance(node, ast.FunctionDef) and node.name == name:
            return ast.dump(node, include_attributes=False)
    raise ValueError(name)


def verify() -> dict:
    attacker_linux, attacker_mac = linux("attacker.py"), (HERE / "attacker.py").read_bytes()
    fixture_linux, fixture_mac = linux("fixtures.py"), (HERE / "fixtures.py").read_bytes()
    oracle_linux, oracle_mac = linux("verify.py"), (HERE / "verify.py").read_bytes()
    checks = {
        "attacker_bytes_identical": attacker_linux == attacker_mac,
        "fixture_bytes_identical": fixture_linux == fixture_mac,
        "permitted_operation_oracle_identical": function(oracle_linux, "allowed")
        == function(oracle_mac, "allowed"),
    }
    return {
        "evidence_valid": all(checks.values()),
        "linux_revision": LINUX,
        "checks": checks,
        "source_sha256": {
            "attacker": sha(attacker_linux),
            "fixtures": sha(fixture_linux),
            "linux_verify": sha(oracle_linux),
            "macos_verify": sha(oracle_mac),
        },
        "oracle_difference": (
            "Forbidden-effect and classification code differs for host-specific "
            "CPU/syscall support and extra macOS live mutations; mapping uses "
            "the shared resource-state oracle per case and reports support outcomes separately."
        ),
    }


if __name__ == "__main__":
    result = verify()
    print(json.dumps(result, indent=2, sort_keys=True))
    raise SystemExit(0 if result["evidence_valid"] else 1)
