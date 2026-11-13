"""Verify the committed macOS host-security package without local run directories."""

from __future__ import annotations

import gzip
import hashlib
import json
import tarfile
import tempfile
from pathlib import Path

HERE = Path(__file__).resolve().parent


def sha256(path: Path) -> str:
    digest = hashlib.sha256()
    with path.open("rb") as source:
        for block in iter(lambda: source.read(1024 * 1024), b""):
            digest.update(block)
    return digest.hexdigest()


def verify() -> dict:
    issues = []
    checked = 0
    for line in (HERE / "SHA256SUMS").read_text().splitlines():
        expected, name = line.split("  ", 1)
        path = HERE / name
        if path.resolve().parent != HERE.resolve() or not path.is_file():
            issues.append(f"missing or escaped artifact: {name}")
            continue
        if sha256(path) != expected:
            issues.append(f"artifact checksum differs: {name}")
        checked += 1
    for prefix, repetitions in (("qualification", 1), ("final", 5)):
        audit = json.loads((HERE / f"{prefix}-case-results.json").read_text())
        verification = json.loads((HERE / f"{prefix}-verification.json").read_text())
        request = json.loads((HERE / f"{prefix}-request.json").read_text())
        config = json.loads((HERE / f"{prefix}-configuration.json").read_text())
        if (
            not audit["evidence_valid"]
            or not verification["evidence_valid"]
            or audit["distinct_cases"] != 45
            or audit["repetitions_per_case"] != repetitions
            or len(audit["rows"]) != 45
            or request["macos_version"] != "26.7.2"
            or len(request["cases"]) != 45
            or config["repetitions"] != repetitions
        ):
            issues.append(f"{prefix} audit or configuration incomplete")
        with gzip.open(HERE / f"{prefix}-trials.jsonl.gz", "rt") as source:
            raw_count = sum(1 for _ in source)
        if raw_count != 45 * repetitions * 2:
            issues.append(f"{prefix} trial count differs: {raw_count}")
        if json.loads((HERE / f"{prefix}-source-before.json").read_text()) != json.loads(
            (HERE / f"{prefix}-source-after.json").read_text()
        ):
            issues.append(f"{prefix} source drift")
    index = json.loads((HERE / "archive-index.json").read_text())
    with tempfile.NamedTemporaryFile(prefix="macos-host-security-", suffix=".tar.gz") as temporary:
        with Path(temporary.name).open("wb") as destination:
            for item in index["parts"]:
                path = HERE / item["name"]
                if sha256(path) != item["sha256"] or path.stat().st_size != item["bytes"]:
                    issues.append(f"archive part differs: {item['name']}")
                with path.open("rb") as source:
                    for block in iter(lambda: source.read(1024 * 1024), b""):
                        destination.write(block)
        archive = Path(temporary.name)
        if (
            sha256(archive) != index["archive_sha256"]
            or archive.stat().st_size != index["archive_bytes"]
        ):
            issues.append("combined raw archive differs")
        with tarfile.open(archive, "r:gz") as bundle:
            names = bundle.getnames()
        count = sum(name.endswith("/trial.json") for name in names)
        if count != 450:
            issues.append(f"raw archive trial count differs: {count}")
        for name in (
            "configuration.json",
            "source-before.json",
            "source-after.json",
            "native/core.dylib",
            "native/runtime.dylib",
            "native/launcher",
            "trials.jsonl",
        ):
            if f"{index['archive_root']}/{name}" not in names:
                issues.append(f"raw archive missing: {name}")
    return {"evidence_valid": not issues, "checked_artifacts": checked, "issues": issues}


if __name__ == "__main__":
    result = verify()
    print(json.dumps(result, indent=2, sort_keys=True))
    raise SystemExit(0 if result["evidence_valid"] else 1)
