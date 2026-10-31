"""Verify frozen execution copies, bundle bytes, utility, and native certificates."""

from __future__ import annotations

import argparse
import hashlib
import importlib.util
import json
import sys
from importlib.machinery import SourceFileLoader
from pathlib import Path


def sha(path):
    return hashlib.sha256(path.read_bytes()).hexdigest()


def execution_copies(folder, before):
    count = 0
    for destination, original in (
        (folder / "framework/libs", "libs"),
        (folder / "harness/demos", "eval/apps/demos"),
        (folder / "harness/pandas", "eval/apps/pandas"),
    ):
        if not destination.is_dir():
            raise ValueError(f"execution snapshot missing: {destination.name}")
        expected = {
            name for name in before if name.startswith(original + "/") and name.endswith(".py")
        }
        observed = set()
        for path in sorted(destination.rglob("*.py")):
            name = f"{original}/{path.relative_to(destination)}"
            observed.add(name)
            if before.get(name) != sha(path):
                raise ValueError(f"execution snapshot differs: {name}")
            count += 1
        if expected != observed:
            raise ValueError(f"execution snapshot inventory differs: {original}")
    return count


def verify(folder, *, require_checksums=False):
    before = json.loads((folder / "source-before.json").read_text())
    count = execution_copies(folder, before)
    checksums = folder / "checksums.json"
    if require_checksums and not checksums.is_file():
        raise ValueError("checksum index required")
    if checksums.is_file():
        for name, digest in json.loads(checksums.read_text()).items():
            path = folder / name
            if path.resolve() != path.absolute() or not path.is_relative_to(folder):
                raise ValueError("invalid checksum path")
            if not path.is_file() or sha(path) != digest:
                raise ValueError(f"bundle checksum differs: {name}")
    build = json.loads((folder / "validation/lean-build.json").read_text())
    for name, digest in build["source_sha256"].items():
        source = "native/worker_route_shim.c" if name == "worker_route_shim.c" else name
        if before.get(f"proofs/worker-route/{source}") != digest:
            raise ValueError(f"Lean build source differs: {name}")
    launcher = json.loads((folder / "validation/launcher-build.json").read_text())
    source = "libs/prebuilt/langgraph/prebuilt/security/native/macos_launcher.c"
    if before[source] != launcher["source_digest"]:
        raise ValueError("launcher build source differs")

    # Replay the verifier captured with the cohort, using the verified framework
    # copies. This avoids silently changing the oracle or checker after a run.
    digest = before["eval/remaining/verify_macos_baseline.py"]
    captured = folder / "sources" / digest
    if sha(captured) != digest:
        raise ValueError("captured verifier differs")
    sys.path[:0] = [
        str(folder / "framework/libs" / library)
        for library in ("prebuilt", "langgraph", "checkpoint", "sdk-py")
    ]
    loader = SourceFileLoader("captured_macos_campaign_verifier", str(captured))
    spec = importlib.util.spec_from_loader(loader.name, loader)
    module = importlib.util.module_from_spec(spec)
    sys.modules[spec.name] = module
    loader.exec_module(module)
    report = module.verify(folder)
    report.update(
        execution_snapshots_verified=count,
        checksums_verified=checksums.is_file(),
        build_sources_verified=True,
        captured_verifier_sha256=digest,
    )
    return report


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("folder", type=Path)
    parser.add_argument("--require-checksums", action="store_true")
    args = parser.parse_args()
    try:
        report = verify(args.folder.resolve(), require_checksums=args.require_checksums)
    except (OSError, ValueError, KeyError, TypeError, IndexError) as exc:
        report = dict(evidence_valid=False, issues=[f"{type(exc).__name__}: {exc}"])
    print(json.dumps(report, indent=2, sort_keys=True))
    raise SystemExit(0 if report["evidence_valid"] else 1)


if __name__ == "__main__":
    main()
