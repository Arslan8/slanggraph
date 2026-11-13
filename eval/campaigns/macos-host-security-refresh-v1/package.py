"""Package the qualified and final macOS host-security evidence with checksums."""

from __future__ import annotations

import argparse
import gzip
import hashlib
import json
import shutil
import tarfile
import tempfile
from pathlib import Path

HERE = Path(__file__).resolve().parent
CHUNK = 8 * 1024 * 1024
SOURCE_FILES = (
    "configuration.json",
    "environment.json",
    "native-configuration.json",
    "source-before.json",
    "source-after.json",
)


def sha256(path: Path) -> str:
    digest = hashlib.sha256()
    with path.open("rb") as source:
        for block in iter(lambda: source.read(1024 * 1024), b""):
            digest.update(block)
    return digest.hexdigest()


def compact(run: Path, prefix: str) -> None:
    for name in SOURCE_FILES:
        shutil.copy2(run / name, HERE / f"{prefix}-{name}")
    shutil.copy2(run.with_name(run.name + "-request.json"), HERE / f"{prefix}-request.json")
    shutil.copy2(HERE / f"{run.name}-verification.json", HERE / f"{prefix}-verification.json")
    with (
        (HERE / f"{prefix}-trials.jsonl.gz").open("wb") as raw,
        gzip.GzipFile(fileobj=raw, mode="wb", filename="", mtime=0) as compressed,
    ):
        compressed.write((run / "trials.jsonl").read_bytes())


def normalized(info: tarfile.TarInfo) -> tarfile.TarInfo | None:
    if "__pycache__" in Path(info.name).parts or info.name.endswith(".pyc"):
        return None
    info.uid = info.gid = 0
    info.uname = info.gname = ""
    info.mtime = 0
    return info


def archive_final(run: Path) -> dict:
    with tempfile.NamedTemporaryFile(
        dir=HERE, prefix=".final-raw-", suffix=".tar.gz", delete=False
    ) as temporary:
        temporary_path = Path(temporary.name)
    try:
        with (
            temporary_path.open("wb") as raw,
            gzip.GzipFile(fileobj=raw, mode="wb", filename="", mtime=0) as compressed,
            tarfile.open(fileobj=compressed, mode="w") as bundle,
        ):
            for path in sorted(run.rglob("*")):
                if path.is_file() and "__pycache__" not in path.parts and path.suffix != ".pyc":
                    bundle.add(
                        path,
                        arcname=f"{run.name}/{path.relative_to(run)}",
                        recursive=False,
                        filter=normalized,
                    )
            request = run.with_name(run.name + "-request.json")
            bundle.add(request, arcname=request.name, recursive=False, filter=normalized)
        parts = []
        with temporary_path.open("rb") as source:
            for number, block in enumerate(iter(lambda: source.read(CHUNK), b"")):
                path = HERE / f"final-raw.tar.gz.part-{number:02d}"
                path.write_bytes(block)
                parts.append({"name": path.name, "sha256": sha256(path), "bytes": len(block)})
        return {
            "schema": 1,
            "archive_sha256": sha256(temporary_path),
            "archive_bytes": temporary_path.stat().st_size,
            "parts": parts,
            "archive_root": run.name,
            "trial_records": 450,
        }
    finally:
        temporary_path.unlink(missing_ok=True)


def checksums() -> int:
    names = {
        "README.md",
        "audit.py",
        "package.py",
        "verify_package.py",
        "native-configuration.json",
        "archive-index.json",
    }
    for prefix in ("qualification", "final"):
        names.update(f"{prefix}-{name}" for name in SOURCE_FILES)
        names.update(
            {
                f"{prefix}-request.json",
                f"{prefix}-verification.json",
                f"{prefix}-case-results.json",
                f"{prefix}-case-results.csv",
                f"{prefix}-trials.jsonl.gz",
            }
        )
    names.update(path.name for path in HERE.glob("final-raw.tar.gz.part-*"))
    files = [HERE / name for name in sorted(names)]
    (HERE / "SHA256SUMS").write_text("".join(f"{sha256(path)}  {path.name}\n" for path in files))
    return len(files)


def main() -> None:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--qualification-run", type=Path)
    parser.add_argument("--final-run", type=Path)
    parser.add_argument("--checksums-only", action="store_true")
    args = parser.parse_args()
    if not args.checksums_only:
        if args.qualification_run is None or args.final_run is None:
            parser.error("both run paths are required unless --checksums-only is set")
        qualification, final = args.qualification_run.resolve(), args.final_run.resolve()
        compact(qualification, "qualification")
        compact(final, "final")
        (HERE / "archive-index.json").write_text(
            json.dumps(archive_final(final), indent=2, sort_keys=True) + "\n"
        )
    print(json.dumps({"checksums": checksums()}))


if __name__ == "__main__":
    main()
