"""Archive compact final demo outputs without duplicating large input fixtures."""

from __future__ import annotations

import gzip
import tarfile
from pathlib import Path

HERE = Path(__file__).resolve().parent
SUFFIXES = {".json", ".jsonl", ".png", ".log", ".txt"}


def archive(condition: str, run: str) -> tuple[int, int]:
    source = HERE / run
    target = HERE / f"app-{condition}-outputs.tar.gz"
    if not (source / "summary.json").is_file():
        raise ValueError(f"incomplete application run: {run}")
    selected = [
        item
        for item in source.rglob("*")
        if item.is_file()
        and item.suffix in SUFFIXES
        and (
            item.is_relative_to(source / "demos")
            or item.is_relative_to(source / "native-evidence")
            or item.parent == source
        )
    ]
    with (
        target.open("wb") as raw,
        gzip.GzipFile(fileobj=raw, mode="wb", filename="", mtime=0) as compressed,
        tarfile.open(fileobj=compressed, mode="w") as bundle,
    ):
        for path in sorted(selected):
            bundle.add(path, arcname=path.relative_to(source), recursive=False)
    return len(selected), target.stat().st_size


if __name__ == "__main__":
    for condition, run in (
        ("baseline", "app-baseline-final-03"),
        ("argus", "app-argus-final-02"),
    ):
        count, size = archive(condition, run)
        print(f"{condition}: {count} output files, {size} compressed bytes")
