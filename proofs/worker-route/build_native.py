"""Build the proved worker-route decision core as an in-process native library."""

from __future__ import annotations

import argparse
import hashlib
import json
import subprocess
from pathlib import Path


def main() -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument("--lake", default="lake")
    parser.add_argument("--cc", default="cc")
    parser.add_argument("--output", type=Path, required=True)
    args = parser.parse_args()
    root = Path(__file__).resolve().parent
    subprocess.run([args.lake, "build", "workerRoute"], cwd=root, check=True)
    prefix = subprocess.run(
        [args.lake, "env", "lean", "--print-prefix"],
        cwd=root,
        check=True,
        stdout=subprocess.PIPE,
        text=True,
    ).stdout.strip()
    output = args.output.resolve()
    output.parent.mkdir(parents=True, exist_ok=True)
    shim = output.with_suffix(".shim.o")
    compiler = str(Path(prefix) / "bin/clang")
    include = str(Path(prefix) / "include")
    subprocess.run(
        [
            args.cc,
            "-c",
            "-O3",
            "-DNDEBUG",
            "-Wall",
            "-Wextra",
            "-Werror",
            "-fPIC",
            "-fvisibility=hidden",
            "-I",
            include,
            "-o",
            str(shim),
            str(root / "native/worker_route_shim.c"),
        ],
        check=True,
    )
    objects = [
        str(root / f".lake/build/ir/{name}.c.o.export")
        for name in ("Main", "WorkerRoute", "ReceiptCoverage", "GrantCoverage")
    ]
    lean_lib = str(Path(prefix) / "lib/lean")
    link = [
        compiler,
        "-shared",
        "-o",
        str(output),
        str(shim),
        *objects,
        "-L",
        lean_lib,
        "-Wl,-rpath,$ORIGIN",
        "-lleanshared",
        "-lpthread",
        "-ldl",
        "-lrt",
        "-lm",
        "-Wl,-z,defs",
        "-Wl,-soname,libargus_worker_route.so",
    ]
    subprocess.run(link, check=True)
    digest = hashlib.sha256(output.read_bytes()).hexdigest()
    runtime = Path(prefix) / "lib/lean/libleanshared.so"
    manifest = {
        "library": str(output),
        "sha256": digest,
        "native_runtime": str(runtime),
        "native_runtime_sha256": hashlib.sha256(runtime.read_bytes()).hexdigest(),
        "lean_toolchain": (root / "lean-toolchain").read_text().strip(),
        "source_sha256": {
            path.name: hashlib.sha256(path.read_bytes()).hexdigest()
            for path in (
                root / "WorkerRoute.lean",
                root / "ReceiptCoverage.lean",
                root / "GrantCoverage.lean",
                root / "Main.lean",
                root / "native/worker_route_shim.c",
            )
        },
    }
    output.with_suffix(output.suffix + ".json").write_text(
        json.dumps(manifest, indent=2) + "\n"
    )
    shim.unlink()
    print(json.dumps(manifest, indent=2))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
