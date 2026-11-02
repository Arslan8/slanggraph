"""Capture operator-built macOS launcher, Lean artifacts, and Python roots."""

import argparse
import json
import sys
from pathlib import Path


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--launcher-manifest", type=Path, required=True)
    parser.add_argument("--lean-manifest", type=Path, required=True)
    parser.add_argument("--output", type=Path, required=True)
    parser.add_argument("--recovery-directory", type=Path, required=True)
    args = parser.parse_args()
    root = Path(__file__).resolve().parents[2]
    roots = [root / "libs" / name for name in ("prebuilt", "langgraph", "checkpoint", "sdk-py")]
    roots.extend(
        Path(value) for value in sys.path if "site-packages" in value and Path(value).is_dir()
    )
    cfg = {
        "launcher": json.loads(args.launcher_manifest.read_text()),
        "lean": json.loads(args.lean_manifest.read_text()),
        "python_roots": [str(path.resolve(strict=True)) for path in dict.fromkeys(roots)],
        "recovery_directory": str(args.recovery_directory.resolve()),
    }
    cfg["python_roots"].extend(cfg["launcher"].get("dependency_roots", ()))
    args.output.write_text(json.dumps(cfg, indent=2) + "\n")


if __name__ == "__main__":
    main()
