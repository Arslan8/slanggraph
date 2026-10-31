"""Generate an attempt ledger and counts by invoking the selected version's verifier."""

import argparse
import json
import subprocess
import sys
from collections import Counter
from pathlib import Path


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("run", type=Path)
    parser.add_argument("--verifier", type=Path, default=Path(__file__).with_name("verify.py"))
    parser.add_argument("--output", type=Path, required=True)
    args = parser.parse_args()
    result = subprocess.run(
        [sys.executable, str(args.verifier.resolve()), str(args.run.resolve())],
        check=True,
        capture_output=True,
        text=True,
    )
    verified = json.loads(result.stdout)
    assert verified["evidence_valid"]
    with args.output.open("w") as stream:
        for item in verified["classified"]:
            item["raw_trial"] = f"trials/{item['case']}-{item['repetition']}/Argus/trial.json"
            stream.write(json.dumps(item) + "\n")
    print(
        json.dumps(
            {
                "evidence_valid": True,
                "total_trials": verified["total_trials"],
                "paired_comparisons": len(verified["classified"]),
                "categories": dict(Counter(item["category"] for item in verified["classified"])),
            },
            indent=2,
        )
    )


if __name__ == "__main__":
    main()
