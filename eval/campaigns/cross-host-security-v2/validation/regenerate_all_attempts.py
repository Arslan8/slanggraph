"""Regenerate complete comparisons plus explicitly retained harness attempts."""

import argparse
import json
import subprocess
import sys
from collections import Counter
from pathlib import Path


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("run", type=Path)
    parser.add_argument("--output", type=Path, required=True)
    args = parser.parse_args()
    root = args.run.resolve()
    verifier = Path(__file__).resolve().parents[1] / "verify.py"
    process = subprocess.run(
        [sys.executable, str(verifier), str(root)], check=True, capture_output=True, text=True
    )
    verified = json.loads(process.stdout)
    assert verified["evidence_valid"]
    retries = [json.loads(p.read_text()) for p in sorted(root.glob("harness-resumption*.json"))]
    keys = {(r["case"], r["repetition"]) for r in retries}
    prefix = f"{root.parent.name}/{root.name}"
    rows = []
    for item in verified["classified"]:
        rows.append(
            dict(
                **item,
                attempt=2 if (item["case"], item["repetition"]) in keys else 1,
                main_matrix=True,
                condition_attempts=2,
                complete_condition_records=2,
                raw_trial=f"{prefix}/trials/{item['case']}-{item['repetition']}/Argus/trial.json",
            )
        )
    for retry in retries:
        original = root / retry["initial_raw"]
        complete = sum(
            (original / mode / "trial.json").is_file() for mode in ["Unprotected", "Argus"]
        )
        rows.append(
            dict(
                case=retry["case"],
                repetition=retry["repetition"],
                attempt=1,
                main_matrix=False,
                category=retry["initial_attempt_category"],
                reason=retry["reason"],
                condition_attempts=2,
                complete_condition_records=complete,
                raw_attempt=f"{prefix}/{retry['initial_raw']}",
            )
        )
    args.output.write_text("".join(json.dumps(row) + "\n" for row in rows))
    print(
        json.dumps(
            dict(
                main_matrix_comparisons=len(verified["classified"]),
                main_matrix_condition_trials=verified["total_trials"],
                all_comparison_attempts=len(rows),
                all_condition_attempts=sum(r["condition_attempts"] for r in rows),
                complete_condition_records=sum(r["complete_condition_records"] for r in rows),
                incomplete_condition_records=sum(
                    r["condition_attempts"] - r["complete_condition_records"] for r in rows
                ),
                all_attempt_categories=dict(Counter(r["category"] for r in rows)),
                main_matrix_categories=verified["categories"],
                source_unchanged_for_retry=all(r["source_stable"] for r in retries),
            ),
            indent=2,
        )
    )


if __name__ == "__main__":
    main()
