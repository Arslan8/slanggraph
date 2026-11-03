"""Verify before-fix disclosure, after-fix refusal, and mediated read."""

from __future__ import annotations

import gzip
import json
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1] / "campaigns/macos-resubmission-v1"
CASES = ("race_rename", "race_hardlink")


def rows(name: str) -> list[dict]:
    with gzip.open(ROOT / name, "rt") as source:
        return [json.loads(line) for line in source]


def check() -> dict:
    before = rows("before-fix-aliases.jsonl.gz")
    after = rows("advanced-trials.jsonl.gz")
    main = rows("security-trials.jsonl.gz")
    observations = []
    issues = []
    for case in CASES:
        for seed in range(3):
            old = next(
                row
                for row in before
                if row["case"] == case and row["seed"] == 0 and row["condition"] == "Argus"
            )
            new = next(
                row
                for row in after
                if row["case"] == case and row["seed"] == seed and row["condition"] == "Argus"
            )
            old_result = json.loads(old["outcome"]["message"]["content"])
            old_start = next(
                item for item in old["evidence"]["startup"] if not item.get("preflight")
            )
            marker = old["markers"]["private"]
            disclosed = (
                bytes.fromhex(old_result["hex"]).decode() == marker
                and old_result["hex"] == old["target"]["bytes"]
                and old_result["inode"] == old["target"]["inode"]
                and old_start["after_inode"] == old_result["inode"]
                and old_start["before_inode"] != old_start["after_inode"]
            )
            refusal = any(
                item.get("decision") == "unsupported"
                and item.get("tool_released") is False
                and any(
                    obligation["domain"] == "filesystem"
                    and obligation["operation"] == "read"
                    and obligation["waivable"] is False
                    for obligation in item.get("unsupported_obligations", [])
                )
                and any(
                    assessment.get("reason") == "seatbelt:filesystem-object-identity-not-enforced"
                    for assessment in item.get("assessments", [])
                )
                for item in new["evidence"]["lowering"]
            )
            if seed == 0 and not disclosed:
                issues.append(f"{case}/{seed}: before-fix disclosure not independently matched")
            if not refusal:
                issues.append(f"{case}/{seed}: after-fix pre-execution refusal not proved")
            observations.append(
                {
                    "case": case,
                    "seed": seed,
                    "before_fix_private_marker": marker,
                    "before_fix_device": old_result["dev"],
                    "before_fix_inode": old_result["inode"],
                    "authorized_path_original_inode": old_start["before_inode"],
                    "authorized_path_substituted_inode": old_start["after_inode"],
                    "before_fix_disclosed_private_content": disclosed if seed == 0 else None,
                    "after_fix_pre_execution_refusal": refusal,
                }
            )
    mediated = []
    for repeat in range(5):
        row = next(
            item
            for item in main
            if item["case"] == "allowed_record_read"
            and item["repetition"] == repeat
            and item["condition"] == "Argus"
        )
        success = (
            row["fixture"]["alice_canary"] in json.dumps(row["outcome"])
            and row["before"]["records"]["bob"] == row["after"]["records"]["bob"]
            and any(
                event["resource"] == "record"
                and event["selector"] == "notes/alice"
                and event["operation"] == "read"
                for event in row["after"]["events"]
            )
        )
        mediated.append(success)
        if not success:
            issues.append(f"allowed_record_read/{repeat}: mediated success absent")
    return {
        "evidence_valid": not issues,
        "finding": "before-fix object-identity violation disclosed private content",
        "before_fix_protected_disclosures": sum(
            item["before_fix_disclosed_private_content"] is True for item in observations
        ),
        "after_fix_pre_execution_refusals": sum(
            item["after_fix_pre_execution_refusal"] for item in observations
        ),
        "legitimate_mediated_reads": sum(mediated),
        "observations": observations,
        "issues": issues,
    }


if __name__ == "__main__":
    result = check()
    print(json.dumps(result, indent=2, sort_keys=True))
    raise SystemExit(0 if result["evidence_valid"] else 1)
