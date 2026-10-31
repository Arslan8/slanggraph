"""Import and recompute committed Linux observations; never relabel them new runs."""

import argparse
import hashlib
import io
import json
import subprocess
import tarfile
from pathlib import Path

from host import GIT, sha
from verify import values, visible

HERE = Path(__file__).resolve().parent
PREFIX = "eval/campaigns/current-implementation-v1/raw"


def capture():
    revision = subprocess.check_output([GIT, "rev-parse", "origin/wip"], text=True).strip()
    entries = []
    with tarfile.open(HERE / "linux-reference.tar.gz", "w:gz") as archive:
        for kind in ("sqlite", "pump"):
            for name in ("trials.jsonl", "plan.json", "policy.cedar", "manifest.slp", "worker.py"):
                path = f"{PREFIX}/{kind}-composition-v1/{name}"
                data = subprocess.check_output([GIT, "show", f"{revision}:{path}"])
                blob = subprocess.check_output(
                    [GIT, "rev-parse", f"{revision}:{path}"], text=True
                ).strip()
                member = f"{kind}/{name}"
                info = tarfile.TarInfo(member)
                info.size, info.mtime = len(data), 0
                archive.addfile(info, io.BytesIO(data))
                entries.append(
                    {
                        "member": member,
                        "repository_path": path,
                        "git_blob": blob,
                        "bytes": len(data),
                        "sha256": hashlib.sha256(data).hexdigest(),
                    }
                )
    index = {
        "evidence_tree_commit": revision,
        "execution_commit": (
            "Not recorded as a full commit in these trial rows; "
            "source_revision is the worker source hash"
        ),
        "files": entries,
        "archive_sha256": sha(HERE / "linux-reference.tar.gz"),
        "scope": "Historical Linux resource composition; no new Linux execution",
    }
    (HERE / "linux-reference.json").write_text(json.dumps(index, indent=2) + "\n")


def compare():
    index = json.loads((HERE / "linux-reference.json").read_text())
    if sha(HERE / "linux-reference.tar.gz") != index["archive_sha256"]:
        raise ValueError("Linux reference archive changed")
    contents = {}
    with tarfile.open(HERE / "linux-reference.tar.gz") as archive:
        for entry in index["files"]:
            data = archive.extractfile(entry["member"]).read()
            git_blob = hashlib.sha1(b"blob " + str(len(data)).encode() + b"\0" + data).hexdigest()
            if hashlib.sha256(data).hexdigest() != entry["sha256"] or git_blob != entry["git_blob"]:
                raise ValueError("committed Linux blob changed")
            contents[entry["member"]] = data
    observations = {
        kind: [json.loads(line) for line in contents[f"{kind}/trials.jsonl"].decode().splitlines()]
        for kind in ("sqlite", "pump")
    }
    by_case = {}
    for kind, rows in observations.items():
        cases = sorted({row["case_id"] for row in rows})
        for case in cases:
            selected = [
                row
                for row in rows
                if row["case_id"] == case and row["mode"] == "production_composition"
            ]
            controls = [
                row
                for row in rows
                if row["case_id"] == case and row["mode"] == "call_authorization_native"
            ]

            def effect(row, kind=kind):
                before, after = row["resource_before"], row["resource_after"]
                if kind == "sqlite":
                    return (
                        visible(row.get("result"), before["bob"])
                        or after.get("bob") != before["bob"]
                    )
                return before != after

            by_case[f"{kind}/{case}"] = {
                "production_trials": len(selected),
                "production_forbidden_effects": sum(effect(row) for row in selected)
                if not case.startswith("allowed_")
                else None,
                "controls_with_intended_forbidden_effect": sum(effect(row) for row in controls)
                if not case.startswith("allowed_")
                else None,
                "allowed_successes_recomputed": sum(
                    (row.get("result") or {}).get("value") == row["resource_before"].get("alice")
                    if kind == "sqlite" and case == "allowed_read"
                    else row["resource_after"].get("alice") == "updated"
                    if kind == "sqlite" and case == "allowed_write"
                    else row["resource_after"].get("flow_rate") == 25.0
                    if kind == "pump" and case == "allowed_set_flow"
                    else any(
                        isinstance(value, dict) and value.get("device_id") == "pump-1"
                        for value in values(row.get("result"))
                    )
                    if kind == "pump" and case == "allowed_inspect"
                    else False
                    for row in selected
                )
                if case.startswith("allowed_")
                else None,
                "source_revision_values": sorted({row["source_revision"] for row in selected}),
            }
    mapping = {
        "allowed_record_read": (
            "sqlite/allowed_read",
            "Same Alice-only read; db_record is alpha-renamed record. "
            "Old policy also allows Alice deletion.",
        ),
        "allowed_record_update": (
            "sqlite/allowed_write",
            "same Alice-only update and Bob unchanged; old policy also grants Alice deletion",
        ),
        "bob_read": (
            "sqlite/selector_substitution",
            "same internal Bob substitution after Alice authorization; tool envelope differs",
        ),
        "direct_database_read": (
            "sqlite/direct_database",
            "same worker direct SQLite Bob read with independent state/canary observations",
        ),
        "direct_wal": (
            "sqlite/direct_wal",
            "Same WAL probe; positive controls must actually disclose their Bob marker.",
        ),
        "direct_shm": (
            "sqlite/direct_shm",
            "Related only: the old Bob oracle does not establish SHM confidentiality.",
        ),
        "retry_after_denial": (
            "sqlite/retry_broker_then_direct",
            "No such retained case in the selected frozen Linux matrix.",
        ),
        "allowed_pump_set_flow": (
            "pump/allowed_set_flow",
            "Alice sets flow to 25 in both; payload names and other rights differ.",
        ),
        "allowed_pump_inspect": (
            "pump/allowed_inspect",
            "Alice inspects the same simulated pump; response fields and other rights differ.",
        ),
        "pump_calibrate": (
            "pump/broker_escalation",
            "Not equivalent: Charlie escalates inspect to set_flow, not Alice calibration.",
        ),
        "direct_device": (
            "pump/direct_socket",
            "Not equivalent: Unix socket/set_flow versus TCP/calibration.",
        ),
        "bob_update": (
            "sqlite/denied_write",
            "Not equivalent: old denial precedes release; new attempt is inside the worker.",
        ),
        "bob_delete": (
            "sqlite/denied_delete",
            "Not equivalent: old denial precedes release; new attempt is inside the worker.",
        ),
    }
    result = {
        "evidence_tree_commit": index["evidence_tree_commit"],
        "new_linux_trials": 0,
        "exact_same_policy_cross_host_validation": False,
        "limitation": (
            "Policies, envelopes, admission and Lean integration differ. "
            "Target requirements provide supporting historical evidence, "
            "not an identical-policy experiment."
        ),
        "historical_cases": by_case,
        "mapping": {
            case: {
                "reference": target,
                "scope": scope,
                "counts": by_case.get(target),
                "equivalence": "unavailable"
                if target not in by_case
                else "related only"
                if "not equivalent" in scope.lower() or "related only" in scope.lower()
                else "target requirement comparable; full policy not identical",
            }
            for case, (target, scope) in mapping.items()
        },
    }
    return result


if __name__ == "__main__":
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--capture", action="store_true")
    args = parser.parse_args()
    if args.capture:
        capture()
    print(json.dumps(compare(), indent=2, sort_keys=True))
