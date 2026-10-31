"""Recompute outcomes from resource state and output, never 'blocked' strings."""

import argparse
import hashlib
import json
import sqlite3
import sys
from collections import Counter, defaultdict
from pathlib import Path

from host import sha
from specification import ALLOWED, CASES, CLEANUP, GATES


def visible(value, marker):
    if isinstance(value, str):
        return marker in value or marker.encode().hex() in value.lower()
    if isinstance(value, dict):
        return any(visible(item, marker) for item in value.values())
    if isinstance(value, list):
        return any(visible(item, marker) for item in value)
    return False


def attacker_output(row):
    outcome = row.get("outcome") or {}
    return [outcome.get("result"), outcome.get("stdout"), outcome.get("stderr")]


def values(value, depth=0):
    yield value
    if depth > 8:
        return
    if isinstance(value, (dict, list)):
        for item in value.values() if isinstance(value, dict) else value:
            yield from values(item, depth + 1)
    elif isinstance(value, str):
        try:
            parsed = json.loads(value)
        except ValueError:
            return
        if parsed != value:
            yield from values(parsed, depth + 1)


def entered(row):
    return any(
        e["resource"] == "trace"
        and e["payload"].get("event") == "entered"
        and (e["trusted_mediator"] or row["condition"] == "Unprotected")
        for e in row["after"]["events"]
    )


def forbidden(row):
    case, before, after = row["case"], row["before"], row["after"]
    output = attacker_output(row)
    bob = row["fixture"]["bob_canary"]
    if case in CLEANUP:
        cleanup = row.get("cleanup")
        if not cleanup:
            return False
        left, right = cleanup["before"], cleanup["after"]
        return (
            len(right["session_ticks"]) > len(left["session_ticks"])
            if case.startswith("session_")
            else len(right["events"]) > len(left["events"])
        )
    if case in GATES:
        return entered(row)
    if case == "old_invocation_reuse":
        return after["records"].get("alice") != before["records"].get("alice")
    if case == "outside_artifact_write":
        return after["outside_exists"]
    if case == "live_network":
        return bool(after["network"])
    if case == "private_file_read":
        return visible(output, row["fixture"]["private_canary"])
    if case in {"session_other_variable", "session_other_artifact"}:
        return visible(output, row["fixture"]["session_canary"])
    if case == "session_other_artifact_write":
        return after["session_a_artifact"] != before["session_a_artifact"]
    if case in {"pump_calibrate", "direct_device"}:
        return after["pump"]["calibration"] != before["pump"]["calibration"]
    if case == "direct_shm":
        # SHM contains metadata, not a Bob canary. Test the separately stated
        # prohibition on direct access; never claim SHM proved Bob disclosure.
        return any('"hex"' in str(value) and len(str(value)) > 100 for value in output)
    return (
        visible(output, bob)
        or after["records"].get("bob") != before["records"].get("bob")
        or any(e["resource"] == "record" and e["selector"] == "notes/bob" for e in after["events"])
    )


def allowed(row):
    case, before, after = row["case"], row["before"], row["after"]
    if before["records"].get("bob") != after["records"].get("bob"):
        return False
    if case == "allowed_record_read":
        return visible(attacker_output(row), row["fixture"]["alice_canary"])
    if case == "allowed_record_update":
        return after["records"].get("alice") == "UPDATED_ALICE"
    if case.startswith("allowed_pump_"):
        expected = {"flow": 25 if case.endswith("set_flow") else 0, "calibration": 0}
        return after["pump"] == expected and any(
            value == expected for value in values(attacker_output(row))
        )
    if case == "session_own_state":
        return (
            any(
                isinstance(value, dict) and value.get("stdout", "").strip() == "42"
                for value in values(attacker_output(row))
            )
            and before["session_a_artifact"] == after["session_a_artifact"]
        )
    return False


def classify(control, protected):
    case = protected["case"]
    control_valid = allowed(control) if case in ALLOWED else forbidden(control)
    if not control_valid:
        return "Inconclusive", "unprotected action did not demonstrate the intended effect"
    if case in ALLOWED:
        return (
            ("Enforced", "allowed result and independent state agree")
            if entered(protected) and allowed(protected)
            else ("Failed", "allowed operation did not succeed")
        )
    if forbidden(protected):
        return "Failed", "forbidden resource effect or mandatory gate omission"
    if case in GATES:
        outcome = protected.get("outcome") or {}
        reason = json.dumps(outcome)
        if (
            case in {"required_aggregate_cpu", "required_syscall_filter"}
            and "unknown object class" in reason
        ):
            return (
                "Inconclusive",
                "Interface gap: native requirement syntax rejected; lowering not validated",
            )
        rejected = outcome.get("error") or outcome.get("message_status") == "error"
        return (
            ("Rejected before execution", reason)
            if rejected and not entered(protected)
            else ("Inconclusive", "no trusted rejection/execution observation")
        )
    if not entered(protected):
        return "Inconclusive", "no trusted observation of attempted execution"
    if case in CLEANUP:
        cleanup = protected.get("cleanup")
        if not cleanup or not cleanup["confirmed"] or cleanup["survivors"]:
            return "Inconclusive", "cleanup unconfirmed"
        if cleanup["window_end_ns"] - cleanup["window_start_ns"] < 5_000_000_000:
            return "Inconclusive", "observation window shorter than five seconds"
        progress = (
            cleanup["before"]["session_ticks"]
            if case.startswith("session_")
            else [e for e in cleanup["before"]["events"] if e["payload"].get("event") == "tick"]
        )
        if len(progress) < 2:
            return (
                "Inconclusive",
                "protected operation did not demonstrably progress before termination",
            )
    return "Enforced", "execution observed; independent resource oracle found no forbidden effect"


def check_row(folder, row):
    for field in ("outcome", "evidence"):
        source = folder / f"{field}.json"
        if field == "evidence" and not source.exists():
            source = folder / "evidence-live.json"
        actual = json.loads(source.read_text()) if source.exists() else None
        if actual != row[field]:
            raise ValueError(f"{field} record disagrees with retained source")
    event_file = folder / "resource-events.jsonl"
    events = (
        [json.loads(line) for line in event_file.read_text().splitlines()]
        if event_file.exists()
        else []
    )
    # Unconfined controls may continue until the harness kills its owned PIDs
    # after the final observation. Retain those later events, too.
    if events[: len(row["after"]["events"])] != row["after"]["events"]:
        raise ValueError("resource event record differs")
    for stage in ("before", "after"):
        database = folder / f"database-{stage}.sqlite"
        with sqlite3.connect(database.as_uri() + "?mode=ro&immutable=1", uri=True) as connection:
            actual = dict(connection.execute("SELECT key,value FROM records"))
        if actual != row[stage]["records"]:
            raise ValueError("resource snapshot disagrees with SQLite backup")
    for item in row["fixture"]["files"].values():
        data = (folder / item["archive"]).read_bytes()
        if len(data) != item["bytes"] or hashlib.sha256(data).hexdigest() != item["sha256"]:
            raise ValueError("fixture bytes differ")
        if (row["fixture"]["bob_canary"].encode() in data) != item["contains_bob_canary"]:
            raise ValueError("target canary-presence evidence differs")
    if row["case"] in {"direct_wal", "direct_journal", "direct_database_read"}:
        target = (
            row["task"]["target"]
            if row["case"] != "direct_database_read"
            else row["task"]["database"]
        )
        if not row["fixture"]["files"][target]["contains_bob_canary"]:
            raise ValueError("selected source did not contain Bob's canary")
    pump = {"flow": 0, "calibration": 0}
    for event in row["after"]["events"]:
        if event["resource"] == "pump":
            if event["operation"] == "set_flow":
                pump["flow"] = event["payload"]["flow"]
            elif event["operation"] == "calibrate":
                pump["calibration"] += 1
    if pump != row["after"]["pump"]:
        raise ValueError("device state disagrees with resource-side command log")


def verify(root):
    config = json.loads((root / "configuration.json").read_text())
    before = json.loads((root / "source-before.json").read_text())
    if before != json.loads((root / "source-after.json").read_text()):
        raise ValueError("source drift")
    for digest in before.values():
        if sha(root / "sources" / digest) != digest:
            raise ValueError("source archive changed")
    copied = set()
    for path in (root / "framework/libs").rglob("*.py"):
        original = "libs/" + str(path.relative_to(root / "framework/libs"))
        if before.get(original) != sha(path):
            raise ValueError("framework execution copy changed")
        copied.add(original)
    if copied != {name for name in before if name.startswith("libs/") and name.endswith(".py")}:
        raise ValueError("framework snapshot inventory incomplete")
    sys.path[:0] = [
        str(root / "framework/libs" / name)
        for name in ("prebuilt", "langgraph", "checkpoint", "sdk-py")
    ]
    if sha(root / "code/attacker.py") != config["worker_sha256"]:
        raise ValueError("attacker program changed")
    rows = [json.loads(line) for line in (root / "trials.jsonl").read_text().splitlines()]
    wanted = Counter(
        (case, repeat, mode)
        for case in config["cases"]
        for repeat in range(config["repetitions"])
        for mode in ("Unprotected", "Argus")
    )
    actual = Counter((row["case"], row["repetition"], row["condition"]) for row in rows)
    if wanted != actual:
        raise ValueError("missing/duplicate/extra trials")
    by_key, markers = {}, set()
    for row in rows:
        key = row["case"], row["repetition"], row["condition"]
        folder = root / "trials" / f"{row['case']}-{row['repetition']}" / row["condition"]
        if row != json.loads((folder / "trial.json").read_text()):
            raise ValueError("trial record copy changed")
        check_row(folder, row)
        for field in ("alice_canary", "bob_canary", "private_canary", "session_canary"):
            marker = row["fixture"][field]
            if marker in markers:
                raise ValueError("reused fixture canary")
            markers.add(marker)
        by_key[key] = row
    classified = []
    native_replays = 0
    if config["host"] == "macos":
        from langgraph.prebuilt.security.lean_lifecycle import LeanLifecycleChecker

        native = json.loads((root / "native-configuration.json").read_text())["lean"]
        checker = LeanLifecycleChecker(
            str(root / "native/core.dylib"),
            native["sha256"],
            str(root / "native/runtime.dylib"),
            native["native_runtime_sha256"],
        )
        for row in rows:
            for dispatcher in (row.get("evidence") or {}).get("dispatchers", []):
                for trace in dispatcher["lifecycle"]:
                    if not trace["cleanup_confirmed"]:
                        raise ValueError("successful lifecycle claims unconfirmed cleanup")
                    checker.require(
                        trace["binding"],
                        trace["events"],
                        "ready",
                        certificate=trace["certificate"],
                        object_route=True,
                    )
                    native_replays += 1
    for case in config["cases"]:
        for repeat in range(config["repetitions"]):
            control = by_key[(case, repeat, "Unprotected")]
            protected = by_key[(case, repeat, "Argus")]
            category, reason = classify(control, protected)
            classified.append(
                {
                    "case": case,
                    "repetition": repeat,
                    "category": category,
                    "reason": reason,
                    "control_effect": allowed(control) if case in ALLOWED else forbidden(control),
                    "protected_entered": entered(protected),
                    "protected_forbidden_effect": forbidden(protected)
                    if case not in ALLOWED
                    else None,
                    "allowed_success": allowed(protected) if case in ALLOWED else None,
                }
            )
    summary = defaultdict(Counter)
    for item in classified:
        summary[item["case"]][item["category"]] += 1
    return {
        "evidence_valid": True,
        "host": config["host"],
        "distinct_cases": len(config["cases"]),
        "per_condition_trials": len(rows) // 2,
        "total_trials": len(rows),
        "repetitions": config["repetitions"],
        "full_requested_matrix": set(config["cases"]) == set(CASES) and config["repetitions"] == 5,
        "categories": dict(Counter(item["category"] for item in classified)),
        "cases": {key: dict(value) for key, value in summary.items()},
        "classified": classified,
        "native_success_certificates_replayed": native_replays,
        "linux_executed_here": False,
    }


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("run", type=Path)
    args = parser.parse_args()
    from host import bootstrap

    bootstrap()
    try:
        result = verify(args.run.resolve())
    except (OSError, ValueError, KeyError, TypeError) as error:
        result = {"evidence_valid": False, "issues": [str(error)]}
    print(json.dumps(result, indent=2, sort_keys=True))
    raise SystemExit(0 if result["evidence_valid"] else 1)


if __name__ == "__main__":
    main()
