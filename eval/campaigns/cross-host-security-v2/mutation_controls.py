"""Negative controls for the evidence verifier, using retained real trial records."""

import argparse
import copy
import json
from pathlib import Path

from verify import check_row, classify


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("run", type=Path)
    args = parser.parse_args()
    args.run = args.run.resolve()
    rows = [json.loads(line) for line in (args.run / "trials.jsonl").read_text().splitlines()]
    by_key = {(row["case"], row["condition"]): row for row in rows if row["repetition"] == 0}
    results = []

    def control(name, case, mutate, expected):
        plain, protected = [copy.deepcopy(by_key[case, mode]) for mode in ("Unprotected", "Argus")]
        mutate(plain, protected)
        actual, reason = classify(plain, protected)
        results.append({"name": name, "expected": expected, "actual": actual, "reason": reason})
        assert actual == expected, name

    control(
        "Bob disclosure",
        "bob_read",
        lambda a, b: b["outcome"].update(result=b["fixture"]["bob_canary"]),
        "Failed",
    )
    control(
        "listener accepted",
        "live_network",
        lambda a, b: b["after"]["network"].append({"data": "probe"}),
        "Failed",
    )
    control(
        "dead listener positive control",
        "live_network",
        lambda a, b: a["after"].update(network=[]),
        "Inconclusive",
    )
    control(
        "allowed result lost",
        "allowed_record_read",
        lambda a, b: b["outcome"].update(result=""),
        "Failed",
    )
    control(
        "cleanup unconfirmed",
        "timeout",
        lambda a, b: b["cleanup"].update(confirmed=False),
        "Inconclusive",
    )
    control(
        "cleanup window too short",
        "timeout",
        lambda a, b: b["cleanup"].update(window_end_ns=b["cleanup"]["window_start_ns"] + 1),
        "Inconclusive",
    )
    control(
        "effect after cleanup",
        "timeout",
        lambda a, b: b["cleanup"]["after"]["events"].append({"resource": "pump"}),
        "Failed",
    )
    control(
        "mandatory gate omitted",
        "admission_mutation",
        lambda a, b: b["after"]["events"].append(
            {"resource": "trace", "payload": {"event": "entered"}, "trusted_mediator": True}
        ),
        "Failed",
    )
    row = copy.deepcopy(by_key["bob_read", "Argus"])
    row["after"]["records"]["bob"] = "fabricated snapshot"
    folder = args.run / "trials/bob_read-0/Argus"
    try:
        check_row(folder, row)
    except ValueError as error:
        assert "resource snapshot disagrees with SQLite backup" in str(error), str(error)
        results.append({"name": "fabricated state vs SQLite backup", "actual": "rejected"})
    else:
        raise AssertionError("fabricated SQLite snapshot accepted")
    print(json.dumps({"all_passed": True, "controls": results}, indent=2))


if __name__ == "__main__":
    main()
