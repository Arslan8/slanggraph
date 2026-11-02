"""Post-run negative controls for control refusals and observed syscall activation."""

import copy
import json
import sys
from pathlib import Path

HERE = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(HERE))


def pair(run, case):
    rows = [json.loads(line) for line in (HERE / run / "trials.jsonl").read_text().splitlines()]
    return [
        next(
            r for r in rows if r["case"] == case and r["repetition"] == 0 and r["condition"] == mode
        )
        for mode in ("Unprotected", "Argus")
    ]


def main():
    from verify import classify

    results = []

    def check(name, run, case, mutate):
        plain, protected = copy.deepcopy(pair(run, case))
        mutate(protected)
        actual, reason = classify(plain, protected)
        assert actual == "Inconclusive", (name, actual, reason)
        results.append(dict(name=name, expected="Inconclusive", actual=actual, reason=reason))

    def remove_refusal(row):
        for d in row["evidence"]["dispatchers"]:
            d["lowering"] = []

    def changed_refusal(row, field):
        for d in row["evidence"]["dispatchers"]:
            for record in d["lowering"]:
                if record.get("decision") == "unsupported":
                    if field == "released":
                        record["tool_released"] = True
                    else:
                        for obligation in record["unsupported_obligations"]:
                            obligation["selector"] = "unrelated"

    for case in ("required_aggregate_cpu", "required_syscall_filter"):
        check(case + ": no lowerer record", "run-macos-02", case, remove_refusal)
        for field in ("released", "selector"):
            check(
                case + ": wrong " + field,
                "run-macos-02",
                case,
                lambda row, field=field: changed_refusal(row, field),
            )

    def remove_receipts(row):
        for d in row["evidence"]["dispatchers"]:
            d["receipts"] = []

    def remove_kernel_state(row):
        for process in row["observed_processes"]:
            process["confinement"] = None

    for label, mutate in [
        ("no activation receipt", remove_receipts),
        ("no observed kernel state", remove_kernel_state),
    ]:
        check(
            "Linux minimal filter: " + label,
            "run-linux-02/security",
            "required_syscall_filter",
            mutate,
        )
    print(json.dumps(dict(all_passed=True, controls=results), indent=2))


if __name__ == "__main__":
    main()
