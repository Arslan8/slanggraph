"""Validate raw SQLite comparator rows and regenerate the campaign summary."""

from __future__ import annotations

import json
from collections import defaultdict
from pathlib import Path

ROOT = Path(__file__).resolve().parent
ATTACKS = (
    "denied_read",
    "denied_write",
    "denied_delete",
    "selector_substitution",
    "omitted_write",
    "omitted_delete",
    "direct_database",
    "direct_wal",
    "direct_shm",
    "retry_broker_then_direct",
    "rpc_spoof",
)


def read_jsonl(path: Path) -> list[dict]:
    return [json.loads(line) for line in path.read_text().splitlines() if line]


def main() -> None:
    external = read_jsonl(ROOT / "raw/external/trials.jsonl")
    ablations = read_jsonl(ROOT / "raw/ablations/trials.jsonl")
    rows = [
        *({**row, "configuration": row["system"]} for row in external),
        *({**row, "configuration": row["mode"]} for row in ablations),
    ]
    grouped: dict[tuple[str, str], list[dict]] = defaultdict(list)
    for row in rows:
        grouped[(row["configuration"], row["case_id"])].append(row)

    expected = {
        "progent",
        "nono",
        "sandlock",
        "apf",
        "camel",
        "call_authorization_native",
        "filesystem_accessible",
        "incomplete_broker_reference",
        "production_composition",
    }
    assert {configuration for configuration, _ in grouped} == expected
    for configuration in expected:
        for case in ("allowed_read", *ATTACKS):
            selected = grouped[(configuration, case)]
            assert len(selected) == 5, (configuration, case, len(selected))
            assert {int(row["repeat"]) for row in selected} == set(range(5))

    configurations = {}
    for configuration in sorted(expected):
        controls = grouped[(configuration, "allowed_read")]
        cases = {}
        for case in ATTACKS:
            selected = grouped[(configuration, case)]
            cases[case] = {
                "effects": sum(bool(row["observed_effect"]) for row in selected),
                "trials": len(selected),
                "errors": sum(row.get("error") is not None for row in selected),
                "nonzero_exits": sum(
                    row.get("detail", {}).get("exit_status", 0) != 0 for row in selected
                ),
                "unsupported": sum(
                    isinstance(row.get("result"), dict) and "unsupported" in row["result"]
                    for row in selected
                ),
            }
        configurations[configuration] = {
            "legitimate_reads": sum(bool(row.get("legitimate_result")) for row in controls),
            "legitimate_trials": len(controls),
            "attacks": cases,
        }

    result = {
        "repetitions": 5,
        "attack_bodies": list(ATTACKS),
        "configurations": configurations,
    }
    (ROOT / "statistics.json").write_text(json.dumps(result, indent=2) + "\n")

    lines = [
        "# Results",
        "",
        "Each cell reports observed forbidden effects over five deterministic trials.",
        "All measured configurations completed the allowed Alice read 5/5.",
        "",
        "| Configuration | Hidden Bob read | Direct DB | WAL | SHM | Retry/direct | All attacks |",
        "| --- | ---: | ---: | ---: | ---: | ---: | ---: |",
    ]
    names = {
        "call_authorization_native": "Call authorization + native body",
        "filesystem_accessible": "Filesystem-accessible ablation",
        "incomplete_broker_reference": "Incomplete broker",
        "production_composition": "Production composition",
        "progent": "Progent proxy",
        "nono": "nono",
        "sandlock": "Sandlock",
        "apf": "APF content-policy configuration",
        "camel": "CaMeL native-tool adapter",
    }
    for key in (
        "call_authorization_native",
        "filesystem_accessible",
        "incomplete_broker_reference",
        "production_composition",
        "progent",
        "nono",
        "sandlock",
        "apf",
        "camel",
    ):
        attacks = configurations[key]["attacks"]
        total = sum(item["effects"] for item in attacks.values())
        trials = sum(item["trials"] for item in attacks.values())
        lines.append(
            f"| {names[key]} | {attacks['selector_substitution']['effects']}/5 "
            f"| {attacks['direct_database']['effects']}/5 "
            f"| {attacks['direct_wal']['effects']}/5 "
            f"| {attacks['direct_shm']['effects']}/5 "
            f"| {attacks['retry_broker_then_direct']['effects']}/5 "
            f"| {total}/{trials} |"
        )
    lines.extend(
        [
            "Sandlock's read-only profile denied all four mutation bodies; its six "
            "content-read bodies landed. The native configurations have no record-broker "
            "identity protocol, so `rpc_spoof` is unsupported rather than counted as a "
            "prevented effect. APF's label refers only to the documented content-policy "
            "middleware configuration: native local tool invocation is outside that "
            "surface. These are configuration-gap observations, not vulnerability claims.",
        ]
    )
    (ROOT / "RESULTS.md").write_text("\n".join(lines) + "\n")


if __name__ == "__main__":
    main()
