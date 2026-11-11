"""Validate completeness and invariants of a unified-final-v1 result directory."""

from __future__ import annotations

import argparse
import json
from collections import Counter
from pathlib import Path
from typing import Any

from campaign import (
    RECORD_FIELDS,
    Cell,
    config_id,
    expected_route,
    load_config,
    request_cells,
    write_json,
)


class ValidationError(ValueError):
    pass


def read_jsonl(path: Path) -> list[dict[str, Any]]:
    if not path.exists():
        return []
    result = []
    for number, line in enumerate(path.read_text(encoding="utf-8").splitlines(), 1):
        if not line.strip():
            continue
        try:
            value = json.loads(line)
        except json.JSONDecodeError as exc:
            raise ValidationError(f"{path}:{number}: invalid JSON: {exc}") from exc
        if type(value) is not dict:
            raise ValidationError(f"{path}:{number}: record must be an object")
        result.append(value)
    return result


def _cell(record: dict[str, Any]) -> Cell:
    return Cell(
        record["evaluation"],
        record["mode"],
        record["workload"],
        record["task"],
        record["session"],
        record["repetition"],
        record["phase"],
        record["seed"],
    )


def validate_request_records(
    records: list[dict[str, Any]], config: dict[str, Any], *, complete: bool
) -> list[str]:
    errors: list[str] = []
    expected_config = config_id(config)
    keys = Counter()
    builds = set()
    for index, record in enumerate(records):
        missing = RECORD_FIELDS.difference(record)
        if missing:
            errors.append(f"record {index} missing fields: {sorted(missing)}")
            continue
        cell = _cell(record)
        keys[cell.key] += 1
        builds.add(record["build_id"])
        if record["campaign_id"] != config["campaign_id"]:
            errors.append(f"record {index} has wrong campaign_id")
        if record["config_id"] != expected_config:
            errors.append(f"record {index} has mixed configuration")
        if record["runtime_start_ns"] > record["runtime_end_ns"]:
            errors.append(f"record {index} has reversed runtime timestamps")
        if record["runtime_ns"] != record["runtime_end_ns"] - record["runtime_start_ns"]:
            errors.append(f"record {index} runtime_ns does not match timestamps")
        if type(record["preflight_ns"]) is not int or record["preflight_ns"] < 0:
            errors.append(f"record {index} has invalid preflight_ns")
        expected = expected_route(config, cell)
        # The application runner reports its native baseline label while the
        # route microbenchmark uses the security-oriented ``unprotected``
        # label.  They denote the same absence of an isolation route; retain
        # the raw label instead of rewriting completed measurements.
        route_matches = record["route"] == expected or (
            cell.mode == "baseline" and expected == "unprotected" and record["route"] == "baseline"
        )
        if not route_matches:
            errors.append(
                f"record {index} unexpected route {record['route']!r}; expected {expected!r}"
            )
        if record["phase"] == "measured" and record.get("delay_injection"):
            errors.append(f"record {index} retained a qualification delay injection")
        if record["mode"].startswith("argus"):
            counters = record["counters"]
            # Authorization is invocation-dependent.  A model response that
            # invokes no tool has no operation to authorize, while cleanup is
            # still mandatory.  Any observed tool invocation must have a
            # corresponding authorization counter.
            if record.get("executed_tools") and counters.get("authorization_checks", 0) < 1:
                errors.append(f"record {index} missing Argus counter authorization_checks")
            if counters.get("cleanup_completed", 0) < 1:
                errors.append(f"record {index} missing Argus counter cleanup_completed")
            if counters.get("normal_fallbacks", 0) or counters.get("debug_fallbacks", 0):
                errors.append(f"record {index} used a forbidden fallback")
            if record["mode"] == "argus-language" and counters.get("host_fallbacks", 0):
                errors.append(f"record {index} silently fell back from forced language")
        if record["evaluation"] == 1 and record["mode"] in {"nono", "apf"}:
            if record.get("policy_category") != "best-available-reduced-enforcement":
                errors.append(
                    f"record {index} gives {record['mode']} an unsupported equivalence label"
                )
            if not record.get("omitted_obligation"):
                errors.append(f"record {index} omits the comparator enforcement gap")
    duplicates = [key for key, count in keys.items() if count != 1]
    if duplicates:
        errors.append(f"duplicate request samples: {duplicates[:5]}")
    if len(builds) > 1:
        errors.append(f"mixed builds in request records: {sorted(builds)}")
    if complete:
        wanted = {cell.key for cell in request_cells(config)}
        missing = wanted.difference(keys)
        unexpected = set(keys).difference(wanted)
        if missing:
            errors.append(
                f"missing {len(missing)} scheduled request samples; first={sorted(missing)[:3]}"
            )
        if unexpected:
            errors.append(
                f"unexpected {len(unexpected)} request samples; first={sorted(unexpected)[:3]}"
            )
    return errors


def validate_security(
    records: list[dict[str, Any]], config: dict[str, Any], complete: bool
) -> list[str]:
    errors: list[str] = []
    keys = Counter()
    for index, record in enumerate(records):
        required = {
            "campaign_id",
            "config_id",
            "build_id",
            "backend",
            "case",
            "repetition",
            "applicable",
            "outcome",
            "oracle_passed",
            "positive_control_passed",
            "obligation",
        }
        missing = required.difference(record)
        if missing:
            errors.append(f"security record {index} missing fields: {sorted(missing)}")
            continue
        key = (record["backend"], record["case"], record["repetition"])
        keys[key] += 1
        if record["config_id"] != config_id(config):
            errors.append(f"security record {index} has mixed configuration")
        if (
            record["applicable"]
            and not record["positive_control_passed"]
            and not (
                record.get("excluded_from_prevention_counts") is True
                and record["outcome"] == "inconclusive"
            )
        ):
            errors.append(f"security record {index} lacks a working positive control")
        if (
            record["applicable"]
            and record["outcome"] == "prevented"
            and not record["oracle_passed"]
        ):
            errors.append(f"security record {index} claims prevention without effect oracle")
    if any(count != 1 for count in keys.values()):
        errors.append("duplicate host-security samples")
    if complete:
        manifest = json.loads((Path(__file__).with_name("host_cases.json")).read_text())
        wanted = {
            (backend, case["id"], repetition)
            for backend in config["evaluations"][1]["backends"]
            for case in manifest["cases"]
            if case.get(backend, False)
            for repetition in range(config["evaluations"][1]["repetitions_per_case"])
        }
        missing = wanted.difference(keys)
        if missing:
            errors.append(
                f"missing {len(missing)} host-security samples; first={sorted(missing)[:3]}"
            )
    return errors


def validate_sustained(
    records: list[dict[str, Any]], config: dict[str, Any], complete: bool
) -> list[str]:
    errors: list[str] = []
    keys = Counter()
    for index, record in enumerate(records):
        required = {
            "mode",
            "concurrency",
            "session",
            "warmup_seconds",
            "issue_seconds",
            "offered",
            "completed",
            "failed",
            "latency_ns",
            "queue_wait_ns",
            "pool_misses",
            "replenishments",
            "initial_ready",
            "final_ready",
            "drain_ns",
            "restoration_ns",
            "config_id",
            "build_id",
        }
        missing = required.difference(record)
        if missing:
            errors.append(f"sustained record {index} missing fields: {sorted(missing)}")
            continue
        key = (record["mode"], record["concurrency"], record["session"])
        keys[key] += 1
        if record["warmup_seconds"] != 10 or record["issue_seconds"] != 60:
            errors.append(f"sustained record {index} changed the frozen durations")
        if record["completed"] + record["failed"] != record["offered"]:
            errors.append(f"sustained record {index} loses issued requests")
        if record["final_ready"] != record["initial_ready"]:
            errors.append(f"sustained record {index} did not restore ready inventory")
    if any(count != 1 for count in keys.values()):
        errors.append("duplicate sustained samples")
    if complete:
        spec = config["evaluations"][2]
        wanted = {
            (mode, concurrency, session)
            for mode in spec["modes"]
            for concurrency in spec["sustained"]["concurrency"]
            for session in range(spec["sustained"]["sessions"])
        }
        missing = wanted.difference(keys)
        if missing:
            errors.append(f"missing {len(missing)} sustained samples; first={sorted(missing)[:3]}")
    return errors


def validate_directory(result: Path, *, complete: bool = True) -> dict[str, Any]:
    config = load_config(result / "configuration.json")
    records = read_jsonl(result / "records.jsonl")
    security = read_jsonl(result / "host-security.jsonl")
    sustained = read_jsonl(result / "sustained.jsonl")
    errors = validate_request_records(records, config, complete=complete)
    errors.extend(validate_security(security, config, complete))
    errors.extend(validate_sustained(sustained, config, complete))
    qualification = result / "qualification.json"
    if complete and (
        not qualification.exists() or not json.loads(qualification.read_text()).get("passed")
    ):
        errors.append("qualification gate is absent or failed")
    freeze = result / "freeze.json"
    if complete and (not freeze.exists() or not json.loads(freeze.read_text()).get("frozen")):
        errors.append("implementation/configuration freeze is absent")
    summary_path = result / "summary.json"
    if summary_path.exists():
        from report import generate_summary

        recorded = json.loads(summary_path.read_text())
        regenerated = generate_summary(result)
        if recorded != regenerated:
            errors.append("summary.json cannot be regenerated byte-semantically from raw records")
    return {
        "schema_version": 1,
        "campaign_id": config["campaign_id"],
        "config_id": config_id(config),
        "complete_requested": complete,
        "records": len(records),
        "security_records": len(security),
        "sustained_records": len(sustained),
        "passed": not errors,
        "errors": errors,
    }


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("result", type=Path)
    parser.add_argument("--allow-incomplete", action="store_true")
    parser.add_argument("--output", type=Path)
    args = parser.parse_args()
    report = validate_directory(args.result, complete=not args.allow_incomplete)
    if args.output:
        write_json(args.output, report)
    else:
        print(json.dumps(report, indent=2, sort_keys=True))
    return 0 if report["passed"] else 1


if __name__ == "__main__":
    raise SystemExit(main())
