"""Retain only final-r2 samples unaffected by the qualified fixes."""

from __future__ import annotations

import argparse
import hashlib
import json
import subprocess
from collections.abc import Callable, Iterable
from pathlib import Path
from typing import Any

from campaign import HERE, load_config, write_json

SOURCE = HERE / "retained" / "final-r2"
SOURCE_FINAL_R3 = HERE / "retained" / "final-r3"
INVALIDATED_MACRO_WORKLOADS = frozenset(
    {"D3-plan-execute", "D4-multi-agent", "D5-support", "T10-time-travel"}
)


def _decompress(parts: Iterable[Path]) -> bytes:
    paths = tuple(parts)
    payload = b"".join(path.read_bytes() for path in paths)
    result = subprocess.run(["zstdcat"], input=payload, capture_output=True, check=False)
    if result.returncode != 0:
        raise RuntimeError(result.stderr.decode(errors="replace"))
    return result.stdout


def _rows(parts: Iterable[Path]) -> list[dict[str, Any]]:
    return [json.loads(line) for line in _decompress(parts).splitlines() if line.strip()]


def _retain_request(row: dict[str, Any]) -> bool:
    if row["evaluation"] == 1:
        return row["mode"] != "apf" and row["workload"] not in INVALIDATED_MACRO_WORKLOADS
    if row["evaluation"] == 3:
        return row["mode"] in {"baseline", "argus-language"}
    return False


def _rewrite(
    rows: Iterable[dict[str, Any]],
    predicate: Callable[[dict[str, Any]], bool],
    *,
    config_id: str,
    build_id: str,
    retained_from: str = "unified-final-v1/final-r2",
    retention_basis: str = "unaffected cell under final-r3 invalidation manifest",
) -> list[dict[str, Any]]:
    retained = []
    for original in rows:
        if not predicate(original):
            continue
        row = dict(original)
        row.update(
            source_config_id=original["config_id"],
            source_build_id=original["build_id"],
            retained_from=retained_from,
            retention_basis=retention_basis,
            config_id=config_id,
            build_id=build_id,
        )
        retained.append(row)
    return retained


def _append(path: Path, rows: Iterable[dict[str, Any]]) -> int:
    if path.read_text(encoding="utf-8").strip():
        raise RuntimeError(f"retention target is not empty: {path}")
    values = list(rows)
    with path.open("a", encoding="utf-8") as stream:
        for row in values:
            stream.write(json.dumps(row, sort_keys=True) + "\n")
    return len(values)


def retain(result: Path, *, linux_security_source: Path | None = None) -> dict[str, Any]:
    prepared = json.loads((result / "prepared.json").read_text())
    load_config(result / "configuration.json")
    source_records = SOURCE / "records.jsonl.zst"
    source_sustained = sorted(SOURCE.glob("sustained.jsonl.zst.part-*"))
    request_rows = _rewrite(
        _rows((source_records,)),
        _retain_request,
        config_id=prepared["config_id"],
        build_id=prepared["build_id"],
    )
    sustained_rows = _rewrite(
        _rows(source_sustained),
        lambda row: row["mode"] in {"baseline", "argus-language"},
        config_id=prepared["config_id"],
        build_id=prepared["build_id"],
    )
    request_count = _append(result / "records.jsonl", request_rows)
    sustained_count = _append(result / "sustained.jsonl", sustained_rows)
    security_count = 0
    if linux_security_source is not None:
        qualification = json.loads((linux_security_source / "qualification.json").read_text())
        freeze = json.loads((linux_security_source / "freeze.json").read_text())
        if qualification.get("passed") is not True or freeze.get("frozen") is not True:
            raise RuntimeError("Linux-security retention source was not qualified and frozen")
        source_security = [
            json.loads(line)
            for line in (linux_security_source / "host-security.jsonl").read_text().splitlines()
            if line.strip()
        ]
        security_rows = _rewrite(
            source_security,
            lambda row: row.get("backend") == "linux",
            config_id=prepared["config_id"],
            build_id=prepared["build_id"],
        )
        for row in security_rows:
            row["retention_basis"] = (
                "unaffected by the subsequent microbenchmark fixture-root change"
            )
        security_count = _append(result / "host-security.jsonl", security_rows)
    source_config = json.loads((SOURCE / "configuration.json").read_text())
    report = {
        "schema_version": 1,
        "source": str(SOURCE.relative_to(HERE)),
        "source_records_sha256": hashlib.sha256(source_records.read_bytes()).hexdigest(),
        "source_sustained_parts_sha256": {
            path.name: hashlib.sha256(path.read_bytes()).hexdigest() for path in source_sustained
        },
        "source_config_id": next(iter({row["source_config_id"] for row in request_rows})),
        "source_campaign_id": source_config["campaign_id"],
        "target_config_id": prepared["config_id"],
        "target_build_id": prepared["build_id"],
        "retained_request_records": request_count,
        "retained_sustained_records": sustained_count,
        "retained_linux_security_records": security_count,
        "linux_security_source": str(linux_security_source) if linux_security_source else None,
        "compatibility_rules": {
            "evaluation_1": (
                "retain baseline/Argus/NoNo except D3, D4, D5, and T10; "
                "APF image/timer changes invalidate every APF cell"
            ),
            "evaluation_2": (
                "retain the freshly rerun Linux cases only when supplied from the qualified, "
                "frozen pre-micro-path-fix result"
                if linux_security_source
                else "retain none after shared Linux lowering change"
            ),
            "evaluation_3": (
                "retain baseline and forced-language; rerun forced-host after adapter, "
                "permission, and lifecycle changes"
            ),
            "evaluation_4": "retain none after Pandas workflow/oracle fixes",
        },
    }
    write_json(result / "retained-lineage.json", report)
    return report


def retain_final_r3_performance(result: Path) -> dict[str, Any]:
    """Retain every performance cell unaffected by host-security-only repairs."""
    prepared = json.loads((result / "prepared.json").read_text())
    load_config(result / "configuration.json")
    source_records = SOURCE_FINAL_R3 / "records.jsonl.zst"
    source_sustained = sorted(SOURCE_FINAL_R3.glob("sustained.jsonl.zst.part-*"))
    basis = (
        "unaffected by aggregate-CPU obligation lowering, SHM security oracle, "
        "and security-category reporting repairs"
    )
    request_rows = _rewrite(
        _rows((source_records,)),
        lambda row: row["evaluation"] in {1, 3, 4},
        config_id=prepared["config_id"],
        build_id=prepared["build_id"],
        retained_from="unified-final-v1/final-r3",
        retention_basis=basis,
    )
    sustained_rows = _rewrite(
        _rows(source_sustained),
        lambda row: True,
        config_id=prepared["config_id"],
        build_id=prepared["build_id"],
        retained_from="unified-final-v1/final-r3",
        retention_basis=basis,
    )
    request_count = _append(result / "records.jsonl", request_rows)
    sustained_count = _append(result / "sustained.jsonl", sustained_rows)
    report = {
        "schema_version": 2,
        "source": str(SOURCE_FINAL_R3.relative_to(HERE)),
        "source_records_sha256": hashlib.sha256(source_records.read_bytes()).hexdigest(),
        "source_sustained_parts_sha256": {
            path.name: hashlib.sha256(path.read_bytes()).hexdigest() for path in source_sustained
        },
        "source_config_id": next(iter({row["source_config_id"] for row in request_rows})),
        "source_campaign_id": "unified-final-v1",
        "target_config_id": prepared["config_id"],
        "target_build_id": prepared["build_id"],
        "retained_request_records": request_count,
        "retained_sustained_records": sustained_count,
        "retained_linux_security_records": 0,
        "retention_scope": "all-performance",
        "compatibility_rules": {
            "evaluations_1_3_4": basis,
            "evaluation_2": (
                "retain none; rerun every Linux case after shared lowering/oracle changes"
            ),
        },
    }
    write_json(result / "retained-lineage.json", report)
    return report


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--result", type=Path, required=True)
    parser.add_argument("--linux-security-source", type=Path)
    args = parser.parse_args()
    print(
        json.dumps(retain(args.result, linux_security_source=args.linux_security_source), indent=2)
    )
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
