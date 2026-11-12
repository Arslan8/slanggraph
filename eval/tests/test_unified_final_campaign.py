"""Protocol invariants for the unified final campaign."""

from __future__ import annotations

import json
import sys
from pathlib import Path

from slanggraph_eval.ready_process import run_ready_process

CAMPAIGN = Path(__file__).resolve().parents[1] / "campaigns/unified-final-v1"
sys.path.insert(0, str(CAMPAIGN))

from campaign import Cell, config_id, load_config, record_for, request_cells  # noqa: E402
from report import _ratio  # noqa: E402
from validate import validate_request_records  # noqa: E402


def test_fixed_scope_and_schedule_counts() -> None:
    config = load_config()
    macro = config["evaluations"][0]
    assert [item["id"] for item in macro["applications"]] == [
        "D1-sql",
        "D2-rag",
        "D3-plan-execute",
        "D4-multi-agent",
        "D5-support",
        "T1-add-tools",
        "T2-custom-weather",
        "T5-prebuilt-multiply",
        "T6-return-direct",
        "T7-forced-tool",
        "T8-serial-tools",
        "T9-add-memory",
        "T10-time-travel",
    ]
    cells = list(request_cells(config))
    counts = {
        evaluation: sum(cell.evaluation == evaluation for cell in cells) for evaluation in (1, 3, 4)
    }
    assert counts == {1: 4620, 3: 315, 4: 700}
    measured = [cell for cell in cells if cell.phase == "measured"]
    assert sum(cell.evaluation == 1 for cell in measured) == 3960
    assert sum(cell.evaluation == 3 for cell in measured) == 270
    assert sum(cell.evaluation == 4 for cell in measured) == 600
    assert len({cell.key for cell in cells}) == len(cells)


def test_every_application_block_warms_up_before_measurement() -> None:
    cells = [cell for cell in request_cells(load_config()) if cell.evaluation in {1, 4}]
    positions: dict[tuple[object, ...], list[tuple[int, str, int]]] = {}
    for position, cell in enumerate(cells):
        key = (cell.evaluation, cell.mode, cell.workload, cell.task, cell.session)
        positions.setdefault(key, []).append((position, cell.phase, cell.repetition))
    for block in positions.values():
        assert [phase for _, phase, _ in block] == ["warmup", *("measured",) * 6]
        assert [repetition for _, _, repetition in block] == [-1, 0, 1, 2, 3, 4, 5]
        assert [position for position, _, _ in block] == list(range(block[0][0], block[0][0] + 7))


def test_parent_ready_timer_excludes_preflight(tmp_path: Path) -> None:
    script = (
        "import json,sys,time;"
        "time.sleep(0.08);"
        "print(json.dumps({'argus_eval_protocol':1,'state':'ready'}),flush=True);"
        "assert sys.stdin.readline() == 'GO\\n';"
        "time.sleep(0.02)"
    )
    result = run_ready_process(
        [sys.executable, "-c", script],
        cwd=tmp_path,
        env=None,
        preflight_timeout=2,
        runtime_timeout=2,
    )
    assert result.ready_observed
    assert result.returncode == 0
    assert result.preflight_ns >= 70_000_000
    assert 15_000_000 <= result.runtime_ns < 70_000_000


def test_validator_rejects_route_fallback_and_timer_drift() -> None:
    config = load_config()
    cell = Cell(3, "argus-language", "read-32", "request", 0, 0, "measured", 7)
    record = record_for(
        cell,
        configuration_id=config_id(config),
        build_id="build",
        route="host",
        preflight_ns=10,
        runtime_start_ns=20,
        runtime_end_ns=30,
        outcome="completed",
        oracle_passed=True,
        counters={
            "authorization_checks": 1,
            "cleanup_completed": 1,
            "host_fallbacks": 1,
        },
    )
    record["runtime_ns"] = 9
    errors = validate_request_records([record], config, complete=False)
    assert any("runtime_ns" in error for error in errors)
    assert any("unexpected route" in error for error in errors)


def test_validator_accepts_baseline_alias_and_no_tool_argus_response() -> None:
    config = load_config()
    baseline_cell = Cell(1, "baseline", "D2-rag", "1", 0, 0, "measured", 7)
    baseline = record_for(
        baseline_cell,
        configuration_id=config_id(config),
        build_id="build",
        route="baseline",
        preflight_ns=10,
        runtime_start_ns=20,
        runtime_end_ns=30,
        outcome="completed",
        oracle_passed=True,
        counters={"cleanup_completed": 1},
    )
    argus_cell = Cell(1, "argus", "D2-rag", "1", 0, 0, "measured", 8)
    argus = record_for(
        argus_cell,
        configuration_id=config_id(config),
        build_id="build",
        route="language",
        preflight_ns=10,
        runtime_start_ns=20,
        runtime_end_ns=30,
        outcome="completed",
        oracle_passed=True,
        counters={"authorization_checks": 0, "cleanup_completed": 1},
        executed_tools=[],
    )
    assert validate_request_records([baseline, argus], config, complete=False) == []


def test_primary_ratio_uses_one_fixed_four_way_common_success_set() -> None:
    modes = ["baseline", "argus", "nono", "apf"]
    records = []
    for session in range(2):
        for repetition in range(2):
            for mode, runtime in zip(modes, (10, 12, 11, 13), strict=True):
                records.append(
                    {
                        "phase": "measured",
                        "outcome": "completed",
                        "oracle_passed": True,
                        "workload": "app",
                        "task": "1",
                        "session": session,
                        "repetition": repetition,
                        "mode": mode,
                        "runtime_ns": runtime,
                    }
                )
    # Remove one APF tuple: it must disappear for every mode, not only APF.
    records.pop()
    summary = _ratio(records, modes, "baseline")
    assert summary["common_success_count"] == 3
    assert summary["sum_runtime_ns"] == {
        "baseline": 30,
        "argus": 36,
        "nono": 33,
        "apf": 39,
    }


def test_inventory_counts_actual_rows() -> None:
    inventory = json.loads((CAMPAIGN / "admission_inventory.json").read_text())
    assert inventory["tool_level"]["total"] == len(inventory["rows"])
    assert inventory["application_level"] == {
        "wholly_language_isolated": 12,
        "host_required": 1,
        "total": 13,
    }


def test_host_write_policy_does_not_grant_read() -> None:
    from microbenchmarks import Workload, _manifest, _policy

    workload = Workload("write-32", "write", 32, b"x" * 32)
    policy = _policy(Path("/tmp/designated-output"), workload, "linux")
    manifest = _manifest(workload, "linux")
    assert "fs::read" not in policy
    assert "fs read" not in manifest
    assert "fs::write" in policy and "fs::truncate" in policy
