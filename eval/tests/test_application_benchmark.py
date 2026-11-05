"""The application benchmark excludes setup, audit, and failed pairs from overhead."""

from __future__ import annotations

import importlib.util
import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parents[2]


def load(name: str, path: Path):
    spec = importlib.util.spec_from_file_location(name, path)
    module = importlib.util.module_from_spec(spec)
    sys.modules[name] = module
    spec.loader.exec_module(module)
    return module


results = load(
    "application_benchmark_results_test",
    ROOT / "eval/campaigns/langgraph-demos-v3/regenerate.py",
)


def record(
    mode: str,
    invocation_ms: float | None,
    *,
    task: int = 1,
    correct: bool = True,
    status: str = "completed",
    preparation_ms: float = 1_000.0,
) -> dict:
    return {
        "application": "example",
        "repetition": 0,
        "task": task,
        "mode": mode,
        "status": status,
        "correct": correct,
        "invocation_ms": invocation_ms,
        "preparation_ms": preparation_ms,
    }


def test_ratio_uses_invocation_time_not_preparation() -> None:
    records = [
        record("Baseline", 100.0, preparation_ms=1.0),
        record("Argus", 106.0, preparation_ms=100_000.0),
    ]
    assert results.ratio_for(records, [0]) == 1.06


def test_failed_or_incorrect_pairs_are_not_latency_samples() -> None:
    records = [
        record("Baseline", 100.0),
        record("Argus", 106.0),
        record("Baseline", 1.0, task=2),
        record("Argus", None, task=2, status="timeout", correct=False),
        record("Baseline", 1.0, task=3),
        record("Argus", 1.0, task=3, correct=False),
    ]
    assert results.timing_samples(records, [0]) == {
        "Baseline": [100.0],
        "Argus": [106.0],
    }
