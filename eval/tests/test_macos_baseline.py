"""Baseline scheduling preserves the frozen application/task denominator."""

import importlib.util
import sys
from collections import Counter
from pathlib import Path

import pytest

ROOT = Path(__file__).resolve().parents[2]


def load(name, path):
    spec = importlib.util.spec_from_file_location(name, path)
    module = importlib.util.module_from_spec(spec)
    sys.modules[name] = module
    spec.loader.exec_module(module)
    return module


harness = load("baseline_harness_test", ROOT / "eval/remaining/macos_baseline_campaign.py")
demos = load("baseline_demos_test", ROOT / "eval/campaigns/langgraph-demos-v3/run_campaign.py")


def test_full_frozen_baseline_matrix():
    jobs = list(harness.jobs(demos, 5, False))
    assert len(jobs) == 175
    assert {job.mode for job in jobs} == {"Baseline"}
    assert len({(job.application, job.task, job.repetition) for job in jobs}) == 175
    counts = Counter(job.application for job in jobs)
    assert counts == {**dict.fromkeys(demos.OLD_DEMOS, 5), **dict.fromkeys(demos.NEW_DEMOS, 25)}
    assert list(harness.jobs(demos, 5, False)) == jobs


def test_pilot_cannot_be_mistaken_for_full_matrix():
    jobs = list(harness.jobs(demos, 1, True))
    assert len(jobs) == 15
    assert {job.task for job in jobs} == {1}


@pytest.mark.parametrize("correct", [True, False])
def test_existing_tutorial_oracle_checks_output_and_actual_tool_use(correct):
    output = {"answer": "294", "executed_tools": ["multiply"] if correct else []}
    assert demos.old_correct("T5-prebuilt-multiply", output) is correct


def test_evidence_verifier_refuses_missing_data(tmp_path):
    verifier = load("baseline_verifier_test", ROOT / "eval/remaining/verify_macos_baseline.py")
    with pytest.raises(FileNotFoundError):
        verifier.verify(tmp_path)
