"""Matched Pandas validation follows the frozen manifest's outcome contract."""

import importlib.util
from collections import Counter
from pathlib import Path

import pytest

ROOT = Path(__file__).resolve().parents[1]


def _validator():
    path = ROOT / "apps/pandas/validate_matched.py"
    spec = importlib.util.spec_from_file_location("pandas_validate_matched_test", path)
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


validate_matched = _validator()


def test_manifest_versions_select_their_frozen_outcome_contract():
    assert validate_matched._expected_outcomes("22-full") == (
        Counter({("slangGraph", "monthly_mean"): 5}),
        95,
    )
    assert validate_matched._expected_outcomes("23-full") == (Counter(), 100)


def test_unknown_manifest_version_is_not_silently_accepted():
    with pytest.raises(ValueError, match="Unsupported matched-campaign manifest version"):
        validate_matched._expected_outcomes("24-full")
