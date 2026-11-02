"""Period API checks use held-out values, independent of the workflow oracle."""

import importlib.util
import inspect
from pathlib import Path

import pytest
from langgraph.prebuilt.security.output_data import validate_output_data

pd = pytest.importorskip("pandas")
spec = importlib.util.spec_from_file_location(
    "codec", Path(__file__).resolve().parents[1] / "apps/pandas/sandbox_codec.py"
)
codec = importlib.util.module_from_spec(spec)
spec.loader.exec_module(codec)
namespace = {"pd": pd}
exec(inspect.getsource(codec.aggregate_periods), namespace)
aggregate = namespace["aggregate_periods"]


def test_partial_months_duplicates_and_empty_buckets():
    frame = pd.DataFrame(
        {"when": ["2024-12-18", "2024-12-18", "2025-02-09"], "amount": [7, 11, 31]}
    )
    original = frame.copy(deep=True)
    result = aggregate(frame, "when", "amount", bucket_column="month", label_format="%Y-%m")
    assert result.to_dict("list") == {
        "month": ["2024-12", "2025-01", "2025-02"],
        "amount": [18, 0, 31],
    }
    pd.testing.assert_frame_equal(frame, original)
    mean = aggregate([frame.iloc[:1], frame.iloc[1:]], "when", "amount", operation="mean")
    assert mean.amount.iloc[0] == 9
    assert mean.amount.iloc[1] is None
    assert mean.amount.iloc[2] == 31
    validate_output_data({"data_wrangled": mean.to_dict()})


def test_null_groups_and_invalid_requests():
    frame = pd.DataFrame({"date": ["2023-04-13"], "value": [None]})
    assert aggregate(frame, "date", "value").value.tolist() == [0]
    assert pd.isna(aggregate(frame, "date", "value", operation="mean").value.iloc[0])
    for kwargs in ({"operation": "eval"}, {"frequency": "bad"}, {"bucket_column": "value"}):
        with pytest.raises(ValueError):
            aggregate(frame, "date", "value", **kwargs)
    frame.loc[0, "date"] = None
    with pytest.raises(ValueError, match="nonmissing"):
        aggregate(frame, "date", "value")


def test_helper_globals_remain_restricted():
    source = """
def _to_jsonable(obj):
    return obj
_SAFE_BUILTINS = {"dict": dict}
pd = None
np = None
def run():
    exec_globals = {"__builtins__": _SAFE_BUILTINS, "pd": pd, "np": np}
    return exec_globals
"""
    scope = {}
    exec(codec.repair_runner(source, computation_api="period-aggregation-v1"), scope)
    helper = scope["run"]()["aggregate_periods"]
    assert set(helper.__globals__) == {"__builtins__", "pd", "np", "aggregate_periods"}
    assert "open" not in helper.__globals__["__builtins__"]
    with pytest.raises(ValueError, match="Unsupported computation"):
        codec.repair_runner(source, computation_api="unknown")
