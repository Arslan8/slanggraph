"""Routing repairs preserve requested semantics, never expected task answers."""

import asyncio
import base64
import importlib.util
import struct
from pathlib import Path
from unittest.mock import AsyncMock, Mock

import pytest

spec = importlib.util.spec_from_file_location(
    "workflow_contract", Path(__file__).resolve().parents[1] / "apps/pandas/workflow_contract.py"
)
contract = importlib.util.module_from_spec(spec)
spec.loader.exec_module(contract)


def test_lossy_router_cannot_remove_mean_or_format_constraints():
    task = "Return exactly region and mean sales, ignoring missing values."
    graph = Mock()
    stage = contract.RequestPreservingStage(graph, task, "wrangling")
    state = {"user_instructions": "grouped by region", "data_raw": {"sales": [5, None, 5]}}
    stage.invoke(state, config={"tags": ["trace"]})
    sent = graph.invoke.call_args.args[0]
    assert sent["user_instructions"] == task
    assert sent["data_raw"] is state["data_raw"]
    assert "Preserve duplicate rows and missing values" in sent["recommended_steps"]
    assert graph.invoke.call_args.kwargs["config"] == {"tags": ["trace"]}
    assert state["user_instructions"] == "grouped by region"


def test_async_stage_preserves_original_request():
    graph = Mock(ainvoke=AsyncMock(return_value={"plot": "result"}))
    stage = contract.RequestPreservingStage(
        graph, "Chart totals in YYYY-MM format.", "visualization"
    )
    assert asyncio.run(stage.ainvoke({"user_instructions": "plot"})) == {"plot": "result"}
    assert graph.ainvoke.call_args.args[0]["user_instructions"].startswith(stage.request)


def test_wrangling_stage_restores_only_versioned_json_null_sentinel():
    graph = Mock(
        invoke=Mock(
            return_value={
                "data_wrangled": {
                    "month": {"0": "2026-04"},
                    "mean_sales": {"0": contract.JSON_NULL_SENTINEL},
                },
                "messages": [contract.JSON_NULL_SENTINEL],
            }
        )
    )
    stage = contract.RequestPreservingStage(graph, "Return monthly means.", "wrangling")
    result = stage.invoke({})
    assert result["data_wrangled"]["mean_sales"]["0"] is None
    assert result["messages"] == [contract.JSON_NULL_SENTINEL]


def test_date_filter_is_not_treated_as_temporal_grouping():
    state = {"user_instructions": "lossy routing"}
    filtered = contract.RequestPreservingStage(
        Mock(), "Filter dates after 2025-10-01 and return total revenue.", "wrangling"
    ).prepare(state)
    assert "Do not add date grouping" in filtered["recommended_steps"]
    assert "time-bucket aggregation" not in filtered["recommended_steps"]
    grouped = contract.RequestPreservingStage(
        Mock(), "Return weekly mean revenue.", "wrangling", version="preserve-request-v4"
    ).prepare(state)
    assert "time-bucket aggregation" in grouped["recommended_steps"]
    helper = contract.RequestPreservingStage(
        Mock(), "Return weekly mean revenue.", "wrangling"
    ).prepare(state)
    assert "aggregate_periods" in helper["recommended_steps"]


@pytest.mark.parametrize(
    "dtype,fmt,values", [("f8", "d", [1.25, -2.5]), ("i2", "h", [5, -9]), ("u1", "B", [0, 255])]
)
def test_plot_transport_preserves_every_value_and_label(dtype, fmt, values):
    native = {
        "data": [
            {
                "x": ["2026-01", "2026-02"],
                "y": {
                    "dtype": dtype,
                    "bdata": base64.b64encode(
                        struct.pack("=" + fmt * len(values), *values)
                    ).decode(),
                },
            }
        ]
    }
    result = contract.portable_plot(native)
    assert result["data"][0] == {"x": ["2026-01", "2026-02"], "y": values}
    assert isinstance(native["data"][0]["y"], dict)


def test_plot_invalid_buffers_and_shapes_are_rejected():
    with pytest.raises(ValueError):
        contract.portable_plot({"dtype": "f8", "bdata": "YQ=="})
    with pytest.raises(ValueError):
        contract.portable_plot({"dtype": "u1", "bdata": "AQI=", "shape": "2,2"})
    with pytest.raises(ValueError):
        contract.portable_plot({"dtype": "object", "bdata": "AQI="})
    with pytest.raises(ValueError):
        contract.portable_plot({"dtype": "u1", "bdata": "", "shape": "1000000000,0"})
    assert contract.portable_plot({"dtype": "u1", "bdata": "AQIDBA==", "shape": "2,2"}) == [
        [1, 2],
        [3, 4],
    ]
