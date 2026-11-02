"""Targeted compatibility regressions; no model, performance or Linux run."""

import importlib.util
import json
import math
import sys
from pathlib import Path
from typing import TypedDict

ROOT = Path(__file__).resolve().parents[3]
sys.path[:0] = [str(ROOT / "libs" / x) for x in ("prebuilt", "langgraph", "checkpoint", "sdk-py")]
spec = importlib.util.spec_from_file_location(
    "pandas_closed", ROOT / "eval/apps/pandas/integration_closed.py"
)
module = importlib.util.module_from_spec(spec)
spec.loader.exec_module(module)


def main():
    import pandas as pd
    from langgraph.graph import StateGraph, START, END
    from langgraph.prebuilt.security.output_data import validate_output_data, OutputDataError
    from langgraph.checkpoint.memory import InMemorySaver
    from langgraph.prebuilt.security import SecurityConfig, Principal, with_principal

    events = []
    source = [{"month": "2026-01", "mean": 1.0}, {"month": "2026-04", "mean": None}]
    converted = pd.DataFrame(source).to_dict()
    assert math.isnan(converted["mean"][1])
    try:
        validate_output_data(json.loads(json.dumps({"data_wrangled": converted})))
    except OutputDataError as e:
        events.append(
            dict(
                stage="before_fix",
                error=str(e),
                conversion="JSON null -> pandas.DataFrame -> to_dict -> NaN",
            )
        )
    else:
        raise AssertionError("guard unexpectedly accepted NaN")

    class State(TypedDict):
        data_wrangled: dict

    def vendor_node(state):
        return {"data_wrangled": converted}

    b = StateGraph(State)
    b.add_node("execute_data_wrangler_code", vendor_node)
    b.add_edge(START, "execute_data_wrangler_code")
    b.add_edge("execute_data_wrangler_code", END)
    module.normalize_wrangler_node(b)
    value = b.compile().invoke({"data_wrangled": {}})
    assert value["data_wrangled"]["mean"]["1"] is None
    validate_output_data(value)
    for infinity in (float("inf"), float("-inf")):
        normalized = module.missing_value_transport({"value": infinity})
        try:
            validate_output_data(normalized)
        except OutputDataError:
            pass
        else:
            raise AssertionError("Infinity accepted")
    events.append(
        dict(
            stage="after_fix",
            missing_cell=None,
            infinity_still_rejected=True,
            validator_unchanged=True,
        )
    )

    class CState(TypedDict):
        value: int

    def inc(state):
        return {"value": state["value"] + 1}

    cb = StateGraph(CState)
    cb.add_node("increment", inc)
    cb.add_edge(START, "increment")
    cb.add_edge("increment", END)
    config = with_principal(
        {"configurable": {"thread_id": "checkpoint-regression"}},
        Principal("alice", frozenset(), frozenset(), "checkpoint-session"),
    )
    graph = cb.compile(
        checkpointer=InMemorySaver(), security=SecurityConfig(checkpoint_key=b"s" * 32)
    )
    graph.invoke({"value": 1}, config)
    history = list(graph.get_state_history(config))
    old = history[-1].config
    try:
        graph.invoke(
            None,
            with_principal(old, Principal("alice", frozenset(), frozenset(), "checkpoint-session")),
        )
    except PermissionError as e:
        assert str(e) in {"checkpoint:broken_chain", "checkpoint:replay", "checkpoint:invalid_sequence"}, str(e)
        events.append(
            dict(
                stage="historical_checkpoint",
                refusal=str(e),
                policy="authenticated linear ancestry; historical rollback is not authorized",
            )
        )
    else:
        raise AssertionError("historical checkpoint unexpectedly accepted")
    print(json.dumps(dict(passed=True, events=events), indent=2))


if __name__ == "__main__":
    main()
