#!/usr/bin/env python3
"""Measure prepared Baseline graph runtime inside an activated comparator."""

from __future__ import annotations

import argparse
import json
import statistics
import sys
import time
import uuid

sys.path.insert(0, "/data/langgraph/eval/apps/demos")

from langchain_core.messages import AIMessage
from timing import ModelTiming
from tool_calling_protected import build


def graph_input(demo: str, sequence: int) -> dict[str, object]:
    calls = [
        {
            "name": "get_weather",
            "args": {"location": "San Francisco"},
            "id": f"weather-{sequence}-{uuid.uuid4().hex}",
            "type": "tool_call",
        }
    ]
    if demo == "parallel-weather":
        calls.append(
            {
                "name": "get_coolest_cities",
                "args": {},
                "id": f"cities-{sequence}-{uuid.uuid4().hex}",
                "type": "tool_call",
            }
        )
    return {"messages": [AIMessage(content="", tool_calls=calls)]}


def main() -> None:
    parser = argparse.ArgumentParser()
    parser.add_argument("--demo", choices=("fixed-weather", "parallel-weather"), required=True)
    parser.add_argument("--repeats", type=int, default=100)
    args = parser.parse_args()

    graph, _, _, _, _ = build(args.demo, "Baseline", None, ModelTiming())
    samples = []
    for sequence in range(args.repeats + 1):
        started = time.perf_counter()
        result = graph.invoke(graph_input(args.demo, sequence), config={"recursion_limit": 20})
        samples.append((time.perf_counter() - started) * 1000)
        if not any(message.type == "tool" for message in result["messages"]):
            raise RuntimeError("tool did not execute")
    steady = samples[1:]
    print(
        json.dumps(
            {
                "demo": args.demo,
                "first_invocation_ms": samples[0],
                "runtime_samples_ms": steady,
                "runtime_mean_ms": statistics.mean(steady),
                "runtime_median_ms": statistics.median(steady),
            },
            sort_keys=True,
        )
    )


if __name__ == "__main__":
    main()
