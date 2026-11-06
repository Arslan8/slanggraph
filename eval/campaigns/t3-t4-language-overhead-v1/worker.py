#!/usr/bin/env python3
"""Measure one fresh-process weather graph through first and repeated invokes."""

from __future__ import annotations

import argparse
import json
import statistics
import sys
import time
import uuid
from pathlib import Path

ROOT = Path(__file__).resolve().parents[3]
sys.path.insert(0, str(ROOT / "eval" / "apps" / "demos"))

from langchain_core.messages import AIMessage  # noqa: E402
from langgraph.prebuilt.security import (  # noqa: E402
    Principal,
    install_mac_policy,
    with_principal,
)
from langgraph.prebuilt.security.object_policy import (  # noqa: E402
    _LanguageSandboxDispatchers,
)
from timing import ModelTiming  # noqa: E402
from tool_calling_protected import (  # noqa: E402
    OPERATOR_POLICY,
    build,
)


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
    parser.add_argument("--mode", choices=("Baseline", "Argus"), required=True)
    parser.add_argument("--repeats", type=int, default=20)
    parser.add_argument("--process-index", type=int, required=True)
    parser.add_argument("--output", type=Path, required=True)
    args = parser.parse_args()

    setup_started = time.perf_counter()
    if args.mode == "Argus":
        install_mac_policy(OPERATOR_POLICY)
    policy_setup_ms = (time.perf_counter() - setup_started) * 1000

    preparation_started = time.perf_counter()
    graph, _, security, _, _ = build(args.demo, args.mode, None, ModelTiming(), record_audit=False)
    preparation_ms = (time.perf_counter() - preparation_started) * 1000

    if security is None:
        route = "baseline"
        admitted_tools: list[str] = []
    else:
        dispatcher = security.host_executor.dispatcher
        if type(dispatcher) is not _LanguageSandboxDispatchers:
            raise RuntimeError(f"unexpected Argus dispatcher: {type(dispatcher)!r}")
        admitted_tools = sorted(dispatcher.admissions)
        route = "language"

    samples = []
    answers = []
    issued_call_ids = []
    for sequence in range(args.repeats + 1):
        config: dict[str, object] = {"recursion_limit": 20}
        if security is not None:
            principal = Principal(
                "alice",
                frozenset(),
                frozenset(),
                f"{args.demo}-{args.process_index}-{sequence}-{uuid.uuid4().hex}",
            )
            config = with_principal(config, principal, modules=security.modules)
        started = time.perf_counter()
        result = graph.invoke(graph_input(args.demo, sequence), config=config)
        samples.append((time.perf_counter() - started) * 1000)
        answers.append(
            [message.content for message in result["messages"] if message.type == "tool"]
        )
        if security is not None:
            expected = sequence + 1
            count = 2 if args.demo == "parallel-weather" else 1
            grants = security.host_executor.authorization_grants()
            if len(grants) != expected * count:
                raise RuntimeError("authorization grant count did not advance per invocation")
            issued_call_ids.append([grant.call_id for grant in grants[-count:]])

    expected_answers = (
        ["It's 60 degrees and foggy.", "nyc, sf"]
        if args.demo == "parallel-weather"
        else ["It's 60 degrees and foggy."]
    )
    if any(answer != expected_answers for answer in answers):
        raise RuntimeError(f"unexpected tool output: {answers!r}")
    steady = samples[1:]
    args.output.parent.mkdir(parents=True, exist_ok=True)
    args.output.write_text(
        json.dumps(
            {
                "process_index": args.process_index,
                "demo": args.demo,
                "mode": args.mode,
                "route": route,
                "admitted_tools": admitted_tools,
                "policy_setup_ms": policy_setup_ms,
                "preparation_ms": preparation_ms,
                "first_invocation_ms": samples[0],
                "steady_invocation_ms": steady,
                "steady_mean_ms": statistics.mean(steady),
                "steady_median_ms": statistics.median(steady),
                "fresh_grant_call_ids": issued_call_ids,
                "answers": answers,
            },
            indent=2,
            sort_keys=True,
        )
        + "\n",
        encoding="utf-8",
    )


if __name__ == "__main__":
    main()
