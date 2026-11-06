#!/usr/bin/env python3
"""Capture diagnostic spans for one cold and one warm Argus invocation."""

from __future__ import annotations

import argparse
import json
import sys
import threading
import time
import uuid
from collections import Counter
from collections.abc import Callable
from itertools import pairwise
from pathlib import Path
from typing import Any

ROOT = Path(__file__).resolve().parents[3]
sys.path.insert(0, str(ROOT / "eval" / "apps" / "demos"))

from langchain_core.messages import AIMessage  # noqa: E402
from langgraph.prebuilt import tool_node  # noqa: E402
from langgraph.prebuilt.security import (  # noqa: E402
    Principal,
    inprocess,
    install_mac_policy,
    with_principal,
)
from langgraph.prebuilt.security import _language_sandbox as language  # noqa: E402
from langgraph.prebuilt.security import object_policy as policy  # noqa: E402
from timing import ModelTiming  # noqa: E402
from tool_calling_protected import OPERATOR_POLICY, build  # noqa: E402

PHASE = "setup"
ORIGIN = time.perf_counter()
EVENTS: list[dict[str, Any]] = []
LOCK = threading.Lock()


def record(name: str, started: float, metadata: dict[str, Any] | None = None) -> None:
    event = {
        "phase": PHASE,
        "name": name,
        "start_ms": (started - ORIGIN) * 1000,
        "end_ms": (time.perf_counter() - ORIGIN) * 1000,
        "thread": threading.get_ident(),
    }
    if metadata:
        event.update(metadata)
    with LOCK:
        EVENTS.append(event)


def wrap_method(owner: Any, name: str, label: str) -> None:
    original = getattr(owner, name)

    def wrapped(*args: Any, **kwargs: Any) -> Any:
        started = time.perf_counter()
        metadata = {}
        if label in {"host_invoke", "language_dispatch"} and len(args) > 2:
            call = args[2]
            metadata = {"tool": call.tool.name, "call_id": call.call_id}
        if label == "cedar_process" and len(args) > 2:
            metadata = {"command": args[2]}
        try:
            return original(*args, **kwargs)
        finally:
            record(label, started, metadata)

    setattr(owner, name, wrapped)


def wrap_function(owner: Any, name: str, label: str) -> None:
    original = getattr(owner, name)

    def wrapped(*args: Any, **kwargs: Any) -> Any:
        started = time.perf_counter()
        try:
            return original(*args, **kwargs)
        finally:
            record(label, started)

    setattr(owner, name, wrapped)


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


def invoke(graph: Any, security: Any, demo: str, sequence: int) -> tuple[float, float]:
    config = with_principal(
        {"recursion_limit": 20},
        Principal("alice", frozenset(), frozenset(), f"profile-{sequence}-{uuid.uuid4().hex}"),
        modules=security.modules,
    )
    started = time.perf_counter()
    graph.invoke(graph_input(demo, sequence), config=config)
    finished = time.perf_counter()
    return (started - ORIGIN) * 1000, (finished - ORIGIN) * 1000


def active_duration(events: list[dict[str, Any]], start: float, end: float) -> dict[str, float]:
    categories: list[tuple[str, Callable[[str], bool]]] = [
        ("serialization_and_copying", lambda name: name == "json_encode"),
        ("authorization", lambda name: name == "authorize"),
        ("interpretation", lambda name: name == "interpret"),
        ("receipt", lambda name: name == "receipt"),
        ("lifecycle_and_cleanup", lambda name: name == "language_dispatch"),
        ("tool_dispatch_and_synchronization", lambda name: name == "tool_node"),
    ]
    boundaries = {start, end}
    clipped = []
    for event in events:
        left = max(start, event["start_ms"])
        right = min(end, event["end_ms"])
        if left < right:
            clipped.append((left, right, event["name"]))
            boundaries.update((left, right))
    result = Counter()
    points = sorted(boundaries)
    for left, right in pairwise(points):
        midpoint = (left + right) / 2
        names = {
            name for event_start, event_end, name in clipped if event_start <= midpoint < event_end
        }
        category = "graph_dispatch"
        for candidate, predicate in categories:
            if any(predicate(name) for name in names):
                category = candidate
                break
        result[category] += right - left
    return dict(result)


def main() -> None:
    global ORIGIN, PHASE
    parser = argparse.ArgumentParser()
    parser.add_argument("--demo", choices=("fixed-weather", "parallel-weather"), required=True)
    parser.add_argument("--output", type=Path, required=True)
    args = parser.parse_args()

    wrap_method(policy.CedarObjectAuthorizer, "prepare", "cedar_prepare")
    wrap_method(policy.CedarObjectAuthorizer, "authorize", "authorize")
    wrap_method(policy.CedarObjectAuthorizer, "_validate", "policy_validate")
    wrap_method(policy.CedarObjectAuthorizer, "_allows", "policy_check")
    wrap_method(policy.CedarObjectAuthorizer, "_run", "cedar_process")
    wrap_method(policy.ObjectPolicyHostExecutor, "invoke", "host_invoke")
    wrap_method(policy._LanguageSandboxDispatcher, "invoke", "language_dispatch")
    wrap_method(policy._LanguageSandboxDispatcher, "_receipt", "receipt")
    wrap_method(inprocess.ManifestAdmission, "__init__", "language_prepare")
    wrap_method(inprocess.ManifestAdmission, "validate", "admission_validate")
    wrap_method(language.LanguageProgram, "invoke", "interpret")
    wrap_method(tool_node.ToolNode, "_func", "tool_node")
    wrap_function(policy, "parse_security_manifest", "manifest_parse")
    wrap_function(policy, "_json", "json_encode")
    wrap_function(inprocess.inspect, "getsource", "source_inspection")
    wrap_function(inprocess.ast, "parse", "python_parse")

    ORIGIN = time.perf_counter()
    PHASE = "preparation"
    install_mac_policy(OPERATOR_POLICY)
    graph, _, security, _, _ = build(args.demo, "Argus", None, ModelTiming())
    preparation_end_ms = (time.perf_counter() - ORIGIN) * 1000
    if security is None:
        raise RuntimeError("Argus security was not constructed")

    windows = {}
    for sequence, phase in enumerate(("first_invocation", "steady_invocation")):
        PHASE = phase
        windows[phase] = invoke(graph, security, args.demo, sequence)

    breakdown = {}
    for phase, (start, end) in windows.items():
        selected = [event for event in EVENTS if event["phase"] == phase]
        values = active_duration(selected, start, end)
        values["total_ms"] = end - start
        values["reconciled_ms"] = sum(value for key, value in values.items() if key != "total_ms")
        breakdown[phase] = values

    counts = {}
    for phase in ("preparation", "first_invocation", "steady_invocation"):
        counts[phase] = dict(Counter(event["name"] for event in EVENTS if event["phase"] == phase))
    tool_spans = [
        event for event in EVENTS if event["name"] in {"host_invoke", "language_dispatch"}
    ]
    args.output.parent.mkdir(parents=True, exist_ok=True)
    args.output.write_text(
        json.dumps(
            {
                "demo": args.demo,
                "route": "language",
                "preparation_ms": preparation_end_ms,
                "windows": windows,
                "non_overlapping_breakdown": breakdown,
                "operation_counts": counts,
                "tool_spans": tool_spans,
                "events": sorted(EVENTS, key=lambda event: event["start_ms"]),
            },
            indent=2,
            sort_keys=True,
        )
        + "\n",
        encoding="utf-8",
    )


if __name__ == "__main__":
    main()
